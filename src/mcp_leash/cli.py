"""Command line interface: ``run``, ``validate``, ``check``, ``init`` and ``suggest``."""

import asyncio
import enum
import logging
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Annotated

import typer

from mcp_leash import __version__
from mcp_leash.audit import AuditLog
from mcp_leash.jsonrpc import InvalidMessageError, parse_strict
from mcp_leash.policy import Policy, PolicyError, evaluate, load_policy, parse_policy
from mcp_leash.policy.loader import read_yaml
from mcp_leash.policy.matchers import canonical_path
from mcp_leash.proxy import Proxy, Relay, serve_stdio
from mcp_leash.suggest import read_log, render

EXIT_INVALID = 2
INIT_FILENAME = "mcp-leash.yaml"

app = typer.Typer(
    name="mcp-leash",
    help="A firewall for your AI agent's tools: enforce one policy on any MCP server.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


class Template(str, enum.Enum):
    """Starter policies for ``init``."""

    readonly = "readonly"
    project = "project"


def _fail(message: str, code: int = EXIT_INVALID) -> typer.Exit:
    typer.echo(f"mcp-leash: {message}", err=True)
    return typer.Exit(code)


def _load(path: Path, project_dir: Path | None) -> Policy:
    try:
        return load_policy(path, project_dir=str(project_dir) if project_dir else None)
    except PolicyError as exc:
        raise _fail(f"invalid policy {str(path)!r}:\n{exc}") from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-leash {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show the version."
        ),
    ] = False,
) -> None:
    """A firewall for your AI agent's tools: enforce one policy on any MCP server."""


PolicyFile = Annotated[
    Path,
    typer.Option("--policy", "-p", help="Policy YAML file.", show_default=False),
]
ProjectDir = Annotated[
    Path | None,
    typer.Option(
        "--project-dir",
        help="Value of ${PROJECT_DIR} in the policy. Default: the current directory.",
        file_okay=False,
    ),
]


@app.command()
def run(
    command: Annotated[
        list[str],
        typer.Argument(
            metavar="-- CMD [ARGS]...", help="The real MCP server command.", show_default=False
        ),
    ],
    policy: PolicyFile,
    project_dir: ProjectDir = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Log would_deny but forward every call (audit mode)."),
    ] = False,
) -> None:
    """Start the proxy and launch the real MCP server as CMD."""
    logging.basicConfig(
        stream=sys.stderr, level=logging.INFO, format="mcp-leash: %(levelname)s: %(message)s"
    )
    loaded = _load(policy, project_dir)
    project = canonical_path(str(project_dir) if project_dir else os.getcwd())
    if os.path.dirname(project) == project:
        logging.getLogger("mcp_leash").warning(
            "${PROJECT_DIR} is the filesystem root (%s); pass --project-dir to narrow it", project
        )
    try:
        audit = AuditLog.open(loaded.audit.path, loaded.audit.redact_keys)
    except OSError as exc:
        raise _fail(f"cannot open the audit log {loaded.audit.path!r}: {exc}") from exc
    try:
        code = asyncio.run(serve_stdio(Proxy(command, Relay(loaded, audit, dry_run=dry_run))))
    finally:
        audit.close()
    raise typer.Exit(code)


@app.command()
def validate(
    file: Annotated[Path, typer.Argument(help="Policy YAML file.", show_default=False)],
) -> None:
    """Check a policy file. Exit 0 if valid, 2 if not."""
    loaded = _load(file, None)
    typer.echo(f"{file}: valid ({len(loaded.rules)} rules, default {loaded.default})")


@app.command()
def check(
    file: Annotated[Path, typer.Argument(help="Policy YAML file.", show_default=False)],
    tool: Annotated[str, typer.Option("--tool", help="Tool name.", show_default=False)],
    args: Annotated[str, typer.Option("--args", help="Tool arguments as a JSON object.")] = "{}",
    project_dir: ProjectDir = None,
) -> None:
    """Evaluate one call offline and print the decision and matching rule."""
    loaded = _load(file, project_dir)
    try:
        arguments = parse_strict(args.encode("utf-8", "surrogateescape"))
    except InvalidMessageError as exc:
        raise _fail(f"--args is not valid JSON: {exc}") from exc
    if not isinstance(arguments, dict):
        raise _fail("--args must be a JSON object")
    decision = evaluate(loaded, tool, arguments)
    typer.echo(f"decision: {decision.action}")
    typer.echo(f"rule: {decision.rule}")
    if decision.reason:
        typer.echo(f"reason: {decision.reason}")


@app.command()
def init(
    template: Annotated[
        Template, typer.Option("--template", "-t", help="Starter policy to write.")
    ] = Template.project,
    force: Annotated[
        bool, typer.Option("--force", help=f"Overwrite an existing {INIT_FILENAME}.")
    ] = False,
) -> None:
    """Write a starter policy to mcp-leash.yaml."""
    target = Path(INIT_FILENAME)
    if target.exists() and not force:
        raise _fail(f"{INIT_FILENAME} already exists; use --force to overwrite it", code=1)
    content = (
        resources.files("mcp_leash")
        .joinpath("templates")
        .joinpath(f"{template.value}.yaml")
        .read_bytes()
    )
    target.write_bytes(content)
    typer.echo(f"Wrote {INIT_FILENAME} from the {template.value!r} template.")


@app.command()
def suggest(
    log: Annotated[
        Path, typer.Argument(help="Audit log written by run (JSON Lines).", show_default=False)
    ],
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            "-p",
            help="Policy to extend: its rules come first, unchanged.",
            dir_okay=False,
        ),
    ] = None,
    project_dir: ProjectDir = None,
) -> None:
    """Print a policy that adds an allow rule for each tool no rule decided in LOG."""
    project = canonical_path(str(project_dir) if project_dir else os.getcwd())
    base = None
    if policy is not None:
        _load(policy, project_dir)
        base = read_yaml(policy.read_text(encoding="utf-8-sig"))
    try:
        with open(log, encoding="utf-8", errors="replace") as stream:
            summary = read_log(stream, project)
    except OSError as exc:
        raise _fail(f"cannot read the audit log {str(log)!r}: {exc.strerror}") from exc
    text = render(summary, source=log.name, base=base, base_name=policy.name if policy else None)
    try:
        parse_policy(text, project_dir=project)
    except PolicyError as exc:  # a bug in suggest, not in the user's input
        raise _fail(f"the suggested policy is not valid; please report this:\n{exc}", 1) from exc
    typer.echo(text, nl=False)
    if not summary.undecided:
        typer.echo("mcp-leash: no call fell to the default rule; nothing to add", err=True)


def main() -> None:
    """Console script entry point."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    app()
