"""Suggest allow rules from an audit log: the logic behind ``mcp-leash suggest``.

Only calls that no rule decided (rule ``default``) get a rule: they are the
ones the current policy has no opinion on. Each such tool gets one allow rule,
and every argument whose name says it holds a path is kept inside
``${PROJECT_DIR}``, whatever paths the log shows.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml

from mcp_leash.policy.matchers import IndeterminateError, within
from mcp_leash.policy.models import DEFAULT_REDACT_KEYS

PATH_NAMES = frozenset(
    {"path", "paths", "file", "filename", "source", "destination", "directory", "dir", "cwd"}
)
PATH_SUFFIXES = ("path", "paths", "_dir", "_directory", "_file", "_folder")
MAX_EXAMPLES = 3
DEFAULT_AUDIT: dict[str, Any] = {
    "path": "~/.mcp-leash/audit.jsonl",
    "redact_keys": list(DEFAULT_REDACT_KEYS),
}


def is_path_argument(name: str) -> bool:
    """True if an argument's name says it holds a path, such as ``path`` or ``source_dir``."""
    lower = name.lower()
    return lower in PATH_NAMES or lower.endswith(PATH_SUFFIXES)


@dataclass
class ToolUsage:
    """How the undecided calls to one tool used their arguments."""

    calls: int = 0
    seen: Counter[str] = field(default_factory=Counter)
    """Calls that passed each argument."""
    not_paths: set[str] = field(default_factory=set)
    """Path-like names that held something other than a string or a list of strings."""
    outside: Counter[str] = field(default_factory=Counter)
    """Paths outside the project, per argument."""
    examples: dict[str, list[str]] = field(default_factory=dict)

    def path_arguments(self) -> list[str]:
        """Arguments the suggested rule keeps inside the project."""
        return sorted(
            name
            for name in self.seen
            if is_path_argument(name) and name not in self.not_paths and _addressable(name)
        )


@dataclass
class LogSummary:
    """What an audit log says about tool calls."""

    calls: int = 0
    sessions: set[str] = field(default_factory=set)
    skipped_lines: int = 0
    undecided: dict[str, ToolUsage] = field(default_factory=dict)
    decided: Counter[tuple[str, str, str]] = field(default_factory=Counter)
    """Calls a rule decided, as ``(tool, decision, rule)``."""


def _addressable(name: str) -> bool:
    # `arg` splits on dots and treats "*" as every string, so such keys cannot be named.
    return bool(name) and "." not in name and name != "*"


def read_log(lines: Iterable[str], project: str) -> LogSummary:
    """Summarize the ``tool_call`` records of an audit log.

    ``project`` is the canonical project directory; path arguments outside it
    are counted so the suggestion can say which calls its rules would block.
    """
    summary = LogSummary()
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            summary.skipped_lines += 1
            continue
        if not isinstance(record, dict):
            summary.skipped_lines += 1
            continue
        if record.get("event") != "tool_call":
            continue
        tool, decision, rule = record.get("tool"), record.get("decision"), record.get("rule")
        if not (isinstance(tool, str) and isinstance(decision, str) and isinstance(rule, str)):
            summary.skipped_lines += 1
            continue
        summary.calls += 1
        if isinstance(record.get("session"), str):
            summary.sessions.add(record["session"])
        if rule != "default":
            summary.decided[(tool, decision, rule)] += 1
            continue
        usage = summary.undecided.setdefault(tool, ToolUsage())
        usage.calls += 1
        arguments = record.get("arguments")
        if isinstance(arguments, dict):
            _note_arguments(usage, arguments, project)
    return summary


def _note_arguments(usage: ToolUsage, arguments: Mapping[str, Any], project: str) -> None:
    for name, value in arguments.items():
        usage.seen[name] += 1
        if not is_path_argument(name):
            continue
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            usage.not_paths.add(name)
            continue
        for path in values:
            try:
                inside = within(path, [project])
            except IndeterminateError:
                inside = False
            if not inside:
                usage.outside[name] += 1
                examples = usage.examples.setdefault(name, [])
                if path not in examples and len(examples) < MAX_EXAMPLES:
                    examples.append(path)


def _escape_glob(tool: str) -> str:
    """A ``tools`` pattern that matches only ``tool``, even if it contains * ? or [."""
    return re.sub(r"([*?\[])", r"[\1]", tool)


def _rule_id(tool: str, taken: set[str]) -> str:
    base = "allow-" + (re.sub(r"[^a-z0-9]+", "-", tool.lower()).strip("-") or "tool")
    candidate, number = base, 2
    while candidate in taken:
        candidate, number = f"{base}-{number}", number + 1
    taken.add(candidate)
    return candidate


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


class _Dumper(yaml.SafeDumper):
    """Writes YAML like the shipped policies: block mappings, indented block
    lists, and lists of plain values on one line."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        super().increase_indent(flow, False)


def _represent_list(dumper: _Dumper, data: list[Any]) -> yaml.Node:
    flow = all(not isinstance(item, (dict, list)) for item in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow)


def _represent_dict(dumper: _Dumper, data: dict[Any, Any]) -> yaml.Node:
    return dumper.represent_mapping("tag:yaml.org,2002:map", data, flow_style=False)


_Dumper.add_representer(list, _represent_list)
_Dumper.add_representer(dict, _represent_dict)


def _dump(value: Any) -> list[str]:
    text = yaml.dump(value, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=1_000_000)
    return text.splitlines()


def _suggested_rule(tool: str, usage: ToolUsage, taken: set[str]) -> list[str]:
    comments = [f"# {tool}: {_plural(usage.calls, 'call')} that no rule decided."]
    rule: dict[str, Any] = {"id": _rule_id(tool, taken), "tools": [_escape_glob(tool)]}
    rule["action"] = "allow"
    paths = usage.path_arguments()
    if paths:
        rule["when"] = [{"arg": name, "within": ["${PROJECT_DIR}"]} for name in paths]
    for name in paths:
        if usage.outside[name]:
            shown = ", ".join(usage.examples[name])
            comments.append(
                f"# {_plural(usage.outside[name], name + ' value')} outside the project,"
                f" which this rule blocks: {shown}"
            )
        missing = usage.calls - usage.seen[name]
        if missing:
            comments.append(f"# {_plural(missing, 'call')} without {name} would be blocked.")
    for name in sorted(n for n in usage.seen if is_path_argument(n) and n not in paths):
        comments.append(f"# {name} looks like a path but is not checked: it held other values.")
    return comments + _dump([rule])


def render(
    summary: LogSummary,
    *,
    source: str,
    base: Mapping[str, Any] | None = None,
    base_name: str | None = None,
) -> str:
    """The suggested policy as YAML: ``base``'s rules first, unchanged, then one allow
    rule per tool that no rule decided. The default is always ``deny``."""
    base = base or {}
    lines = [
        f"# Suggested by `mcp-leash suggest` from {source}: "
        f"{_plural(summary.calls, 'tool call')} in {_plural(len(summary.sessions), 'session')}.",
        "# Each tool that no rule decided gets an allow rule, with path arguments kept",
        "# inside ${PROJECT_DIR}. It allows what the agent did, not what it should do:",
        "# review every rule before you use it.",
    ]
    if base_name is not None:
        lines.append(f"# The rules of {base_name} come first, unchanged (without their comments).")
        if base.get("default") == "allow":
            lines.append(f"# {base_name} used default: allow; this policy uses default: deny.")
    if summary.skipped_lines:
        lines.append(f"# {_plural(summary.skipped_lines, 'line')} of the log could not be read.")

    head: dict[str, Any] = {"version": 1, "default": "deny"}
    head["hide_denied_tools"] = base.get("hide_denied_tools", True)
    audit = base.get("audit") if base_name is not None else DEFAULT_AUDIT
    if audit is not None:
        head["audit"] = audit
    lines += _dump(head)

    existing = [rule for rule in base.get("rules") or [] if isinstance(rule, dict)]
    taken = {str(rule.get("id")) for rule in existing}
    body: list[str] = []
    for rule in existing:
        body += _dump([rule])
    if existing and summary.undecided:
        body.append("")
    for tool in sorted(summary.undecided):
        body += _suggested_rule(tool, summary.undecided[tool], taken)
        body.append("")
    if not summary.undecided:
        body.append("# No call fell to the default rule, so there is nothing to add.")
    lines.append("rules:" if existing or summary.undecided else "rules: []")
    lines += ["  " + line if line else "" for line in body]

    if summary.decided:
        lines.append("# Calls that a rule already decided (left as they are):")
        for (tool, decision, rule_id), count in sorted(summary.decided.items()):
            lines.append(f"#   {tool}: {_plural(count, 'call')}, {decision} by {rule_id}")
    return "\n".join(lines).rstrip("\n") + "\n"
