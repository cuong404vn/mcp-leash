from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_leash.audit import AuditLog
from mcp_leash.cli import app
from mcp_leash.policy import evaluate, parse_policy
from mcp_leash.policy.loader import read_yaml
from mcp_leash.policy.matchers import canonical_path
from mcp_leash.suggest import is_path_argument, read_log, render

ROOT = Path(__file__).parents[2]
runner = CliRunner()


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    return root


def log_lines(*calls: tuple[str, str, str, dict[str, Any]], session: str = "s1") -> list[str]:
    """Audit lines for ``(tool, decision, rule, arguments)`` calls, written by the real writer."""
    stream = io.StringIO()
    audit = AuditLog(stream, [], session=session)
    for number, (tool, decision, rule, arguments) in enumerate(calls):
        audit.tool_call(number, tool, decision, rule, None, arguments)
        audit.tool_result(number, tool, False, 1)
    return stream.getvalue().splitlines()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("path", True),
        ("paths", True),
        ("source", True),
        ("destination", True),
        ("directory", True),
        ("cwd", True),
        ("file_path", True),
        ("filePath", True),
        ("root_dir", True),
        ("output_file", True),
        ("pattern", False),
        ("content", False),
        ("files", False),
        ("profile", False),
        ("query", False),
    ],
)
def test_is_path_argument(name: str, expected: bool) -> None:
    assert is_path_argument(name) is expected


def test_read_log_splits_undecided_from_decided_calls(project: Path) -> None:
    lines = log_lines(
        ("read_file", "would_deny", "default", {"path": str(project / "a.txt")}),
        ("read_file", "allow", "default", {"path": str(project / "b.txt")}),
        ("delete_file", "deny", "no-deletes", {"path": "a"}),
        ("delete_file", "would_deny", "no-deletes", {"path": "b"}),
    )
    lines += log_lines(("get_me", "deny", "default", {}), session="s2")
    lines += ["{broken", "[1, 2]", '{"event": "tool_call", "tool": 5}', "", '{"event": "other"}']
    summary = read_log(lines, canonical_path(str(project)))
    assert summary.calls == 5
    assert summary.sessions == {"s1", "s2"}
    assert summary.skipped_lines == 3
    assert sorted(summary.undecided) == ["get_me", "read_file"]
    assert summary.undecided["read_file"].calls == 2
    assert summary.decided == {
        ("delete_file", "deny", "no-deletes"): 1,
        ("delete_file", "would_deny", "no-deletes"): 1,
    }


def test_read_log_notes_paths_outside_the_project(project: Path) -> None:
    outside = [str(project.parent / f"x{n}.txt") for n in range(5)]
    lines = log_lines(
        ("read_file", "deny", "default", {"path": outside[0]}),
        ("read_file", "deny", "default", {"path": outside[0]}),
        ("read_many", "deny", "default", {"paths": [str(project / "a"), *outside[1:]]}),
        ("tool", "deny", "default", {"path": {"nested": "x"}, "target": "prod"}),
    )
    summary = read_log(lines, canonical_path(str(project)))
    read_file = summary.undecided["read_file"]
    assert read_file.outside["path"] == 2
    assert read_file.examples["path"] == [outside[0]]
    read_many = summary.undecided["read_many"]
    assert read_many.outside["paths"] == 4
    assert read_many.examples["paths"] == outside[1:4]
    assert summary.undecided["tool"].path_arguments() == []
    assert summary.undecided["tool"].not_paths == {"path"}


def suggested(project: Path, lines: list[str], **kwargs: Any) -> str:
    text = render(read_log(lines, canonical_path(str(project))), source="audit.jsonl", **kwargs)
    parse_policy(text, project_dir=str(project), env={})
    return text


def test_suggested_policy_allows_the_logged_calls_inside_the_project(project: Path) -> None:
    lines = log_lines(
        ("read_text_file", "would_deny", "default", {"path": str(project / "src" / "a.py")}),
        ("read_text_file", "would_deny", "default", {"path": "/etc/hosts"}),
        ("read_multiple_files", "would_deny", "default", {"paths": [str(project / "a")]}),
        ("search_files", "would_deny", "default", {"pattern": "*.py"}),
        ("search_files", "would_deny", "default", {"path": str(project), "pattern": "*.md"}),
        ("list_allowed_directories", "would_deny", "default", {}),
        ("delete_file", "would_deny", "no-deletes", {"path": str(project / "a")}),
    )
    text = suggested(project, lines)
    policy = parse_policy(text, project_dir=str(project), env={})
    assert policy.default == "deny"
    assert [r.id for r in policy.rules] == [
        "allow-list-allowed-directories",
        "allow-read-multiple-files",
        "allow-read-text-file",
        "allow-search-files",
    ]

    def allowed(tool: str, **arguments: Any) -> bool:
        return evaluate(policy, tool, arguments).allowed

    assert allowed("read_text_file", path=str(project / "src" / "a.py"))
    assert not allowed("read_text_file", path="/etc/hosts")
    assert allowed("read_multiple_files", paths=[str(project / "a"), str(project / "b")])
    assert not allowed("read_multiple_files", paths=[str(project / "a"), "/etc/hosts"])
    assert allowed("search_files", path=str(project), pattern="*")
    assert not allowed("search_files", pattern="*")
    assert allowed("list_allowed_directories")
    assert not allowed("delete_file", path=str(project / "a"))
    assert not allowed("write_file", path=str(project / "a"))

    assert "# 1 path value outside the project, which this rule blocks: /etc/hosts" in text
    assert "# 1 call without path would be blocked." in text
    assert "#   delete_file: 1 call, would_deny by no-deletes" in text
    assert "1 tool call" not in text
    assert "7 tool calls in 1 session." in text


def test_existing_rules_come_first_and_default_becomes_deny(project: Path) -> None:
    base_text = (ROOT / "policies" / "project.yaml").read_text(encoding="utf-8")
    base = read_yaml(base_text.replace("default: deny", "default: allow"))
    lines = log_lines(
        ("get_me", "allow", "default", {}), ("directory_tree", "allow", "default", {})
    )
    text = suggested(project, lines, base=base, base_name="mcp-leash.yaml")
    original = parse_policy(base_text, project_dir=str(project), env={})
    policy = parse_policy(text, project_dir=str(project), env={})
    count = len(original.rules)
    assert [r.model_dump() for r in policy.rules[:count]] == [
        r.model_dump() for r in original.rules
    ]
    assert [r.id for r in policy.rules[count:]] == ["allow-directory-tree", "allow-get-me"]
    assert policy.default == "deny"
    assert "# mcp-leash.yaml used default: allow; this policy uses default: deny." in text
    assert policy.audit == original.audit


def test_a_base_without_audit_keeps_logging_to_stderr(project: Path) -> None:
    base = {"version": 1, "default": "deny", "rules": []}
    text = suggested(project, log_lines(("t", "deny", "default", {})), base=base, base_name="p")
    assert parse_policy(text, project_dir=str(project), env={}).audit.path is None
    assert "hide_denied_tools: true" in text


def test_rule_ids_stay_unique(project: Path) -> None:
    base = {
        "version": 1,
        "default": "deny",
        "rules": [{"id": "allow-read-file", "tools": ["x"], "action": "deny"}],
    }
    lines = log_lines(("read_file", "deny", "default", {}), ("read-file", "deny", "default", {}))
    text = suggested(project, lines, base=base, base_name="p")
    ids = [r.id for r in parse_policy(text, project_dir=str(project), env={}).rules]
    assert ids == ["allow-read-file", "allow-read-file-2", "allow-read-file-3"]


def test_tool_names_with_glob_characters_match_only_themselves(project: Path) -> None:
    tool = "odd*tool[1]?"
    text = suggested(project, log_lines((tool, "deny", "default", {})))
    policy = parse_policy(text, project_dir=str(project), env={})
    assert evaluate(policy, tool, {}).allowed
    assert not evaluate(policy, "oddXXtool1!", {}).allowed
    assert policy.rules[0].id == "allow-odd-tool-1"


def test_arguments_that_cannot_be_named_are_left_unchecked(project: Path) -> None:
    lines = log_lines(("t", "deny", "default", {"a.path": "/x", "path": {"k": 1}}))
    text = suggested(project, lines)
    assert "when:" not in text
    assert "# a.path looks like a path but is not checked" in text
    assert "# path looks like a path but is not checked" in text


def test_nothing_to_add(project: Path) -> None:
    text = suggested(project, log_lines(("rm", "deny", "no-deletes", {})))
    assert "rules: []" in text
    assert "nothing to add" in text
    assert parse_policy(text, project_dir=str(project), env={}).rules == []


def write_log(path: Path, *calls: tuple[str, str, str, dict[str, Any]]) -> Path:
    path.write_text("\n".join(log_lines(*calls)) + "\n", encoding="utf-8")
    return path


def test_cli_suggest(project: Path, tmp_path: Path) -> None:
    log = write_log(
        tmp_path / "audit.jsonl", ("read_file", "would_deny", "default", {"path": "src/a.py"})
    )
    result = runner.invoke(app, ["suggest", str(log), "--project-dir", str(project)])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.startswith("# Suggested by `mcp-leash suggest` from audit.jsonl")
    assert "id: allow-read-file" in result.stdout
    assert result.stderr == ""
    parse_policy(result.stdout, project_dir=str(project), env={})


def test_cli_suggest_with_a_policy(project: Path, tmp_path: Path) -> None:
    log = write_log(tmp_path / "audit.jsonl", ("get_me", "deny", "default", {}))
    policy = ROOT / "policies" / "readonly.yaml"
    args = ["suggest", str(log), "--policy", str(policy), "--project-dir", str(project)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stderr
    ids = [r.id for r in parse_policy(result.stdout, project_dir=str(project), env={}).rules]
    assert ids[0] == "no-writes"
    assert ids[-1] == "allow-get-me"


def test_cli_suggest_reports_when_nothing_is_added(tmp_path: Path) -> None:
    log = write_log(tmp_path / "audit.jsonl", ("rm", "deny", "no-deletes", {}))
    result = runner.invoke(app, ["suggest", str(log)])
    assert result.exit_code == 0
    assert "nothing to add" in result.stderr


def test_cli_suggest_missing_log(tmp_path: Path) -> None:
    result = runner.invoke(app, ["suggest", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 2
    assert "cannot read the audit log" in result.stderr


def test_cli_suggest_invalid_policy(tmp_path: Path) -> None:
    log = write_log(tmp_path / "audit.jsonl")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ndefault: maybe\n", encoding="utf-8")
    result = runner.invoke(app, ["suggest", str(log), "--policy", str(bad)])
    assert result.exit_code == 2
    assert "invalid policy" in result.stderr


def test_log_lines_match_the_documented_format() -> None:
    record = json.loads(log_lines(("t", "allow", "r", {"a": 1}))[0])
    assert {"ts", "event", "session", "tool", "decision", "rule", "arguments"} <= set(record)
