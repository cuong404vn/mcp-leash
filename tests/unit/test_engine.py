from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_leash.policy import Decision, Policy, always_denied, evaluate, parse_policy


def make_policy(rules: str, default: str = "deny", project_dir: Path | None = None) -> Policy:
    text = (
        f"version: 1\ndefault: {default}\nrules:\n{rules}"
        if rules
        else f"version: 1\ndefault: {default}\n"
    )
    return parse_policy(text, project_dir=str(project_dir) if project_dir else None, env={})


ORDERED = """
  - id: deny-delete
    tools: ['delete_*']
    action: deny
    reason: no deletes
  - id: allow-all-files
    tools: ['*_file']
    action: allow
  - id: never-reached
    tools: ['delete_file']
    action: allow
"""


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("delete_file", Decision("deny", "deny-delete", "no deletes")),
        ("read_file", Decision("allow", "allow-all-files", None)),
        ("Read_File", Decision("deny", "default", None)),
        ("list_directory", Decision("deny", "default", None)),
    ],
)
def test_first_matching_rule_wins(tool: str, expected: Decision) -> None:
    assert evaluate(make_policy(ORDERED), tool, {}) == expected


@pytest.mark.parametrize("default", ["allow", "deny"])
def test_default_applies_when_nothing_matches(default: str) -> None:
    decision = evaluate(make_policy("", default=default), "anything", {"a": 1})
    assert decision == Decision(default, "default", None)  # type: ignore[arg-type]


def test_rule_with_failing_condition_falls_through() -> None:
    policy = make_policy(
        """
  - id: only-safe-mode
    tools: ['run']
    action: allow
    when:
      - arg: mode
        equals: safe
  - id: fallback
    tools: ['run']
    action: deny
"""
    )
    assert evaluate(policy, "run", {"mode": "safe"}).rule == "only-safe-mode"
    assert evaluate(policy, "run", {"mode": "fast"}).rule == "fallback"
    assert evaluate(policy, "run", {}).rule == "fallback"


def test_conditions_are_combined_with_and() -> None:
    policy = make_policy(
        """
  - id: both
    tools: ['t']
    action: allow
    when:
      - arg: a
        equals: 1
      - arg: b
        equals: 2
"""
    )
    assert evaluate(policy, "t", {"a": 1, "b": 2}).allowed
    assert not evaluate(policy, "t", {"a": 1, "b": 3}).allowed
    assert not evaluate(policy, "t", {"a": 1}).allowed


def test_indeterminate_condition_denies_with_that_rule() -> None:
    policy = make_policy(
        """
  - id: prefix
    tools: ['t']
    action: allow
    when:
      - arg: path
        starts_with: /tmp/
"""
    )
    decision = evaluate(policy, "t", {"path": ["/tmp/a"]})
    assert decision.action == "deny"
    assert decision.rule == "prefix"
    assert decision.reason is not None
    assert "needs a string" in decision.reason


def test_lists_of_paths_lean_toward_deny(tmp_path: Path) -> None:
    project = tmp_path / "project"
    secrets = project / "secrets"
    secrets.mkdir(parents=True)
    policy = parse_policy(
        "version: 1\ndefault: deny\nrules:\n"
        "  - id: no-secrets\n    tools: ['*']\n    action: deny\n    when:\n"
        "      - arg: paths\n        within: ['${PROJECT_DIR}/secrets']\n"
        "  - id: read-project\n    tools: ['*']\n    action: allow\n    when:\n"
        "      - arg: paths\n        within: ['${PROJECT_DIR}']\n",
        project_dir=str(project),
        env={},
    )

    def decide(*paths: Any) -> Decision:
        return evaluate(policy, "read_multiple_files", {"paths": list(paths)})

    readme, key = str(project / "README.md"), str(secrets / "key.pem")
    assert decide(readme, str(project / "src" / "a.py")).rule == "read-project"
    # One path in secrets is enough for the deny rule; the allow rule alone would match.
    assert decide(readme, key).rule == "no-secrets"
    assert decide(key, readme).rule == "no-secrets"
    # One path outside the project is enough to miss the allow rule.
    assert decide(readme, str(tmp_path / "other.txt")) == Decision("deny", "default", None)
    assert decide() == Decision("deny", "default", None)
    decision = decide(readme, 5)
    assert (decision.action, decision.rule) == ("deny", "no-secrets")
    assert decision.reason is not None
    assert "needs a path or a list of paths" in decision.reason


def test_deny_rules_ignore_case_on_every_platform(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".ssh").mkdir(parents=True)
    policy = parse_policy(
        "version: 1\ndefault: deny\nrules:\n"
        "  - id: no-keys\n    tools: ['*']\n    action: deny\n    when:\n"
        "      - arg: path\n        within: ['${PROJECT_DIR}/.ssh']\n"
        "  - id: read-project\n    tools: ['*']\n    action: allow\n    when:\n"
        "      - arg: path\n        within: ['${PROJECT_DIR}']\n",
        project_dir=str(project),
        env={},
    )
    for name in [".ssh", ".SSH", ".Ssh"]:
        decision = evaluate(policy, "read_text_file", {"path": str(project / name / "id_rsa")})
        assert decision.rule == "no-keys", name
    assert evaluate(policy, "read_text_file", {"path": str(project / "a.txt")}).allowed


def test_glob_patterns() -> None:
    policy = make_policy(
        """
  - id: g
    tools: ['git_?', 'fs_[ab]*', 'exact']
    action: allow
""",
    )
    allowed = ["git_x", "fs_alpha", "fs_beta", "exact"]
    denied = ["git_xy", "fs_c", "exactly", "EXACT"]
    assert all(evaluate(policy, t, {}).allowed for t in allowed)
    assert not any(evaluate(policy, t, {}).allowed for t in denied)


ALWAYS = """
  - id: conditional-deny
    tools: ['a']
    action: deny
    when:
      - arg: x
        equals: 1
  - id: deny-a
    tools: ['a', 'b']
    action: deny
  - id: allow-c
    tools: ['c']
    action: allow
    when:
      - arg: x
        equals: 1
  - id: deny-c
    tools: ['c']
    action: deny
"""


@pytest.mark.parametrize(
    ("tool", "expected"),
    [("a", True), ("b", True), ("c", False), ("unmatched", False)],
)
def test_always_denied(tool: str, expected: bool) -> None:
    assert always_denied(make_policy(ALWAYS), tool) is expected


def test_evaluate_example_policy(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    example = Path(__file__).parents[2] / "policies" / "example.yaml"
    policy = parse_policy(example.read_text(encoding="utf-8"), project_dir=str(tmp_path))
    cases: list[tuple[str, dict[str, Any], str]] = [
        ("delete_file", {"path": str(tmp_path / "a")}, "no-deletes"),
        ("read_file", {"path": str(tmp_path / "a.txt")}, "read-inside-project"),
        ("read_file", {"path": str(tmp_path / ".." / "a.txt")}, "default"),
        ("write_file", {"path": str(tmp_path / "src" / "m.py")}, "write-only-src-and-docs"),
        ("write_file", {"path": str(tmp_path / "setup.py")}, "default"),
        (
            "read_file",
            {"path": str(tmp_path / "a"), "x": "BEGIN RSA PRIVATE KEY"},
            "no-credentials-in-arguments",
        ),
    ]
    for tool, arguments, rule in cases:
        assert evaluate(policy, tool, arguments).rule == rule, (tool, arguments)
