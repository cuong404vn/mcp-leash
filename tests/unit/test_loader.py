from __future__ import annotations

from pathlib import Path

import pytest

from mcp_leash.policy import PolicyError, load_policy, parse_policy
from mcp_leash.policy.loader import expand_variables
from mcp_leash.policy.matchers import canonical_path
from mcp_leash.policy.models import DEFAULT_REDACT_KEYS

MINIMAL = "version: 1\ndefault: deny\n"


def rule(body: str) -> str:
    return MINIMAL + "rules:\n  - id: r\n    tools: ['t']\n" + body


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("version: 2\ndefault: deny\n", "version"),
        ("version: 1\ndefault: block\n", "default"),
        ("version: 1\n", "default"),
        (MINIMAL + "unknown_key: 1\n", "unknown_key"),
        (
            rule("    action: deny\n    when:\n      - arg: a\n        unknown_operator: x\n"),
            "unknown_operator",
        ),
        (MINIMAL + "hide_denied_tools: 'yes'\n", "hide_denied_tools"),
        (rule("    action: maybe\n"), "action"),
        (rule("    action: deny\n    when:\n      - arg: a\n        contains: x\n"), "contains"),
        (rule("    action: deny\n    when:\n      - arg: a\n"), "exactly one operator"),
        (
            rule(
                "    action: deny\n    when:\n      - arg: a\n        equals: x\n        matches: x\n"
            ),
            "exactly one operator",
        ),
        (
            rule("    action: deny\n    when:\n      - arg: a\n        matches: '(unclosed'\n"),
            "invalid regular",
        ),
        (rule("    action: deny\n    when:\n      - arg: a\n        equals: [1]\n"), "equals"),
        (rule("    action: deny\n    when:\n      - arg: a\n        within: []\n"), "within"),
        (
            rule("    action: deny\n    when:\n      - arg: a.\n        equals: 1\n"),
            "invalid argument path",
        ),
        (
            rule("    action: deny\n    when:\n      - arg: p\n        within: ['${NOPE}/x']\n"),
            "unknown or empty variable \\$\\{NOPE\\}",
        ),
        (
            rule("    action: deny\n    when:\n      - arg: p\n        within: ['${EMPTY}/x']\n"),
            "unknown or empty variable",
        ),
        (
            rule(
                "    action: deny\n    when:\n      - arg: p\n        within: ['${PROJECT_DIR']\n"
            ),
            "unterminated",
        ),
        (
            rule("    action: deny\n    when:\n      - arg: p\n        within: ['${1BAD}']\n"),
            "invalid variable name",
        ),
        (
            rule("    action: deny\n    when:\n      - arg: p\n        starts_with: '${NOPE}'\n"),
            "NOPE",
        ),
        (MINIMAL + "rules:\n  - id: r\n    tools: 't'\n    action: deny\n", "tools"),
        (MINIMAL + "rules:\n  - id: r\n    tools: []\n    action: deny\n", "tools"),
        (MINIMAL + "rules:\n  - tools: ['t']\n    action: deny\n", "id"),
        (
            MINIMAL
            + "rules:\n  - {id: r, tools: [a], action: deny}\n  - {id: r, tools: [b], action: deny}\n",
            "used more than once",
        ),
        (MINIMAL + "rules:\n  - {id: default, tools: [a], action: deny}\n", "reserved"),
        (MINIMAL + "default: allow\n", "duplicate key"),
        (rule("    action: deny\n    action: allow\n"), "duplicate key"),
        ("- just\n- a list\n", "mapping"),
        ("", "mapping"),
        ("version: [1\n", "invalid YAML"),
    ],
)
def test_invalid_policies(text: str, error: str) -> None:
    with pytest.raises(PolicyError, match=error):
        parse_policy(text, env={"EMPTY": ""})


@pytest.mark.parametrize(
    ("text", "line", "column"),
    [
        (
            rule("    action: deny\n    when:\n      - arg: a\n        unknown_operator: x\n"),
            9,
            9,
        ),
        (rule(""), 4, 5),
        (
            rule("    action: deny\n    when:\n      - arg: p\n        within: ['${MISSING}/x']\n"),
            9,
            9,
        ),
    ],
)
def test_validation_errors_include_source_location(text: str, line: int, column: int) -> None:
    with pytest.raises(PolicyError, match=rf"line {line}, column {column}:"):
        parse_policy(text, env={})


def test_defaults() -> None:
    policy = parse_policy(MINIMAL, env={})
    assert policy.rules == []
    assert policy.hide_denied_tools is False
    assert policy.audit.path is None
    assert policy.audit.redact_keys == DEFAULT_REDACT_KEYS


def test_project_dir_defaults_to_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    policy = parse_policy(
        rule("    action: allow\n    when:\n      - arg: p\n        within: ['${PROJECT_DIR}']\n")
    )
    assert policy.rules[0].when[0].within == [canonical_path(str(tmp_path))]


def test_variables_expand_in_string_operands_but_not_regex(tmp_path: Path) -> None:
    text = rule(
        "    action: deny\n    when:\n"
        "      - arg: a\n        starts_with: '${PROJECT_DIR}/'\n"
        "      - arg: b\n        equals: '${USER_NAME}'\n"
        "      - arg: c\n        in: ['${USER_NAME}', 3]\n"
        "      - arg: d\n        matches: '^\\$\\{x\\}$'\n"
    )
    policy = parse_policy(text, project_dir=str(tmp_path), env={"USER_NAME": "me"})
    when = policy.rules[0].when
    assert when[0].starts_with == canonical_path(str(tmp_path)) + "/"
    assert when[1].equals == "me"
    assert when[2].in_ == ["me", 3]
    assert when[3].matches == "^\\$\\{x\\}$"


def test_tilde_expands_in_within_and_audit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    text = (
        "version: 1\ndefault: deny\naudit:\n  path: ~/logs/audit.jsonl\n"
        "rules:\n  - id: r\n    tools: ['t']\n    action: allow\n    when:\n"
        "      - arg: p\n        within: ['~/work']\n"
    )
    policy = parse_policy(text, env={})
    assert policy.audit.path is not None
    assert Path(policy.audit.path) == tmp_path / "logs" / "audit.jsonl"
    assert policy.rules[0].when[0].within == [canonical_path(str(tmp_path / "work"))]


def test_expand_variables() -> None:
    lookup = {"A": "1", "B": "two"}.get
    assert expand_variables("${A}/${B}/$C/$", lookup) == "1/two/$C/$"
    assert expand_variables("no variables", lookup) == "no variables"


def test_load_policy_reads_file_with_bom(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + MINIMAL.encode())
    assert load_policy(path).default == "deny"


def test_load_policy_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read policy file"):
        load_policy(tmp_path / "missing.yaml")


def test_load_policy_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_bytes(b"version: 1\ndefault: \xff\n")
    with pytest.raises(PolicyError, match="not valid UTF-8"):
        load_policy(path)


@pytest.mark.parametrize(
    "name", ["example.yaml", "readonly.yaml", "project.yaml", "github.yaml", "shell.yaml"]
)
def test_shipped_policies_are_valid(name: str) -> None:
    path = Path(__file__).parents[2] / "policies" / name
    policy = load_policy(path)
    assert policy.version == 1


@pytest.mark.parametrize("name", ["readonly.yaml", "project.yaml"])
def test_shipped_policies_match_init_templates(name: str) -> None:
    root = Path(__file__).parents[2]
    template = root / "src" / "mcp_leash" / "templates" / name
    assert (root / "policies" / name).read_bytes() == template.read_bytes()
