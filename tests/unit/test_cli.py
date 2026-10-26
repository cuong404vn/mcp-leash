from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_leash import __version__
from mcp_leash.cli import app

runner = CliRunner()
ROOT = Path(__file__).parents[2]
EXAMPLE = ROOT / "policies" / "example.yaml"


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"mcp-leash {__version__}"


def test_validate_valid_policy() -> None:
    result = runner.invoke(app, ["validate", str(EXAMPLE)])
    assert result.exit_code == 0
    assert "valid (4 rules, default deny)" in result.stdout


def test_validate_invalid_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ndefault: maybe\n")
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "invalid policy" in result.stderr
    assert "default" in result.stderr


def test_validate_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2
    assert "cannot read policy file" in result.stderr


@pytest.mark.parametrize(
    ("tool", "args", "expected"),
    [
        (
            "delete_file",
            '{"path": "a"}',
            ["decision: deny", "rule: no-deletes", "reason: Deleting"],
        ),
        ("read_file", '{"path": "README.md"}', ["decision: allow", "rule: read-inside-project"]),
        ("read_file", '{"path": "../x"}', ["decision: deny", "rule: default"]),
        ("list_directory", "{}", ["decision: deny", "rule: default"]),
    ],
)
def test_check(tool: str, args: str, expected: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    result = runner.invoke(app, ["check", str(EXAMPLE), "--tool", tool, "--args", args])
    assert result.exit_code == 0, result.output
    for text in expected:
        assert text in result.stdout


def test_check_uses_project_dir(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "check",
            str(EXAMPLE),
            "--tool",
            "write_file",
            "--args",
            json.dumps({"path": str(tmp_path / "src" / "a.py")}),
            "--project-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "rule: write-only-src-and-docs" in result.stdout


@pytest.mark.parametrize(
    ("args", "error"),
    [
        ("{not json", "not valid JSON"),
        ('{"a":1,"a":2}', "duplicate key"),
        ("[1, 2]", "must be a JSON object"),
    ],
)
def test_check_rejects_bad_args(args: str, error: str) -> None:
    result = runner.invoke(app, ["check", str(EXAMPLE), "--tool", "t", "--args", args])
    assert result.exit_code == 2
    assert error in result.stderr


@pytest.mark.parametrize("template", ["readonly", "project"])
def test_init_writes_template(
    template: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--template", template])
    assert result.exit_code == 0
    written = (tmp_path / "mcp-leash.yaml").read_bytes()
    assert written == (ROOT / "policies" / f"{template}.yaml").read_bytes()
    assert runner.invoke(app, ["validate", "mcp-leash.yaml"]).exit_code == 0


def test_init_defaults_to_project_template(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init"]).exit_code == 0
    assert "id: write-inside-project" in (tmp_path / "mcp-leash.yaml").read_text()


def test_init_refuses_to_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcp-leash.yaml").write_text("mine")
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 1
    assert "already exists" in result.stderr
    assert (tmp_path / "mcp-leash.yaml").read_text() == "mine"
    assert runner.invoke(app, ["init", "--force"]).exit_code == 0
    assert (tmp_path / "mcp-leash.yaml").read_text() != "mine"


def test_init_rejects_unknown_template(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--template", "nope"])
    assert result.exit_code == 2
    assert not (tmp_path / "mcp-leash.yaml").exists()


def test_run_with_invalid_policy_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\n")
    result = runner.invoke(app, ["run", "--policy", str(bad), "--", "python", "-c", "pass"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "invalid policy" in result.stderr


def test_run_with_unwritable_audit_path_exits_2(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(f"version: 1\ndefault: deny\naudit:\n  path: '{tmp_path.as_posix()}'\n")
    result = runner.invoke(app, ["run", "--policy", str(policy), "--", "python", "-c", "pass"])
    assert result.exit_code == 2
    assert "cannot open the audit log" in result.stderr


def test_run_requires_a_command(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--policy", str(EXAMPLE)])
    assert result.exit_code == 2
