"""Behaviour of the shipped policy templates, with the tool names of the official filesystem server."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.policy import Policy, evaluate, parse_policy

TEMPLATES = Path(__file__).parents[2] / "src" / "mcp_leash" / "templates"


@functools.cache
def template(name: str, project: Path) -> Policy:
    text = (TEMPLATES / f"{name}.yaml").read_text(encoding="utf-8")
    return parse_policy(text, project_dir=str(project), env={})


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("templates") / "project"
    (root / "src").mkdir(parents=True)
    return root


CREDENTIALS = [
    "api_key=abcdefghijklmnop",
    'API-KEY: "abcdefghijklmnopqrstu"',
    '{"secret": "0123456789abcdef"}',
    "password=CorrectHorseBattery9",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "x = 'sk-abcdefghijklmnopqrstuvwxyz'",
]

NOT_CREDENTIALS = [
    'API_KEY = os.environ["API_KEY"]',
    "token = get_token()",
    "password: hunter2",
    "Use a token to authenticate.",
    "the secret: is out",
]

NOT_CREDENTIAL_FILES = ["secret.txt", "docs/api_key_rotation.md", "src/secrets_manager.py"]


@pytest.mark.parametrize("name", ["readonly", "project"])
@pytest.mark.parametrize("text", CREDENTIALS)
def test_credentials_are_blocked(name: str, text: str, project: Path) -> None:
    arguments = {"path": str(project / "a.txt"), "content": text, "pattern": text}
    decision = evaluate(template(name, project), "read_text_file", arguments)
    assert decision.rule == "no-credentials-in-arguments"


@pytest.mark.parametrize("text", NOT_CREDENTIALS)
def test_code_mentioning_credentials_can_be_written(text: str, project: Path) -> None:
    arguments = {"path": str(project / "src" / "settings.py"), "content": text}
    assert evaluate(template("project", project), "write_file", arguments).allowed


@pytest.mark.parametrize("name", ["readonly", "project"])
@pytest.mark.parametrize("relative", NOT_CREDENTIAL_FILES)
def test_files_named_after_secrets_can_be_read(name: str, relative: str, project: Path) -> None:
    arguments = {"path": str(project / relative)}
    assert evaluate(template(name, project), "read_text_file", arguments).allowed


@pytest.mark.parametrize("relative", [".env", ".env.local", ".git/config", "sub/.git/HEAD"])
def test_project_template_blocks_env_and_git(relative: str, project: Path) -> None:
    decision = evaluate(
        template("project", project), "read_text_file", {"path": str(project / relative)}
    )
    assert decision.rule == "no-env-or-git-internals"


@pytest.mark.parametrize("name", ["readonly", "project"])
@pytest.mark.parametrize(
    ("tool", "arguments", "allowed"),
    [
        ("list_allowed_directories", {}, True),
        ("read_media_file", {"path": "IN/logo.png"}, True),
        ("get_file_info", {"path": "IN/a.txt"}, True),
        ("search_files", {"path": "IN", "pattern": "*.py"}, True),
        ("read_text_file", {"path": "OUT/a.txt"}, False),
        ("read_text_file", {"path": "IN/../../a.txt"}, False),
        ("read_multiple_files", {"paths": ["IN/a.txt"]}, False),
    ],
)
def test_read_rules(
    name: str, tool: str, arguments: dict[str, Any], allowed: bool, project: Path
) -> None:
    resolved = {
        k: v.replace("IN", str(project)).replace("OUT", str(project.parent))
        if isinstance(v, str)
        else v
        for k, v in arguments.items()
    }
    assert evaluate(template(name, project), tool, resolved).allowed is allowed


@pytest.mark.parametrize(
    ("tool", "arguments", "allowed"),
    [
        ("write_file", {"path": "IN/src/a.py", "content": "x = 1"}, True),
        ("write_file", {"path": "OUT/a.py", "content": "x = 1"}, False),
        ("edit_file", {"path": "IN/src/a.py", "edits": []}, True),
        ("create_directory", {"path": "IN/docs"}, True),
        ("move_file", {"source": "IN/a.txt", "destination": "IN/b.txt"}, True),
        ("move_file", {"source": "IN/a.txt", "destination": "OUT/b.txt"}, False),
        ("move_file", {"source": "OUT/a.txt", "destination": "IN/b.txt"}, False),
    ],
)
def test_project_template_write_rules(
    tool: str, arguments: dict[str, Any], allowed: bool, project: Path
) -> None:
    resolved = {
        k: v.replace("IN", str(project)).replace("OUT", str(project.parent))
        if isinstance(v, str)
        else v
        for k, v in arguments.items()
    }
    assert evaluate(template("project", project), tool, resolved).allowed is allowed


@pytest.mark.parametrize("tool", ["write_file", "edit_file", "create_directory", "move_file"])
def test_readonly_template_blocks_writes(tool: str, project: Path) -> None:
    decision = evaluate(template("readonly", project), tool, {"path": str(project / "a.txt")})
    assert decision.rule == "no-writes"
