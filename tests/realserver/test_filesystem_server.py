"""The shipped project template in front of the real filesystem MCP server.

These tests download @modelcontextprotocol/server-filesystem with npx, so they
need Node.js and network access. They run only when MCP_LEASH_REAL_SERVERS=1.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "@modelcontextprotocol/server-filesystem@2.0.1"
TEMPLATE = Path(__file__).parents[2] / "src" / "mcp_leash" / "templates" / "project.yaml"
TIMEOUT = 180.0

pytestmark = pytest.mark.skipif(
    os.environ.get("MCP_LEASH_REAL_SERVERS") != "1" or shutil.which("npx") is None,
    reason="set MCP_LEASH_REAL_SERVERS=1 and install Node.js to run real-server tests",
)


class Client:
    """A minimal MCP client talking to ``mcp-leash run`` over pipes."""

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc
        self._lines: queue.Queue[bytes] = queue.Queue()
        self._next_id = 0
        threading.Thread(target=self._read_lines, daemon=True).start()

    def _read_lines(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        while True:
            reply: dict[str, Any] = json.loads(self._lines.get(timeout=TIMEOUT))
            if reply.get("id") == request_id:
                return reply

    def call(self, tool: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        """Return ``(is_error, text)`` for one tool call."""
        result = self.request("tools/call", {"name": tool, "arguments": arguments})["result"]
        return bool(result.get("isError")), str(result["content"][0]["text"])


@pytest.fixture(scope="module")
def dirs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    base = tmp_path_factory.mktemp("real")
    project = base / "project"
    (project / "src").mkdir(parents=True)
    (project / "notes.txt").write_bytes(b"hello from the project\n")
    (project / "src" / "app.py").write_text("print('hi')\n")
    (project / ".env").write_text("API_TOKEN=abc\n")
    outside = base / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("not for agents\n")
    return project, outside


@pytest.fixture(scope="module")
def client(dirs: tuple[Path, Path]) -> Iterator[Client]:
    project, _ = dirs
    audit = project.parent / "audit.jsonl"
    policy = project.parent / "policy.yaml"
    text = TEMPLATE.read_text(encoding="utf-8")
    policy.write_text(text.replace("~/.mcp-leash/audit.jsonl", audit.as_posix()), encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "mcp_leash", "run",
            "--policy", str(policy), "--project-dir", str(project),
            "--", "npx", "-y", PACKAGE, str(project),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=project.parent,
    )  # fmt: skip
    client = Client(proc)
    init = client.request(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-leash-tests", "version": "0"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "secure-filesystem-server"
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    yield client
    assert proc.stdin is not None
    proc.stdin.close()
    assert proc.wait(timeout=60) == 0


def test_tools_list_reaches_the_client(client: Client) -> None:
    names = {tool["name"] for tool in client.request("tools/list")["result"]["tools"]}
    assert {"read_text_file", "write_file", "move_file", "list_allowed_directories"} <= names


def test_reads_inside_the_project_are_allowed(client: Client, dirs: tuple[Path, Path]) -> None:
    project, _ = dirs
    assert client.call("read_text_file", {"path": str(project / "notes.txt")}) == (
        False,
        "hello from the project\n",
    )
    is_error, text = client.call("list_directory", {"path": str(project)})
    assert not is_error
    assert "notes.txt" in text
    assert not client.call("list_allowed_directories", {})[0]


@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("OUT/private.txt", "default"),
        ("IN/../outside/private.txt", "default"),
        ("IN/src/../../outside/private.txt", "default"),
        ("IN/.env", "no-env-or-git-internals"),
        ("private.txt", "default"),
    ],
)
def test_reads_outside_the_project_are_blocked(
    client: Client, dirs: tuple[Path, Path], path: str, rule: str
) -> None:
    project, outside = dirs
    resolved = path.replace("IN", str(project)).replace("OUT", str(outside))
    is_error, text = client.call("read_text_file", {"path": resolved})
    assert is_error
    assert text.startswith(f"Blocked by mcp-leash (rule {rule})")


def test_writes_follow_the_policy(client: Client, dirs: tuple[Path, Path]) -> None:
    project, outside = dirs
    code = 'API_KEY = os.environ["API_KEY"]\n'
    assert not client.call(
        "write_file", {"path": str(project / "src" / "settings.py"), "content": code}
    )[0]
    assert (project / "src" / "settings.py").read_text() == code

    is_error, text = client.call("write_file", {"path": str(outside / "x.txt"), "content": "x"})
    assert is_error
    assert "rule default" in text
    assert not (outside / "x.txt").exists()

    is_error, text = client.call(
        "write_file", {"path": str(project / "cfg.txt"), "content": "api_key=abcdefghijklmnop"}
    )
    assert is_error
    assert "rule no-credentials-in-arguments" in text
    assert not (project / "cfg.txt").exists()


def test_moves_must_stay_inside_the_project(client: Client, dirs: tuple[Path, Path]) -> None:
    project, outside = dirs
    (project / "draft.txt").write_text("draft\n")
    is_error, _ = client.call(
        "move_file",
        {"source": str(project / "draft.txt"), "destination": str(outside / "draft.txt")},
    )
    assert is_error
    assert (project / "draft.txt").exists()

    is_error, _ = client.call(
        "move_file",
        {"source": str(project / "draft.txt"), "destination": str(project / "final.txt")},
    )
    assert not is_error
    assert (project / "final.txt").exists()


def test_audit_log_records_real_calls(client: Client, dirs: tuple[Path, Path]) -> None:
    project, _ = dirs
    client.call("read_text_file", {"path": str(project / "notes.txt")})
    audit = project.parent / "audit.jsonl"
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    events = {(r["event"], r.get("decision")) for r in records}
    assert ("tool_call", "allow") in events
    assert ("tool_call", "deny") in events
    assert ("tool_result", None) in events
