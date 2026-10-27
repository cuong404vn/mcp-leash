"""End-to-end tests: ``mcp-leash run`` as a real process between pipes and the fake server."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.integration.support import FAKE_SERVER

POLICY = """
version: 1
default: deny
hide_denied_tools: true
audit:
  path: {audit}
rules:
  - id: no-deletes
    tools: ['delete_*']
    action: deny
    reason: Deleting files is not permitted for agents.
  - id: allow-rest
    tools: ['*']
    action: allow
"""


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        **os.environ,
        "FAKE_SERVER_RECORD": str(tmp_path / "received.jsonl"),
        "FAKE_SERVER_PID_FILE": str(tmp_path / "server.pid"),
        "PYTHONUTF8": "1",
    }


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY.format(audit=json.dumps((tmp_path / "audit.jsonl").as_posix())))
    return path


def start(policy_file: Path, env: dict[str, str], *extra: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mcp_leash",
            "run",
            "--policy",
            str(policy_file),
            *extra,
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def line(message: Any) -> bytes:
    return json.dumps(message).encode() + b"\n"


def call(request_id: int, tool: str, arguments: dict[str, Any] | None = None) -> bytes:
    params = {"name": tool, "arguments": arguments or {}}
    return line({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})


def test_run_end_to_end(policy_file: Path, env: dict[str, str], tmp_path: Path) -> None:
    proc = start(policy_file, env)
    stdin = b"".join(
        [
            line({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}),
            line({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            call(2, "delete_file", {"path": "/tmp/x"}),
            call(3, "echo", {"token": "s3cret"}),
            b"{broken\n",
        ]
    )
    stdout, stderr = proc.communicate(stdin, timeout=60)
    assert proc.returncode == 0, stderr.decode()

    responses = {
        m["id"]: m for m in map(json.loads, stdout.splitlines())
    }  # stdout is protocol only
    assert sorted(responses) == [0, 1, 2, 3]
    assert "delete_file" not in [t["name"] for t in responses[1]["result"]["tools"]]
    assert responses[2]["result"]["isError"] is True
    assert "rule no-deletes" in responses[2]["result"]["content"][0]["text"]
    assert responses[3]["result"]["isError"] is False

    received = [json.loads(x) for x in (tmp_path / "received.jsonl").read_bytes().splitlines()]
    assert [m["id"] for m in received] == [0, 1, 3]

    audit = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()]
    # The invalid line may be logged before or after the server answers call 3.
    assert sorted(r["event"] for r in audit) == [
        "invalid_message",
        "tool_call",
        "tool_call",
        "tool_result",
    ]
    audit = [r for r in audit if r["event"] != "invalid_message"]
    assert audit[0]["decision"] == "deny"
    assert audit[1]["arguments"] == {"token": "[REDACTED]"}
    assert b"blocked delete_file (rule no-deletes)" in stderr


def test_run_dry_run_forwards_denied_calls(
    policy_file: Path, env: dict[str, str], tmp_path: Path
) -> None:
    proc = start(policy_file, env, "--dry-run")
    stdout, _ = proc.communicate(call(1, "delete_file", {"path": "a"}), timeout=60)
    assert proc.returncode == 0
    assert json.loads(stdout)["result"]["isError"] is False
    audit = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()]
    assert audit[0]["decision"] == "would_deny"


def test_run_returns_server_exit_code(policy_file: Path, env: dict[str, str]) -> None:
    proc = start(policy_file, {**env, "FAKE_SERVER_EXIT_CODE": "5"})
    proc.communicate(b"", timeout=60)
    assert proc.returncode == 5


def test_run_exits_when_server_crashes(policy_file: Path, env: dict[str, str]) -> None:
    proc = start(policy_file, env)
    assert proc.stdin is not None
    proc.stdin.write(call(1, "crash"))
    proc.stdin.flush()
    assert proc.wait(timeout=60) == 3  # stdin is still open: the proxy must not wait for it
    # communicate() closes stdin itself; closing it first fails on POSIX before Python 3.13.
    proc.communicate(timeout=10)


def test_run_with_invalid_policy_starts_nothing(tmp_path: Path, env: dict[str, str]) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\ndefault: deny\nrules:\n  - id: x\n    tools: [a]\n    action: nope\n"
    )
    proc = start(bad, env)
    stdout, stderr = proc.communicate(b"", timeout=60)
    assert proc.returncode == 2
    assert stdout == b""
    assert b"invalid policy" in stderr
    assert not (tmp_path / "server.pid").exists()


@pytest.mark.skipif(
    sys.platform == "win32", reason="SIGTERM cannot be delivered to a process on Windows"
)
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_run_terminates_server_on_signal(
    policy_file: Path, env: dict[str, str], tmp_path: Path, signum: int
) -> None:
    proc = start(policy_file, env)
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(line({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    proc.stdin.flush()
    assert json.loads(proc.stdout.readline())["id"] == 1
    server_pid = int((tmp_path / "server.pid").read_text())

    proc.send_signal(signum)
    assert proc.wait(timeout=30) == 128 + signal.SIGTERM  # the server was terminated with SIGTERM
    with pytest.raises(ProcessLookupError):
        os.kill(server_pid, 0)  # no orphan left behind
    proc.communicate(timeout=10)
