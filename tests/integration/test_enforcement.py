from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.audit import REDACTED, AuditLog
from mcp_leash.policy import Policy, parse_policy
from mcp_leash.proxy import Relay

StartSession = Callable[..., Any]

POLICY = """
version: 1
default: deny
hide_denied_tools: true
rules:
  - id: no-deletes
    tools: ['delete_*']
    action: deny
    reason: Deleting files is not permitted for agents.
  - id: echo-safe
    tools: ['echo', 'read_file', 'fail']
    action: allow
    when:
      - arg: mode
        not_equals: unsafe
  - id: crash-ok
    tools: ['crash']
    action: allow
"""


def policy(text: str = POLICY) -> Policy:
    return parse_policy(text, env={})


def audit_records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def blocked(response: dict[str, Any]) -> str:
    result = response["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert isinstance(text, str)
    return text


async def test_allowed_call_returns_server_result_unchanged(start_session: StartSession) -> None:
    session = await start_session(Relay(policy()))
    session.client.send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"mode": "safe"}},
        }
    )
    raw = await session.client.receive_raw()
    # The fake server writes json.dumps() output with ", " separators; re-serializing would change them.
    assert raw.startswith(b'{"jsonrpc": "2.0", "id": 1, "result": ')
    assert json.loads(json.loads(raw)["result"]["content"][0]["text"])["arguments"] == {
        "mode": "safe"
    }
    await session.finish()


async def test_denied_call_never_reaches_server(start_session: StartSession) -> None:
    session = await start_session(Relay(policy()))
    response = await session.call(5, "delete_file", {"path": "/tmp/a"})
    assert response["id"] == 5
    assert blocked(response) == (
        "Blocked by mcp-leash (rule no-deletes): Deleting files is not permitted for agents."
    )
    default_denied = await session.call("x", "write_file", {"path": "/tmp/a"})
    assert (
        blocked(default_denied) == "Blocked by mcp-leash (rule default): No rule allows this call."
    )
    conditional = await session.call(6, "echo", {"mode": "unsafe"})
    assert "rule default" in blocked(conditional)
    await session.finish()
    assert session.received_by_server() == []


async def test_denied_notification_is_dropped_silently(start_session: StartSession) -> None:
    session = await start_session(Relay(policy()))
    session.client.send(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_file"}}
    )
    session.client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert (await session.client.receive())["id"] == 2
    await session.finish()
    assert [m.get("method") for m in session.received_by_server()] == ["tools/list"]


@pytest.mark.parametrize(
    "params",
    [
        None,
        "delete_file",
        {"arguments": {}},
        {"name": 5},
        {"name": "echo", "arguments": ["mode", "safe"]},
        {"name": "echo", "arguments": "mode=safe"},
    ],
)
async def test_malformed_tool_call_is_blocked(start_session: StartSession, params: Any) -> None:
    session = await start_session(Relay(policy()))
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
    if params is not None:
        message["params"] = params
    session.client.send(message)
    assert "rule invalid-request" in blocked(await session.client.receive())
    await session.finish()
    assert session.received_by_server() == []


async def test_null_arguments_are_treated_as_empty(start_session: StartSession) -> None:
    session = await start_session(Relay(policy("version: 1\ndefault: allow\n")))
    response = await session.call(1, "echo", None)
    assert response["result"]["isError"] is False
    session.client.send(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": None},
        }
    )
    assert (await session.client.receive())["result"]["isError"] is False
    await session.finish()


async def test_dry_run_forwards_and_logs_would_deny(start_session: StartSession) -> None:
    stream = io.StringIO()
    session = await start_session(Relay(policy(), AuditLog(stream, ["token"]), dry_run=True))
    response = await session.call(1, "delete_file", {"path": "a"})
    assert json.loads(response["result"]["content"][0]["text"])["tool"] == "delete_file"
    tools = await _list_tools(session)
    assert "delete_file" in tools  # dry-run never changes traffic
    await session.finish()
    assert [
        m["params"]["name"] for m in session.received_by_server() if m["method"] == "tools/call"
    ] == ["delete_file"]
    call = audit_records(stream)[0]
    assert (call["decision"], call["rule"]) == ("would_deny", "no-deletes")


async def _list_tools(session: Any) -> list[str]:
    session.client.send({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
    response = await session.client.receive()
    return [tool["name"] for tool in response["result"]["tools"]]


async def test_hide_denied_tools_filters_tools_list(start_session: StartSession) -> None:
    session = await start_session(Relay(policy()))
    tools = await _list_tools(session)
    assert "delete_file" not in tools
    assert {"echo", "read_file", "write_file", "crash"} <= set(tools)
    await session.finish()


async def test_tools_list_unchanged_without_hide_denied_tools(start_session: StartSession) -> None:
    session = await start_session(Relay(policy(POLICY.replace("hide_denied_tools: true", ""))))
    assert "delete_file" in await _list_tools(session)
    await session.finish()


async def test_audit_log_records_calls_results_and_invalid_lines(
    start_session: StartSession,
) -> None:
    stream = io.StringIO()
    session = await start_session(Relay(policy(), AuditLog(stream, ["token"], session="b1f6")))
    await session.call(1, "echo", {"mode": "safe", "token": "s3cret"})
    await session.call(2, "fail", {"mode": "safe"})
    await session.call(3, "delete_file", {"path": "/x"})
    session.client.send_raw(b'{"id":4,"id":5}\n')
    await session.finish()
    records = audit_records(stream)
    assert [(r["event"], r.get("request_id")) for r in records] == [
        ("tool_call", 1),
        ("tool_result", 1),
        ("tool_call", 2),
        ("tool_result", 2),
        ("tool_call", 3),
        ("invalid_message", None),
    ]
    assert records[0]["decision"] == "allow"
    assert records[0]["rule"] == "echo-safe"
    assert records[0]["arguments"] == {"mode": "safe", "token": REDACTED}
    assert records[1]["is_error"] is False
    assert isinstance(records[1]["latency_ms"], int)
    assert records[3]["is_error"] is True
    assert (records[4]["decision"], records[4]["reason"]) == (
        "deny",
        "Deleting files is not permitted for agents.",
    )
    assert "duplicate key" in records[5]["error"]
    assert {r["session"] for r in records} == {"b1f6"}


async def test_audit_failure_blocks_allowed_calls(start_session: StartSession) -> None:
    stream = io.StringIO()
    stream.close()
    session = await start_session(Relay(policy(), AuditLog(stream, [])))
    response = await session.call(1, "echo", {"mode": "safe"})
    assert (
        blocked(response)
        == "Blocked by mcp-leash (rule echo-safe): The audit log could not be written."
    )
    await session.finish()
    assert session.received_by_server() == []


async def test_batch_with_tool_call_is_dropped(start_session: StartSession) -> None:
    session = await start_session(Relay(policy()))
    session.client.send(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "delete_file"}},
        ]
    )
    session.client.send([{"jsonrpc": "2.0", "method": "notifications/initialized"}])
    session.client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert (await session.client.receive())["id"] == 3
    await session.finish()
    received = session.received_by_server()
    assert received[0] == [{"jsonrpc": "2.0", "method": "notifications/initialized"}]
    assert received[1]["id"] == 3


async def test_cancelled_request_is_forgotten(start_session: StartSession) -> None:
    stream = io.StringIO()
    session = await start_session(Relay(policy(), AuditLog(stream, [])))
    session.client.send(
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}}
    )
    await session.call(1, "echo", {"mode": "safe"})
    await session.finish()
    assert [r["event"] for r in audit_records(stream)] == ["tool_call", "tool_result"]


def test_relay_handles_server_messages_without_pending_requests() -> None:
    relay = Relay(policy())
    for line in [b"not json", b'{"jsonrpc":"2.0","method":"notifications/x"}', b"[1,2]"]:
        assert relay.from_server(line) == [("client", line + b"\n")]


def test_relay_reports_oversized_lines(tmp_path: Path) -> None:
    stream = io.StringIO()
    Relay(policy(), AuditLog(stream, [])).oversized("server", 123)
    record = audit_records(stream)[0]
    assert (record["event"], record["source"]) == ("invalid_message", "server")
    assert "123-byte" in record["error"]


def test_relay_forwards_non_object_json() -> None:
    relay = Relay(policy())
    assert relay.from_client(b"42") == [("server", b"42\n")]
