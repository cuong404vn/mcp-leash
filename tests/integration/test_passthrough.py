from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from mcp_leash.proxy import Proxy, Relay, exit_code_from, resolve_command
from tests.integration.support import FAKE_SERVER, MemoryClient, allow_all

StartSession = Callable[..., Any]


async def test_messages_pass_through_byte_for_byte(start_session: StartSession) -> None:
    session = await start_session()
    raw = b'{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"x": "\\u00e9"}}\n'
    session.client.send_raw(raw)
    response = await session.client.receive()
    assert response["result"]["serverInfo"]["name"] == "fake"

    raw_notification = b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    session.client.send_raw(raw_notification)
    assert await session.finish() == 0
    assert session.record.read_bytes() == raw + raw_notification


async def test_server_response_is_returned_unchanged(start_session: StartSession) -> None:
    session = await start_session()
    session.client.send({"jsonrpc": "2.0", "id": "x-1", "method": "tools/list"})
    raw = await session.client.receive_raw()
    names = [tool["name"] for tool in json.loads(raw)["result"]["tools"]]
    assert "delete_file" in names
    assert raw.endswith(b"\n")
    assert await session.finish() == 0


async def test_request_ids_of_any_type_are_preserved(start_session: StartSession) -> None:
    session = await start_session()
    for request_id in [0, "abc", 12345678901234567890, None, 1.5]:
        result = await session.call(request_id, "echo", {"v": 1})
        assert result["id"] == request_id
    await session.finish()


async def test_invalid_lines_are_dropped(start_session: StartSession) -> None:
    session = await start_session()
    session.client.send_raw(b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}\n')
    session.client.send_raw(b"not json\n")
    session.client.send_raw(b"\n")
    session.client.send_raw(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    response = await session.client.receive()
    assert response["id"] == 2
    await session.finish()
    assert [m["id"] for m in session.received_by_server()] == [2]


async def test_message_over_one_megabyte(start_session: StartSession) -> None:
    session = await start_session()
    payload = "y" * (2 * 1024 * 1024)
    result = await session.call(1, "echo", {"data": payload})
    assert json.loads(result["result"]["content"][0]["text"])["arguments"]["data"] == payload
    big = await session.call(2, "big", {"size": 3 * 1024 * 1024})
    assert len(big["result"]["content"][0]["text"]) == 3 * 1024 * 1024
    await session.finish()


async def test_oversized_line_is_dropped(start_session: StartSession) -> None:
    session = await start_session(max_line_bytes=1024)
    session.client.send(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": "z" * 2000}}
    )
    session.client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert (await session.client.receive())["id"] == 2
    await session.finish()
    assert [m["id"] for m in session.received_by_server()] == [2]


async def test_client_closing_stdin_ends_server(start_session: StartSession) -> None:
    session = await start_session()
    assert await session.finish() == 0


async def test_exit_code_of_server_is_returned(
    start_session: StartSession, monkeypatch: Any
) -> None:
    monkeypatch.setenv("FAKE_SERVER_EXIT_CODE", "7")
    session = await start_session()
    assert await session.finish() == 7


async def test_server_crash_ends_proxy_with_its_code(start_session: StartSession) -> None:
    session = await start_session()
    session.client.send(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "crash"}}
    )
    assert await session.task == 3
    assert session.client.closed


async def test_request_stop_terminates_server(fake_server_command: list[str]) -> None:
    client = MemoryClient()
    proxy = Proxy(fake_server_command, Relay(allow_all()))
    task = asyncio.create_task(proxy.run(client))
    client.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    await client.receive()
    proxy.request_stop()
    code = await asyncio.wait_for(task, 10)
    assert code != 0


async def test_missing_server_command_exits_127() -> None:
    client = MemoryClient()
    proxy = Proxy(["definitely-not-a-real-command-mcp-leash"], Relay(allow_all()))
    assert await proxy.run(client) == 127


def test_resolve_command_finds_executable_on_path() -> None:
    resolved = resolve_command(["python", str(FAKE_SERVER)])
    assert resolved[1] == str(FAKE_SERVER)
    assert resolved[0].lower().endswith(("python", "python.exe", "python3"))


def test_exit_code_mapping() -> None:
    assert exit_code_from(0) == 0
    assert exit_code_from(3) == 3
    assert exit_code_from(-15) == 143
