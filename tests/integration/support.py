"""Helpers for driving a proxy in-process against the fake MCP server."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from mcp_leash.policy import Policy, parse_policy

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_server.py"
TIMEOUT = 10.0


class MemoryClient:
    """An in-memory MCP client channel for driving a :class:`Proxy` in-process."""

    def __init__(self) -> None:
        self._inbox: asyncio.Queue[bytes] = asyncio.Queue()
        self._outbox: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = False

    async def read(self) -> bytes:
        return await self._inbox.get()

    def write(self, data: bytes) -> None:
        self._outbox.put_nowait(data)

    async def aclose(self) -> None:
        self.closed = True

    def send_raw(self, data: bytes) -> None:
        self._inbox.put_nowait(data)

    def send(self, message: Any) -> None:
        self.send_raw(json.dumps(message).encode() + b"\n")

    def close_stdin(self) -> None:
        self._inbox.put_nowait(b"")

    async def receive_raw(self) -> bytes:
        return await asyncio.wait_for(self._outbox.get(), TIMEOUT)

    async def receive(self) -> Any:
        return json.loads(await self.receive_raw())

    def pending(self) -> int:
        return self._outbox.qsize()


class Session:
    """A running proxy in front of the fake server."""

    def __init__(self, client: MemoryClient, task: asyncio.Task[int], record: Path) -> None:
        self.client = client
        self.task = task
        self.record = record

    def received_by_server(self) -> list[Any]:
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_bytes().splitlines() if line]

    async def call(self, request_id: Any, tool: str, arguments: Any = None) -> Any:
        params: dict[str, Any] = {"name": tool}
        if arguments is not None:
            params["arguments"] = arguments
        self.client.send(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}
        )
        return await self.client.receive()

    async def finish(self) -> int:
        self.client.close_stdin()
        return await asyncio.wait_for(self.task, TIMEOUT)


def allow_all() -> Policy:
    """A policy that allows every call, for pass-through tests."""
    return parse_policy("version: 1\ndefault: allow\n", env={})
