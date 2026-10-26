from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.proxy import Proxy, Relay
from tests.integration.support import FAKE_SERVER, TIMEOUT, MemoryClient, Session


@pytest.fixture
def fake_server_command() -> list[str]:
    return [sys.executable, str(FAKE_SERVER)]


@pytest.fixture
async def start_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_server_command: list[str]
) -> AsyncIterator[Callable[..., Any]]:
    record = tmp_path / "server-received.jsonl"
    monkeypatch.setenv("FAKE_SERVER_RECORD", str(record))
    sessions: list[Session] = []

    async def start(relay: Relay | None = None, **proxy_kwargs: Any) -> Session:
        client = MemoryClient()
        proxy = Proxy(fake_server_command, relay or Relay(), **proxy_kwargs)
        session = Session(client, asyncio.create_task(proxy.run(client)), record)
        sessions.append(session)
        return session

    yield start
    for session in sessions:
        if not session.task.done():
            session.client.close_stdin()
            await asyncio.wait_for(session.task, TIMEOUT)
