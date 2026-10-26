"""Async stdio relay between an MCP client and the real server, and the child process lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import queue
import shutil
import signal
import sys
import threading
from collections.abc import Callable, Sequence
from typing import Literal, Protocol

from mcp_leash.jsonrpc import (
    DEFAULT_MAX_LINE_BYTES,
    InvalidMessageError,
    LineFramer,
    Oversized,
    parse_strict,
)

logger = logging.getLogger("mcp_leash")

READ_CHUNK = 64 * 1024
TERMINATE_GRACE_SECONDS = 5.0
DRAIN_SECONDS = 2.0

Target = Literal["client", "server"]
Outgoing = tuple[Target, bytes]


class ClientChannel(Protocol):
    """The MCP client's side of the connection."""

    async def read(self) -> bytes:
        """Return the next chunk of bytes from the client, or ``b""`` at end of stream."""
        ...

    def write(self, data: bytes) -> None:
        """Queue bytes for the client. Must not block."""
        ...

    async def aclose(self) -> None:
        """Flush queued writes and release the channel."""
        ...


class Relay:
    """Decide what happens to every line passing through the proxy."""

    def from_client(self, line: bytes) -> list[Outgoing]:
        """Handle one line from the client and return what to send where."""
        if not line.strip():
            return []
        try:
            parse_strict(line)
        except InvalidMessageError as exc:
            logger.warning("dropped invalid message from client: %s", exc)
            return []
        return [("server", line + b"\n")]

    def from_server(self, line: bytes) -> list[Outgoing]:
        """Handle one line from the server and return what to send where."""
        return [("client", line + b"\n")]

    def oversized(self, source: Target, size: int) -> None:
        """Record a line that was dropped for exceeding the size limit."""
        logger.warning("dropped %d-byte message from %s: line size limit exceeded", size, source)


class StdioClient:
    """Client channel on this process's real stdin and stdout.

    Reads and writes run in daemon threads because asyncio cannot read an
    inherited stdin pipe on Windows. Reads apply backpressure: the reader
    thread waits until the event loop has taken each chunk.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        on_broken: Callable[[], None],
        stdin_fd: int | None = None,
        stdout_fd: int | None = None,
    ) -> None:
        self._loop = loop
        self._on_broken = on_broken
        self._in_fd = sys.stdin.fileno() if stdin_fd is None else stdin_fd
        self._out_fd = sys.stdout.fileno() if stdout_fd is None else stdout_fd
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue(maxsize=8)
        self._outgoing: queue.Queue[bytes | None] = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, name="stdin-reader", daemon=True)
        self._writer = threading.Thread(target=self._write_loop, name="stdout-writer", daemon=True)
        self._reader.start()
        self._writer.start()

    async def read(self) -> bytes:
        return await self._incoming.get()

    def write(self, data: bytes) -> None:
        self._outgoing.put(data)

    async def aclose(self) -> None:
        self._outgoing.put(None)
        await asyncio.to_thread(self._writer.join, DRAIN_SECONDS)

    def _read_loop(self) -> None:
        while True:
            try:
                data = os.read(self._in_fd, READ_CHUNK)
            except OSError:
                data = b""
            try:
                asyncio.run_coroutine_threadsafe(self._incoming.put(data), self._loop).result()
            except RuntimeError:  # event loop already closed
                return
            if not data:
                return

    def _write_loop(self) -> None:
        while True:
            data = self._outgoing.get()
            if data is None:
                return
            view = memoryview(data)
            try:
                while view:
                    written = os.write(self._out_fd, view)
                    view = view[written:]
            except OSError:
                with contextlib.suppress(RuntimeError):
                    self._loop.call_soon_threadsafe(self._on_broken)
                return


def resolve_command(command: Sequence[str]) -> list[str]:
    """Resolve the server executable on PATH, including Windows ``.cmd`` shims such as ``npx``."""
    if not command:
        raise ValueError("no server command given")
    executable = shutil.which(command[0]) or command[0]
    return [executable, *command[1:]]


def exit_code_from(returncode: int) -> int:
    """Map a child's return code to our exit code (``128 + n`` when killed by signal ``n``)."""
    return 128 - returncode if returncode < 0 else returncode


class Proxy:
    """One proxied MCP stdio connection."""

    def __init__(
        self,
        command: Sequence[str],
        relay: Relay,
        *,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        self._command = list(command)
        self._relay = relay
        self._max_line_bytes = max_line_bytes
        self._stop = asyncio.Event()

    def request_stop(self) -> None:
        """Ask the proxy to terminate the server and exit (signal or lost client)."""
        self._stop.set()

    async def run(self, client: ClientChannel) -> int:
        """Start the server, relay until it exits, and return the exit code to use."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *resolve_command(self._command),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            logger.error("could not start server %r: %s", self._command[0], exc)
            await client.aclose()
            return 127
        assert proc.stdin is not None
        assert proc.stdout is not None

        server_task = asyncio.create_task(self._pump_server(proc.stdout, client))
        client_task = asyncio.create_task(self._pump_client(client, proc.stdin))
        wait_task = asyncio.create_task(proc.wait())
        stop_task = asyncio.create_task(self._stop.wait())

        await asyncio.wait({wait_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if not wait_task.done():
            await self._terminate(proc, wait_task)
        stop_task.cancel()
        returncode = await wait_task

        # Deliver whatever the server wrote before exiting, then stop reading the client.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(server_task), DRAIN_SECONDS)
        for task in (server_task, client_task):
            task.cancel()
        await asyncio.gather(server_task, client_task, return_exceptions=True)
        await client.aclose()
        return exit_code_from(returncode)

    async def _terminate(
        self, proc: asyncio.subprocess.Process, wait_task: asyncio.Task[int]
    ) -> None:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), TERMINATE_GRACE_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("server did not exit after terminate; killing it")
            with contextlib.suppress(ProcessLookupError):
                proc.kill()

    async def _pump_client(self, client: ClientChannel, server_in: asyncio.StreamWriter) -> None:
        framer = LineFramer(self._max_line_bytes)
        try:
            while True:
                chunk = await client.read()
                events = framer.feed(chunk) if chunk else framer.finish()
                for event in events:
                    if isinstance(event, Oversized):
                        self._relay.oversized("client", event.size)
                        continue
                    for target, data in self._relay.from_client(event):
                        if target == "server":
                            server_in.write(data)
                            await server_in.drain()
                        else:
                            client.write(data)
                if not chunk:
                    break
        except (BrokenPipeError, ConnectionResetError):
            logger.info("server closed its stdin")
        finally:
            # The client closed its stdin: pass the end of stream on to the server.
            with contextlib.suppress(OSError, RuntimeError):
                server_in.close()

    async def _pump_server(self, server_out: asyncio.StreamReader, client: ClientChannel) -> None:
        framer = LineFramer(self._max_line_bytes)
        while True:
            chunk = await server_out.read(READ_CHUNK)
            events = framer.feed(chunk) if chunk else framer.finish()
            for event in events:
                if isinstance(event, Oversized):
                    self._relay.oversized("server", event.size)
                    continue
                for target, data in self._relay.from_server(event):
                    if target == "client":
                        client.write(data)
            if not chunk:
                return


def install_signal_handlers(loop: asyncio.AbstractEventLoop, proxy: Proxy) -> None:
    """Terminate the server on SIGINT or SIGTERM (Ctrl+C and Ctrl+Break on Windows)."""
    if sys.platform == "win32":

        def handler(signum: int, frame: object) -> None:
            loop.call_soon_threadsafe(proxy.request_stop)

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGBREAK, handler)
    else:
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(signum, proxy.request_stop)


async def serve_stdio(proxy: Proxy) -> int:
    """Run ``proxy`` on this process's stdin and stdout and return the exit code."""
    loop = asyncio.get_running_loop()
    install_signal_handlers(loop, proxy)
    client = StdioClient(loop, on_broken=proxy.request_stop)
    return await proxy.run(client)
