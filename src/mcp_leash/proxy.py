"""Async stdio relay between an MCP client and the real server, and the child process lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import queue
import shutil
import signal
import sys
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any, Literal, Protocol

from mcp_leash.audit import AuditLog
from mcp_leash.jsonrpc import (
    DEFAULT_MAX_LINE_BYTES,
    InvalidMessageError,
    LineFramer,
    Oversized,
    blocked_result,
    dump_line,
    parse_strict,
)
from mcp_leash.policy import Decision, Policy, always_denied, evaluate

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


def _id_key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True)


def _blocked_text(decision: Decision) -> str:
    reason = decision.reason
    if reason is None:
        reason = "No rule allows this call." if decision.rule == "default" else "Denied by policy."
    return f"Blocked by mcp-leash (rule {decision.rule}): {reason}"


class Relay:
    """Decide what happens to every line passing through the proxy.

    Only ``tools/call`` requests from the client are evaluated. Everything else
    is forwarded unchanged, except that ``tools/list`` responses lose the tools
    a rule always denies when ``hide_denied_tools`` is on.
    """

    def __init__(
        self,
        policy: Policy,
        audit: AuditLog | None = None,
        *,
        dry_run: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._dry_run = dry_run
        self._clock = clock
        self._pending_calls: dict[str, tuple[Any, str, float]] = {}
        self._pending_lists: set[str] = set()

    def from_client(self, line: bytes) -> list[Outgoing]:
        """Handle one line from the client and return what to send where."""
        if not line.strip():
            return []
        try:
            message = parse_strict(line)
        except InvalidMessageError as exc:
            self._invalid("client", str(exc))
            return []
        forward: list[Outgoing] = [("server", line + b"\n")]
        if isinstance(message, list):
            if any(isinstance(m, dict) and m.get("method") == "tools/call" for m in message):
                self._invalid("client", "a JSON-RPC batch containing tools/call is not supported")
                return []
            return forward
        if not isinstance(message, dict):
            return forward
        method = message.get("method")
        if method == "tools/call":
            return self._tool_call(message, line)
        if method == "tools/list" and "id" in message:
            self._pending_lists.add(_id_key(message["id"]))
        elif method == "notifications/cancelled":
            params = message.get("params")
            if isinstance(params, dict) and "requestId" in params:
                self._pending_calls.pop(_id_key(params["requestId"]), None)
        return forward

    def from_server(self, line: bytes) -> list[Outgoing]:
        """Handle one line from the server and return what to send where."""
        forward: list[Outgoing] = [("client", line + b"\n")]
        if not self._pending_calls and not self._pending_lists:
            return forward
        try:
            message = parse_strict(line)
        except InvalidMessageError:
            return forward
        if not isinstance(message, dict) or "method" in message or "id" not in message:
            return forward
        key = _id_key(message["id"])
        if key in self._pending_calls:
            request_id, tool, started = self._pending_calls.pop(key)
            result = message.get("result")
            is_error = "error" in message or (
                isinstance(result, dict) and result.get("isError") is True
            )
            latency_ms = round((self._clock() - started) * 1000)
            self._record(lambda a: a.tool_result(request_id, tool, is_error, latency_ms))
        elif key in self._pending_lists:
            self._pending_lists.discard(key)
            filtered = self._hide_denied_tools(message)
            if filtered is not None:
                return [("client", dump_line(filtered))]
        return forward

    def oversized(self, source: Target, size: int) -> None:
        """Record a line that was dropped for exceeding the size limit."""
        self._invalid(source, f"{size}-byte line exceeds the size limit")

    def _tool_call(self, message: dict[str, Any], line: bytes) -> list[Outgoing]:
        request_id = message.get("id")
        params = message.get("params")
        tool = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        if arguments is None:
            arguments = {}
        if isinstance(tool, str) and isinstance(arguments, dict):
            decision = evaluate(self._policy, tool, arguments)
        else:
            decision = Decision("deny", "invalid-request", "The tools/call request is malformed.")
            tool = tool if isinstance(tool, str) else ""
            arguments = params
        outcome = "would_deny" if self._dry_run and not decision.allowed else decision.action

        recorded = self._record(
            lambda a: a.tool_call(
                request_id, tool, outcome, decision.rule, decision.reason, arguments
            )
        )
        if not recorded and outcome == "allow":
            decision = Decision("deny", decision.rule, "The audit log could not be written.")
            outcome = "deny"

        if outcome == "deny":
            logger.info("blocked %s (rule %s)", tool, decision.rule)
            if "id" not in message:
                return []  # a notification gets no response
            return [("client", dump_line(blocked_result(request_id, _blocked_text(decision))))]
        if outcome == "would_deny":
            logger.info("would block %s (rule %s); forwarding in dry-run mode", tool, decision.rule)
        if "id" in message:
            self._pending_calls[_id_key(request_id)] = (request_id, tool, self._clock())
        return [("server", line + b"\n")]

    def _hide_denied_tools(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not self._policy.hide_denied_tools or self._dry_run:
            return None
        result = message.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return None
        tools = result["tools"]
        kept = [
            t
            for t in tools
            if not (
                isinstance(t, dict)
                and isinstance(t.get("name"), str)
                and always_denied(self._policy, t["name"])
            )
        ]
        if len(kept) == len(tools):
            return None
        return {**message, "result": {**result, "tools": kept}}

    def _invalid(self, source: Target, error: str) -> None:
        logger.warning("dropped message from %s: %s", source, error)
        self._record(lambda a: a.invalid_message(source, error))

    def _record(self, write: Callable[[AuditLog], None]) -> bool:
        if self._audit is None:
            return True
        try:
            write(self._audit)
        except (OSError, ValueError) as exc:
            logger.error("could not write the audit log: %s", exc)
            return False
        return True


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
