"""A tiny stdio MCP server used by the integration tests.

Every raw line it receives is appended to the file named by ``FAKE_SERVER_RECORD``
(when set), so tests can prove that a blocked call never reached the server. Its process id
is written to ``FAKE_SERVER_PID_FILE`` (when set).

Tools: ``read_file``, ``write_file``, ``delete_file`` and ``echo`` echo their
arguments; ``fail`` returns ``isError``; ``big`` returns ``size`` characters;
``crash`` exits immediately with code 3.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

TOOLS = ["read_file", "write_file", "delete_file", "echo", "fail", "big", "crash"]


def send(message: dict[str, Any]) -> None:
    sys.stdout.buffer.write(json.dumps(message).encode() + b"\n")
    sys.stdout.buffer.flush()


def record(line: bytes) -> None:
    path = os.environ.get("FAKE_SERVER_RECORD")
    if path:
        with open(path, "ab") as f:
            f.write(line if line.endswith(b"\n") else line + b"\n")


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    if "id" not in message or method is None:
        return
    request_id = message["id"]
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS],
        }
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "crash":
            sys.exit(3)
        if name == "big":
            text = "x" * int(arguments.get("size", 0))
        else:
            text = json.dumps({"tool": name, "arguments": arguments})
        result = {"content": [{"type": "text", "text": text}], "isError": name == "fail"}
    else:
        send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": method}})
        return
    send({"jsonrpc": "2.0", "id": request_id, "result": result})


def main() -> None:
    pid_file = os.environ.get("FAKE_SERVER_PID_FILE")
    if pid_file:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    for line in sys.stdin.buffer:
        record(line)
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if isinstance(message, dict):
            handle(message)
    sys.exit(int(os.environ.get("FAKE_SERVER_EXIT_CODE", "0")))


if __name__ == "__main__":
    main()
