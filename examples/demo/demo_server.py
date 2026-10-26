"""A tiny stdio MCP server for the demo: read, list and delete real files.

Usage: python demo_server.py

Paths are resolved against the current directory. delete_file really deletes,
which is the point of putting mcp-leash in front of it.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

TOOLS = [
    {"name": name, "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
    for name in ("read_file", "list_directory", "delete_file")
]


def run_tool(name: str, path: str) -> str:
    if name == "read_file":
        with open(path, encoding="utf-8") as f:
            return f.read()
    if name == "list_directory":
        return "\n".join(sorted(os.listdir(path)))
    if name == "delete_file":
        os.remove(path)
        return f"Deleted {path}"
    raise ValueError(f"unknown tool {name}")


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    if "id" not in message:
        return None
    method = message.get("method")
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-files", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params") or {}
        try:
            text = run_tool(params.get("name", ""), (params.get("arguments") or {}).get("path", ""))
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        except (OSError, ValueError) as exc:
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    else:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": "not found"},
        }
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def main() -> None:
    for line in sys.stdin.buffer:
        reply = handle(json.loads(line))
        if reply is not None:
            sys.stdout.buffer.write(json.dumps(reply).encode() + b"\n")
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
