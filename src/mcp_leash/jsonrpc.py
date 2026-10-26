"""Strict JSON-RPC parsing, newline framing and response builders."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024
"""Largest accepted message line. MCP results can carry multi-megabyte base64 payloads."""


class InvalidMessageError(ValueError):
    """Raised when a line is not strictly valid JSON."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise InvalidMessageError(f"duplicate key {key[:64]!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise InvalidMessageError(f"non-standard JSON constant {name}")


def parse_strict(line: bytes) -> Any:
    """Parse one line as strict JSON.

    Rejects invalid UTF-8, a byte order mark, duplicate object keys and the
    non-standard ``NaN``/``Infinity`` constants, so that mcp-leash never reads a
    message differently from the server that receives it.
    """
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidMessageError("line is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except InvalidMessageError:
        raise
    except RecursionError as exc:
        raise InvalidMessageError("JSON nesting is too deep") from exc
    except ValueError as exc:
        raise InvalidMessageError(f"invalid JSON: {exc}") from exc


def dump_line(message: Any) -> bytes:
    """Serialize a message as one compact UTF-8 line ending in a newline."""
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    # Lone surrogates from \\uD800-style escapes become JSON escapes again.
    return text.encode("utf-8", "backslashreplace") + b"\n"


def blocked_result(request_id: Any, text: str) -> dict[str, Any]:
    """Build the successful response that tells the model its call was blocked."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"isError": True, "content": [{"type": "text", "text": text}]},
    }


@dataclass(frozen=True)
class Oversized:
    """A line that exceeded the size limit and was discarded."""

    size: int


class LineFramer:
    """Split a byte stream into newline-delimited lines, with a per-line size cap.

    Lines are returned without their trailing ``\\n``. A line longer than
    ``max_line_bytes`` is discarded up to its newline and reported as
    :class:`Oversized`, so it can never be half-forwarded.
    """

    def __init__(self, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES) -> None:
        self._max = max_line_bytes
        self._buf = bytearray()
        self._discarding = False
        self._discarded = 0

    def feed(self, chunk: bytes) -> list[bytes | Oversized]:
        """Add bytes and return every line completed by them."""
        out: list[bytes | Oversized] = []
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            if newline == -1:
                self._append(chunk[start:])
                return out
            self._append(chunk[start:newline])
            out.append(self._take())
            start = newline + 1

    def finish(self) -> list[bytes | Oversized]:
        """Return a final unterminated line at end of stream, if any."""
        if self._discarding or self._buf:
            return [self._take()]
        return []

    def _append(self, data: bytes) -> None:
        if self._discarding:
            self._discarded += len(data)
        elif len(self._buf) + len(data) > self._max:
            self._discarding = True
            self._discarded = len(self._buf) + len(data)
            self._buf.clear()
        else:
            self._buf += data

    def _take(self) -> bytes | Oversized:
        if self._discarding:
            size = self._discarded
            self._discarding = False
            self._discarded = 0
            return Oversized(size)
        line = bytes(self._buf)
        self._buf.clear()
        return line
