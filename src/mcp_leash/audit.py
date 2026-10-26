"""JSON Lines audit log with redaction and truncation."""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, TextIO

REDACTED = "[REDACTED]"
TRUNCATED = "…[truncated]"
MAX_STRING_LENGTH = 2000


def redact(value: Any, keys: Iterable[str]) -> Any:
    """Return a copy of ``value`` with values under ``keys`` (any depth, any case) redacted."""
    lowered = {key.lower() for key in keys}
    return _redact(value, lowered)


def _redact(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: REDACTED if k.lower() in keys else _redact(v, keys) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, keys) for item in value]
    return value


def truncate(value: Any, limit: int = MAX_STRING_LENGTH) -> Any:
    """Return a copy of ``value`` with every string longer than ``limit`` cut and marked."""
    if isinstance(value, str):
        return value[:limit] + TRUNCATED if len(value) > limit else value
    if isinstance(value, dict):
        return {k: truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [truncate(item, limit) for item in value]
    return value


def timestamp() -> str:
    """UTC time with milliseconds, e.g. ``2026-10-26T14:43:05.120Z``."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class AuditLog:
    """Append-only JSONL audit writer. Every line is flushed as soon as it is written."""

    def __init__(self, stream: TextIO, redact_keys: Iterable[str], session: str | None = None):
        self._stream = stream
        self._redact_keys = list(redact_keys)
        self.session = session or secrets.token_hex(2)

    @classmethod
    def open(cls, path: str | None, redact_keys: Iterable[str]) -> AuditLog:
        """Open ``path`` for appending, creating parent directories; ``None`` logs to stderr."""
        if path is None:
            return cls(sys.stderr, redact_keys)
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        # newline="\n" keeps one record per line on Windows; backslashreplace turns a
        # lone surrogate into a JSON escape instead of failing the write.
        stream = open(path, "a", encoding="utf-8", errors="backslashreplace", newline="\n")  # noqa: SIM115
        return cls(stream, redact_keys)

    def close(self) -> None:
        """Close the log file (never closes stderr)."""
        if self._stream is not sys.stderr:
            self._stream.close()

    def write(self, event: str, **fields: Any) -> None:
        """Write one event. ``arguments`` is redacted and truncated before writing."""
        record: dict[str, Any] = {"ts": timestamp(), "event": event, "session": self.session}
        for key, value in fields.items():
            if key == "arguments":
                value = truncate(redact(value, self._redact_keys))
            record[key] = value
        self._stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._stream.flush()

    def tool_call(
        self,
        request_id: Any,
        tool: str,
        decision: str,
        rule: str,
        reason: str | None,
        arguments: Any,
    ) -> None:
        """Record the decision for one ``tools/call`` request."""
        self.write(
            "tool_call",
            request_id=request_id,
            tool=tool,
            decision=decision,
            rule=rule,
            reason=reason,
            arguments=arguments,
        )

    def tool_result(self, request_id: Any, tool: str, is_error: bool, latency_ms: int) -> None:
        """Record the server's answer to a forwarded call."""
        self.write(
            "tool_result",
            request_id=request_id,
            tool=tool,
            is_error=is_error,
            latency_ms=latency_ms,
        )

    def invalid_message(self, source: str, error: str) -> None:
        """Record a line that was dropped because it could not be parsed or was too large."""
        self.write("invalid_message", source=source, error=error)
