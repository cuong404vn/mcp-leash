from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.audit import REDACTED, TRUNCATED, AuditLog, redact, timestamp, truncate

KEYS = ["token", "password", "api_key", "authorization", "secret"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"token": "abc", "path": "x"}, {"token": REDACTED, "path": "x"}),
        ({"TOKEN": "abc", "Api_Key": 1}, {"TOKEN": REDACTED, "Api_Key": REDACTED}),
        ({"a": {"b": [{"password": "p", "n": 1}]}}, {"a": {"b": [{"password": REDACTED, "n": 1}]}}),
        ({"secret": {"nested": "whole value"}}, {"secret": REDACTED}),
        ({"headers": {"Authorization": "Bearer x"}}, {"headers": {"Authorization": REDACTED}}),
        ({"tokens": "not exact"}, {"tokens": "not exact"}),
        (["token", {"token": None}], ["token", {"token": REDACTED}]),
        ("plain", "plain"),
    ],
)
def test_redact(value: Any, expected: Any) -> None:
    assert redact(value, KEYS) == expected


def test_redact_does_not_modify_input() -> None:
    original = {"a": {"token": "x"}}
    redact(original, KEYS)
    assert original == {"a": {"token": "x"}}


def test_truncate() -> None:
    long = "a" * 2001
    assert truncate(long) == "a" * 2000 + TRUNCATED
    assert truncate("a" * 2000) == "a" * 2000
    assert truncate({"x": [long, 5]}) == {"x": ["a" * 2000 + TRUNCATED, 5]}


def test_timestamp_format() -> None:
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", timestamp())


def test_tool_call_record_matches_documented_format() -> None:
    stream = io.StringIO()
    log = AuditLog(stream, KEYS, session="b1f6")
    log.tool_call(7, "delete_file", "deny", "no-deletes", "No.", {"path": "/p/a.txt", "token": "t"})
    record = json.loads(stream.getvalue())
    assert list(record) == [
        "ts",
        "event",
        "session",
        "request_id",
        "tool",
        "decision",
        "rule",
        "reason",
        "arguments",
    ]
    assert record["event"] == "tool_call"
    assert record["session"] == "b1f6"
    assert record["arguments"] == {"path": "/p/a.txt", "token": REDACTED}


def test_tool_result_and_invalid_message_records() -> None:
    stream = io.StringIO()
    log = AuditLog(stream, KEYS)
    log.tool_result("r1", "read_file", False, 12)
    log.invalid_message("client", "duplicate key 'id'")
    first, second = (json.loads(line) for line in stream.getvalue().splitlines())
    assert first["event"] == "tool_result"
    assert first["is_error"] is False
    assert first["latency_ms"] == 12
    assert len(first["session"]) == 4
    assert second == {**second, "event": "invalid_message", "source": "client"}


def test_open_appends_and_flushes_each_line(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir()
    path.write_bytes(b'{"existing":true}\n')
    log = AuditLog.open(str(path), KEYS)
    log.tool_result(1, "t", False, 1)
    assert path.read_bytes().count(b"\n") == 2  # flushed before close
    log.write("x", arguments={"v": "\ud800é"})
    log.close()
    lines = path.read_bytes().split(b"\n")
    assert b"\r" not in path.read_bytes()
    assert json.loads(lines[2])["arguments"] == {"v": "\ud800é"}


def test_open_creates_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "audit.jsonl"
    log = AuditLog.open(str(path), KEYS)
    log.close()
    assert path.exists()


def test_open_without_path_uses_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    log = AuditLog.open(None, KEYS)
    log.tool_result(1, "t", True, 3)
    log.close()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["is_error"] is True
