from __future__ import annotations

import json

import pytest

from mcp_leash.jsonrpc import (
    InvalidMessageError,
    LineFramer,
    Oversized,
    blocked_result,
    dump_line,
    parse_strict,
)


def test_parse_strict_accepts_valid_message() -> None:
    message = parse_strict(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert message == {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def test_parse_strict_keeps_escapes_equivalent_to_server() -> None:
    assert parse_strict(b'{"meth\\u006fd":"tools\\/call"}') == {"method": "tools/call"}


@pytest.mark.parametrize(
    ("line", "error"),
    [
        (b'{"method":"ping","method":"tools/call"}', "duplicate key 'method'"),
        (b'{"a":{"b":1,"b":2}}', "duplicate key 'b'"),
        (b'{"id":NaN}', "NaN"),
        (b'{"id":Infinity}', "Infinity"),
        (b'{"id":-Infinity}', "-Infinity"),
        (b"\xef\xbb\xbf{}", "invalid JSON"),
        (b'{"a":"\xff"}', "not valid UTF-8"),
        (b'{"a":1', "invalid JSON"),
        (b"", "invalid JSON"),
        (b"{} {}", "invalid JSON"),
    ],
)
def test_parse_strict_rejects(line: bytes, error: str) -> None:
    with pytest.raises(InvalidMessageError, match=error):
        parse_strict(line)


def test_parse_strict_rejects_deep_nesting() -> None:
    with pytest.raises(InvalidMessageError, match="JSON"):
        parse_strict(b"[" * 100_000 + b"]" * 100_000)


def test_dump_line_is_compact_and_newline_terminated() -> None:
    assert dump_line({"a": [1, "é"]}) == '{"a":[1,"é"]}\n'.encode()


def test_dump_line_keeps_lone_surrogates_as_escapes() -> None:
    line = dump_line(parse_strict(b'{"id":"\\ud800"}'))
    assert json.loads(line) == {"id": "\ud800"}


def test_blocked_result_shape() -> None:
    assert blocked_result("abc", "no") == {
        "jsonrpc": "2.0",
        "id": "abc",
        "result": {"isError": True, "content": [{"type": "text", "text": "no"}]},
    }


def test_framer_splits_lines_across_chunks() -> None:
    framer = LineFramer(100)
    assert framer.feed(b'{"a":') == []
    assert framer.feed(b"1}\n{}\n{") == [b'{"a":1}', b"{}"]
    assert framer.feed(b"}\r\n") == [b"{}\r"]
    assert framer.finish() == []


def test_framer_returns_unterminated_final_line() -> None:
    framer = LineFramer(100)
    assert framer.feed(b"{}") == []
    assert framer.finish() == [b"{}"]


def test_framer_drops_oversized_line_and_recovers() -> None:
    framer = LineFramer(10)
    assert framer.feed(b"0123456") == []
    assert framer.feed(b"789abc") == []
    assert framer.feed(b"def\n{}\n") == [Oversized(16), b"{}"]


def test_framer_oversized_in_single_chunk() -> None:
    framer = LineFramer(4)
    assert framer.feed(b"12345\n1234\n") == [Oversized(5), b"1234"]


def test_framer_oversized_at_end_of_stream() -> None:
    framer = LineFramer(4)
    assert framer.feed(b"123456") == []
    assert framer.finish() == [Oversized(6)]
