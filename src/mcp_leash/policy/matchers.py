"""Condition operators, argument selection and safe path containment checks."""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from collections.abc import Iterator, Sequence
from typing import Any

from mcp_leash.policy.models import Condition

IS_WINDOWS = sys.platform == "win32"


class IndeterminateError(Exception):
    """A condition could not be evaluated with certainty; the call must be denied."""


_MISSING = object()
_INDEX = re.compile(r"0|[1-9][0-9]*")


def select(arguments: Any, arg: str) -> Any:
    """Return the value at dotted path ``arg``, or ``_MISSING``.

    A part selects a key of an object, or, written as a number such as the
    ``0`` in ``command.0``, an item of a list. An index past the end of the
    list is missing, like a key that is not there.
    """
    value = arguments
    for part in arg.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and _INDEX.fullmatch(part) and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


def iter_strings(value: Any) -> Iterator[str]:
    """Yield every string value at any depth inside objects and lists (not keys)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def json_equal(a: Any, b: Any) -> bool:
    """Compare two JSON scalars without Python's ``True == 1`` coercion."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def canonical_path(path: str) -> str:
    """Resolve ``..`` segments and symlinks, then normalize case on Windows only."""
    try:
        resolved = os.path.realpath(os.path.abspath(path))
    except (OSError, ValueError) as exc:
        raise IndeterminateError(f"cannot resolve path {path[:200]!r}: {exc}") from exc
    if IS_WINDOWS:
        if resolved.startswith("\\\\?\\UNC\\"):
            resolved = "\\\\" + resolved[8:]
        elif resolved.startswith("\\\\?\\"):
            resolved = resolved[4:]
        resolved = os.path.normcase(resolved)
    return resolved


def fold(path: str) -> str:
    """Unicode canonical caseless form: names a case-insensitive file system treats as one."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", path).casefold())


def is_inside(path: str, directory: str) -> bool:
    """True if canonical ``path`` equals canonical ``directory`` or lies below it."""
    if path == directory:
        return True
    prefix = directory if directory.endswith(os.sep) else directory + os.sep
    return path.startswith(prefix)


def path_candidates(value: str) -> list[str]:
    """Every way a server might read ``value``: literally, and with ``~`` expanded."""
    candidates = [value]
    if value.startswith("~"):
        expanded = os.path.expanduser(value)
        if expanded != value:
            candidates.append(expanded)
    return candidates


def within(value: str, directories: Sequence[str], *, require_all: bool = True) -> bool:
    """True if ``value`` is inside one of ``directories``.

    With ``require_all`` every interpretation of ``value`` (see
    :func:`path_candidates`) must be inside; without it one is enough.
    ``directories`` must already be canonical (see :func:`canonical_path`).

    Outside Windows the file system may or may not ignore case and Unicode
    normalization (macOS and FAT drives do, most Linux file systems do not),
    so names that differ only in those ways are another two readings. Exact
    comparison holds under both, so it is what ``require_all`` uses; without
    it names are compared folded (see :func:`fold`).
    """
    if "\x00" in value:
        raise IndeterminateError("path contains a NUL byte")
    folded = not require_all and not IS_WINDOWS
    if folded:
        directories = [fold(d) for d in directories]
    readings = (
        any(is_inside(fold(path) if folded else path, d) for d in directories)
        for path in map(canonical_path, path_candidates(value))
    )
    return all(readings) if require_all else any(readings)


def _strings(value: Any, condition: Condition) -> list[str]:
    """What a string operator checks: a single string, or every item of a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return value
        kind = "a list with non-string items"
    else:
        kind = type(value).__name__
    noun = "path" if condition.within is not None else "string"
    raise IndeterminateError(
        f"argument {condition.arg!r} is {kind}, "
        f"but {condition.operator!r} needs a {noun} or a list of {noun}s"
    )


def apply_operator(condition: Condition, value: Any, *, require_all: bool = True) -> bool:
    """Apply the condition's operator to one argument value.

    ``starts_with``, ``ends_with``, ``matches`` and ``within`` also take a list of strings
    and check each item; ``require_all`` decides how the results combine
    (see :func:`condition_holds`).
    """
    if condition.equals is not None:
        return json_equal(value, condition.equals)
    if condition.not_equals is not None:
        return not json_equal(value, condition.not_equals)
    if condition.in_ is not None:
        return any(json_equal(value, item) for item in condition.in_)
    strings = _strings(value, condition)
    results: Iterator[bool]
    if (prefix := condition.starts_with) is not None:
        results = (s.startswith(prefix) for s in strings)
    elif (suffix := condition.ends_with) is not None:
        results = (s.endswith(suffix) for s in strings)
    elif (pattern := condition.matches) is not None:
        results = (re.search(pattern, s) is not None for s in strings)
    elif (directories := condition.within) is not None:
        results = (within(s, directories, require_all=require_all) for s in strings)
    else:
        raise IndeterminateError(f"condition on {condition.arg!r} has no operator")
    return bool(strings) and (all(results) if require_all else any(results))


def condition_holds(condition: Condition, arguments: Any, *, require_all: bool = True) -> bool:
    """Evaluate one ``when`` condition against the call's arguments.

    A missing argument, or an empty list of strings, makes the condition false.
    ``arg: '*'`` is true if any string value at any depth satisfies the operator.

    A value can have several readings: each item of a list of strings, and for
    ``within`` a path starting with ``~`` both expanded and literally, and
    outside Windows a name with or without regard to case. With
    ``require_all`` (allow rules) every reading must pass; without it (deny
    rules) one is enough, so an ambiguous value always leans toward deny.
    """
    if condition.arg == "*":
        return any(
            apply_operator(condition, value, require_all=require_all)
            for value in iter_strings(arguments)
        )
    value = select(arguments, condition.arg)
    if value is _MISSING:
        return False
    return apply_operator(condition, value, require_all=require_all)
