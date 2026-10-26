"""Condition operators, argument selection and safe path containment checks."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator, Sequence
from typing import Any

from mcp_leash.policy.models import Condition

IS_WINDOWS = sys.platform == "win32"


class IndeterminateError(Exception):
    """A condition could not be evaluated with certainty; the call must be denied."""


_MISSING = object()


def select(arguments: Any, arg: str) -> Any:
    """Return the value at dotted path ``arg``, or ``_MISSING``."""
    value = arguments
    for part in arg.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
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


def within(value: str, directories: Sequence[str]) -> bool:
    """True only if every interpretation of ``value`` is inside one of ``directories``.

    ``directories`` must already be canonical (see :func:`canonical_path`).
    """
    if "\x00" in value:
        raise IndeterminateError("path contains a NUL byte")
    return all(
        any(is_inside(canonical_path(candidate), d) for d in directories)
        for candidate in path_candidates(value)
    )


def _require_str(value: Any, condition: Condition) -> str:
    if not isinstance(value, str):
        raise IndeterminateError(
            f"argument {condition.arg!r} is {type(value).__name__}, "
            f"but {condition.operator!r} needs a string"
        )
    return value


def apply_operator(condition: Condition, value: Any) -> bool:
    """Apply the condition's operator to one argument value."""
    if condition.equals is not None:
        return json_equal(value, condition.equals)
    if condition.not_equals is not None:
        return not json_equal(value, condition.not_equals)
    if condition.in_ is not None:
        return any(json_equal(value, item) for item in condition.in_)
    if condition.starts_with is not None:
        return _require_str(value, condition).startswith(condition.starts_with)
    if condition.matches is not None:
        return re.search(condition.matches, _require_str(value, condition)) is not None
    if condition.within is not None:
        return within(_require_str(value, condition), condition.within)
    raise IndeterminateError(f"condition on {condition.arg!r} has no operator")


def condition_holds(condition: Condition, arguments: Any) -> bool:
    """Evaluate one ``when`` condition against the call's arguments.

    A missing argument makes the condition false. ``arg: '*'`` is true if any
    string value at any depth satisfies the operator.
    """
    if condition.arg == "*":
        return any(apply_operator(condition, value) for value in iter_strings(arguments))
    value = select(arguments, condition.arg)
    if value is _MISSING:
        return False
    return apply_operator(condition, value)
