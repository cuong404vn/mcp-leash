"""Load a policy file, expand variables and validate it."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Hashable, Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_leash.policy.matchers import IndeterminateError, canonical_path
from mcp_leash.policy.models import Condition, Policy

_VARIABLE = re.compile(r"\$\{([^}]*)\}?")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class PolicyError(Exception):
    """The policy file is missing or invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """A safe YAML loader that rejects duplicate mapping keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def expand_variables(value: str, lookup: Callable[[str], str | None]) -> str:
    """Replace each ``${NAME}``. Unknown or empty variables are errors, never ``""``."""

    def replace(match: re.Match[str]) -> str:
        if not match.group(0).endswith("}"):
            raise PolicyError(f"unterminated variable in {value!r}")
        name = match.group(1)
        if not _NAME.fullmatch(name):
            raise PolicyError(f"invalid variable name {name!r} in {value!r}")
        result = lookup(name)
        if not result:
            raise PolicyError(f"unknown or empty variable ${{{name}}} in {value!r}")
        return result

    return _VARIABLE.sub(replace, value)


def _expand_path(value: str, lookup: Callable[[str], str | None]) -> str:
    return os.path.expanduser(expand_variables(value, lookup))


def _expand_condition(condition: Condition, lookup: Callable[[str], str | None]) -> Condition:
    def expand(value: Any) -> Any:
        return expand_variables(value, lookup) if isinstance(value, str) else value

    update: dict[str, Any] = {}
    if condition.within is not None:
        try:
            update["within"] = [canonical_path(_expand_path(d, lookup)) for d in condition.within]
        except IndeterminateError as exc:
            raise PolicyError(str(exc)) from exc
    for name in ("equals", "not_equals", "starts_with"):
        if getattr(condition, name) is not None:
            update[name] = expand(getattr(condition, name))
    if condition.in_ is not None:
        update["in_"] = [expand(item) for item in condition.in_]
    return condition.model_copy(update=update)


def _format_validation_error(error: ValidationError) -> str:
    lines = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "policy"
        lines.append(f"{location}: {item['msg']}")
    return "\n".join(lines)


def parse_policy(
    text: str,
    *,
    project_dir: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Policy:
    """Parse and validate policy YAML, expanding ``${VAR}`` and ``~`` where allowed.

    ``${PROJECT_DIR}`` is ``project_dir`` (default: the current directory).
    Other variables come from ``env`` (default: the process environment).
    """
    environment = os.environ if env is None else env
    project = canonical_path(project_dir or os.getcwd())

    def lookup(name: str) -> str | None:
        return project if name == "PROJECT_DIR" else environment.get(name)

    try:
        data = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("the policy must be a YAML mapping")
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(exc)) from exc

    rules = [
        rule.model_copy(update={"when": [_expand_condition(c, lookup) for c in rule.when]})
        for rule in policy.rules
    ]
    audit = policy.audit
    if audit.path is not None:
        audit = audit.model_copy(update={"path": _expand_path(audit.path, lookup)})
    return policy.model_copy(update={"rules": rules, "audit": audit})


def load_policy(
    path: str | os.PathLike[str],
    *,
    project_dir: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Policy:
    """Read and validate the policy file at ``path``."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {os.fspath(path)!r}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file {os.fspath(path)!r} is not valid UTF-8") from exc
    return parse_policy(text, project_dir=project_dir, env=env)
