"""Load a policy file, expand variables and validate it."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Hashable, Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from mcp_leash.policy.matchers import IndeterminateError, canonical_path
from mcp_leash.policy.models import Condition, Policy

_VARIABLE = re.compile(r"\$\{([^}]*)\}?")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class PolicyError(Exception):
    """The policy file is missing or invalid."""


YamlPath = tuple[str | int, ...]
SourceLocations = dict[YamlPath, yaml.error.Mark]


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


def _expand_condition(
    condition: Condition,
    lookup: Callable[[str], str | None],
    locations: SourceLocations,
    path: YamlPath,
) -> Condition:
    def expand(value: Any) -> Any:
        return expand_variables(value, lookup) if isinstance(value, str) else value

    update: dict[str, Any] = {}
    if condition.within is not None:
        try:
            update["within"] = [canonical_path(_expand_path(d, lookup)) for d in condition.within]
        except IndeterminateError as exc:
            raise PolicyError(
                _format_located_error(str(exc), (*path, "within"), locations)
            ) from exc
        except PolicyError as exc:
            raise PolicyError(
                _format_located_error(str(exc), (*path, "within"), locations)
            ) from exc
    for name in ("equals", "not_equals", "starts_with"):
        if getattr(condition, name) is not None:
            try:
                update[name] = expand(getattr(condition, name))
            except PolicyError as exc:
                raise PolicyError(
                    _format_located_error(str(exc), (*path, name), locations)
                ) from exc
    if condition.in_ is not None:
        try:
            update["in_"] = [expand(item) for item in condition.in_]
        except PolicyError as exc:
            raise PolicyError(_format_located_error(str(exc), (*path, "in"), locations)) from exc
    return condition.model_copy(update=update)


def _source_locations(text: str) -> SourceLocations:
    """Map YAML paths to the source marks of their keys or values."""
    root = yaml.compose(text, Loader=_UniqueKeyLoader)
    locations: SourceLocations = {}

    active: set[int] = set()

    def visit(node: Node, path: YamlPath) -> None:
        if id(node) in active:
            return
        active.add(id(node))
        locations.setdefault(path, node.start_mark)
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    continue
                try:
                    key: str | int = key_node.value
                except (TypeError, ValueError):
                    continue
                child_path = (*path, key)
                locations[child_path] = key_node.start_mark
                visit(value_node, child_path)
        elif isinstance(node, SequenceNode):
            for index, item_node in enumerate(node.value):
                child_path = (*path, index)
                locations[child_path] = item_node.start_mark
                visit(item_node, child_path)
        active.remove(id(node))

    if root is not None:
        visit(root, ())
    return locations


def _format_located_error(message: str, path: YamlPath, locations: SourceLocations) -> str:
    """Prefix a policy error with the nearest available YAML source location."""
    for length in range(len(path), -1, -1):
        mark = locations.get(path[:length])
        if mark is not None:
            return f"line {mark.line + 1}, column {mark.column + 1}: {message}"
    return message


def read_yaml(text: str) -> dict[str, Any]:
    """Parse policy YAML into a mapping, rejecting duplicate keys, without validating it."""
    try:
        data = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("the policy must be a YAML mapping")
    return data


def _format_validation_error(error: ValidationError, locations: SourceLocations) -> str:
    lines = []
    for item in error.errors():
        path = tuple(part for part in item["loc"] if isinstance(part, (str, int)))
        location = ".".join(str(part) for part in path) or "policy"
        message = f"{location}: {item['msg']}"
        lines.append(_format_located_error(message, path, locations))
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

    data = read_yaml(text)
    locations = _source_locations(text)
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(exc, locations)) from exc

    rules = []
    for rule_index, rule in enumerate(policy.rules):
        conditions = []
        for condition_index, condition in enumerate(rule.when):
            path = ("rules", rule_index, "when", condition_index)
            conditions.append(_expand_condition(condition, lookup, locations, path))
        rules.append(rule.model_copy(update={"when": conditions}))
    audit = policy.audit
    if audit.path is not None:
        try:
            audit = audit.model_copy(update={"path": _expand_path(audit.path, lookup)})
        except PolicyError as exc:
            raise PolicyError(
                _format_located_error(str(exc), ("audit", "path"), locations)
            ) from exc
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
