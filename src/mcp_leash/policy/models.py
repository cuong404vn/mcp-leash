"""Pydantic models for the policy YAML schema."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

Scalar = StrictBool | StrictInt | StrictFloat | StrictStr
Action = Literal["allow", "deny"]

OPERATORS = ("equals", "not_equals", "in", "starts_with", "istarts_with", "matches", "within")
DEFAULT_REDACT_KEYS = ["token", "password", "api_key", "authorization", "secret"]
RESERVED_RULE_IDS = ("default", "invalid-request")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Condition(_Strict):
    """One ``when`` condition: an argument selector and exactly one operator."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    arg: StrictStr = Field(min_length=1)
    equals: Scalar | None = None
    not_equals: Scalar | None = None
    in_: list[Scalar] | None = Field(default=None, alias="in")
    starts_with: StrictStr | None = None
    istarts_with: StrictStr | None = None
    matches: StrictStr | None = None
    within: list[StrictStr] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _exactly_one_operator(self) -> Condition:
        given = [name for name in OPERATORS if self.operand(name) is not None]
        if len(given) != 1:
            found = ", ".join(given) if given else "none"
            raise ValueError(
                f"condition on {self.arg!r} needs exactly one operator "
                f"({', '.join(OPERATORS)}); found {found}"
            )
        return self

    @field_validator("matches")
    @classmethod
    def _valid_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
        return value

    @field_validator("arg")
    @classmethod
    def _valid_arg(cls, value: str) -> str:
        if value != "*" and any(part == "" for part in value.split(".")):
            raise ValueError(f"invalid argument path {value!r}")
        return value

    @property
    def operator(self) -> str:
        """The name of the operator this condition uses."""
        return next(name for name in OPERATORS if self.operand(name) is not None)

    def operand(self, name: str) -> object:
        """Return the value given for operator ``name`` (``None`` when absent)."""
        return self.in_ if name == "in" else getattr(self, name)


class Rule(_Strict):
    """A policy rule: tool name patterns, optional conditions and an action."""

    id: StrictStr = Field(min_length=1)
    tools: list[StrictStr] = Field(min_length=1)
    action: Action
    when: list[Condition] = Field(default_factory=list)
    reason: StrictStr | None = None


class AuditConfig(_Strict):
    """Where the audit log goes and which keys are redacted."""

    path: StrictStr | None = None
    redact_keys: list[StrictStr] = Field(default_factory=lambda: list(DEFAULT_REDACT_KEYS))


class Policy(_Strict):
    """A complete policy file."""

    version: Literal[1]
    default: Action
    hide_denied_tools: StrictBool = False
    audit: AuditConfig = Field(default_factory=AuditConfig)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen or rule.id in RESERVED_RULE_IDS:
                raise ValueError(f"rule id {rule.id!r} is reserved or used more than once")
            seen.add(rule.id)
        return self
