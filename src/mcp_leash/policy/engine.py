"""The policy decision function: ``evaluate(policy, tool, arguments) -> Decision``."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from mcp_leash.policy.matchers import IndeterminateError, condition_holds
from mcp_leash.policy.models import Action, Policy, Rule


@dataclass(frozen=True)
class Decision:
    """The outcome for one tool call."""

    action: Action
    rule: str
    """The id of the deciding rule, or ``"default"`` when no rule matched."""
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def tool_matches(rule: Rule, tool: str) -> bool:
    """True if any of the rule's glob patterns matches the tool name (case-sensitive)."""
    return any(fnmatchcase(tool, pattern) for pattern in rule.tools)


def evaluate(policy: Policy, tool: str, arguments: Any) -> Decision:
    """Decide a tool call. The first rule whose tools and conditions all match wins.

    If a condition cannot be evaluated with certainty (for example a path that
    cannot be resolved), the call is denied by that rule. A value that can be
    read several ways must pass under every reading to match an allow rule, and
    under any reading to match a deny rule.
    """
    for rule in policy.rules:
        if not tool_matches(rule, tool):
            continue
        require_all = rule.action == "allow"
        try:
            matched = all(condition_holds(c, arguments, require_all=require_all) for c in rule.when)
        except IndeterminateError as exc:
            return Decision("deny", rule.id, f"Could not evaluate the policy: {exc}")
        if matched:
            return Decision(rule.action, rule.id, rule.reason)
    return Decision(policy.default, "default", None)


def always_denied(policy: Policy, tool: str) -> bool:
    """True if a rule without conditions denies ``tool`` before any rule could allow it."""
    for rule in policy.rules:
        if not tool_matches(rule, tool):
            continue
        if rule.action == "allow":
            return False
        if not rule.when:
            return True
    return False
