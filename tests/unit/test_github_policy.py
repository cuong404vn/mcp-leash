"""Behaviour of policies/github.yaml with the tools of github/github-mcp-server."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.policy import Policy, always_denied, evaluate, load_policy

ROOT = Path(__file__).parents[2]
POLICY = ROOT / "policies" / "github.yaml"
SERVER_TOOLS = {
    line
    for line in (ROOT / "tests" / "fixtures" / "github_mcp_server_tools.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line and not line.startswith("#")
}

MINE = {"owner": "your-name", "repo": "your-repo"}
OTHER = {"owner": "someone-else", "repo": "private-stuff"}


@functools.cache
def policy() -> Policy:
    return load_policy(POLICY)


def decide(tool: str, **arguments: Any) -> tuple[str, str]:
    decision = evaluate(policy(), tool, arguments)
    return decision.action, decision.rule


def test_policy_names_only_real_tools() -> None:
    named = {t for rule in policy().rules for t in rule.tools if "*" not in t}
    assert named <= SERVER_TOOLS, sorted(named - SERVER_TOOLS)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_file_contents", {"path": "README.md"}),
        ("get_repository_tree", {"recursive": True}),
        ("list_commits", {"sha": "main"}),
        ("issue_read", {"issue_number": 3, "method": "get_comments"}),
        ("pull_request_read", {"pullNumber": 4, "method": "get_diff"}),
        ("get_job_logs", {"run_id": 1, "failed_only": True}),
    ],
)
def test_reads_in_the_repository_are_allowed(tool: str, arguments: dict[str, Any]) -> None:
    assert decide(tool, **MINE, **arguments) == ("allow", "read-this-repository")


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("add_issue_comment", {"issue_number": 3, "body": "Fixed in #4."}),
        ("issue_write", {"method": "create", "title": "Bug", "body": "Steps..."}),
        ("create_branch", {"branch": "agent/fix-typo"}),
        ("create_or_update_file", {"branch": "agent/fix", "path": "src/a.py", "content": "x = 1"}),
        ("push_files", {"branch": "agent/fix", "files": [{"path": "a.md", "content": "hi"}]}),
        ("create_pull_request", {"base": "main", "head": "agent/fix", "title": "Fix"}),
        ("pull_request_review_write", {"method": "create", "pullNumber": 4, "event": "COMMENT"}),
    ],
)
def test_work_in_the_repository_is_allowed(tool: str, arguments: dict[str, Any]) -> None:
    assert decide(tool, **MINE, **arguments) == ("allow", "work-in-this-repository")


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_file_contents", {**OTHER, "path": "secrets.md"}),
        ("add_issue_comment", {**OTHER, "issue_number": 1, "body": "leaked text"}),
        ("issue_write", {"owner": "your-name", "repo": "other-repo", "method": "create"}),
        ("issue_write", {"owner": "someone-else", "repo": "your-repo", "method": "create"}),
        ("create_pull_request", {"repo": "your-repo", "base": "main", "head": "x", "title": "t"}),
        ("search_code", {"query": "repo:someone-else/private-stuff password"}),
        ("search_issues", {**MINE, "query": "is:open"}),
        ("list_notifications", {}),
        ("get_gist", {"gist_id": "abc"}),
        ("sub_issue_write", {**MINE, "method": "add", "issue_number": 1, "sub_issue_id": 2}),
    ],
)
def test_anything_else_is_denied_by_default(tool: str, arguments: dict[str, Any]) -> None:
    assert decide(tool, **arguments) == ("deny", "default")


@pytest.mark.parametrize(
    "tool",
    [
        "merge_pull_request",
        "delete_file",
        "delete_repository",
        "actions_run_trigger",
        "create_gist",
        "fork_repository",
        "list_secret_scanning_alerts",
    ],
)
def test_dangerous_tools_are_denied_and_hidden(tool: str) -> None:
    assert decide(tool, **MINE) == ("deny", "no-merge-delete-or-admin")
    assert always_denied(policy(), tool)


@pytest.mark.parametrize(
    "tool", ["get_file_contents", "issue_write", "push_files", "get_me", "search_code"]
)
def test_other_tools_stay_visible(tool: str) -> None:
    assert not always_denied(policy(), tool)


@pytest.mark.parametrize("branch", ["main", "master", "Main", "refs/heads/main", " main "])
def test_pushes_to_the_default_branch_are_denied(branch: str) -> None:
    file = {"path": "a.md", "content": "x", "message": "m"}
    assert decide("create_or_update_file", **MINE, branch=branch, **file) == (
        "deny",
        "no-pushes-to-default-branch",
    )
    files = [{"path": "a.md", "content": "x"}]
    assert decide("push_files", **MINE, branch=branch, files=files, message="m") == (
        "deny",
        "no-pushes-to-default-branch",
    )


@pytest.mark.parametrize("branch", ["main-fix", "agent/main", "maintenance"])
def test_branches_named_like_main_are_allowed(branch: str) -> None:
    arguments = {"path": "a.md", "content": "x", "message": "m", "branch": branch}
    assert decide("create_or_update_file", **MINE, **arguments)[0] == "allow"


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", "/.github/workflows/x.yaml"])
def test_workflow_files_cannot_be_written(path: str) -> None:
    arguments = {"branch": "agent/ci", "message": "m", "content": "on: push"}
    assert decide("create_or_update_file", **MINE, path=path, **arguments) == (
        "deny",
        "no-workflow-files",
    )
    files = [{"path": "README.md", "content": "x"}, {"path": path, "content": "on: push"}]
    assert decide("push_files", **MINE, branch="agent/ci", message="m", files=files) == (
        "deny",
        "no-workflow-files-push",
    )


def test_other_github_files_can_be_written() -> None:
    arguments = {"branch": "agent/x", "message": "m", "content": "x"}
    assert decide("create_or_update_file", **MINE, path=".github/CODEOWNERS", **arguments)[0] == (
        "allow"
    )


@pytest.mark.parametrize(
    "text",
    [
        "token: ghp_" + "a" * 36,
        "github_pat_" + "A1b2" * 10,
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_credentials_cannot_be_posted(text: str) -> None:
    assert decide("add_issue_comment", **MINE, issue_number=1, body=text) == (
        "deny",
        "no-credentials-in-arguments",
    )


def test_get_me_is_allowed() -> None:
    assert decide("get_me") == ("allow", "who-am-i")
