from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_leash.policy import parse_policy
from mcp_leash.policy.matchers import (
    _MISSING,
    IndeterminateError,
    canonical_path,
    condition_holds,
    fold,
    is_inside,
    iter_strings,
    json_equal,
    select,
    within,
)
from mcp_leash.policy.models import Condition

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX path semantics")


def cond(**fields: Any) -> Condition:
    return Condition.model_validate(fields)


@pytest.mark.parametrize(
    ("condition", "arguments", "expected"),
    [
        # equals / not_equals with strict JSON typing
        ({"arg": "a", "equals": "x"}, {"a": "x"}, True),
        ({"arg": "a", "equals": "x"}, {"a": "X"}, False),
        ({"arg": "a", "equals": 1}, {"a": 1.0}, True),
        ({"arg": "a", "equals": 1}, {"a": True}, False),
        ({"arg": "a", "equals": True}, {"a": 1}, False),
        ({"arg": "a", "equals": False}, {"a": False}, True),
        ({"arg": "a", "equals": "1"}, {"a": 1}, False),
        ({"arg": "a", "equals": 2.5}, {"a": 2.5}, True),
        ({"arg": "a", "not_equals": "x"}, {"a": "y"}, True),
        ({"arg": "a", "not_equals": "x"}, {"a": "x"}, False),
        ({"arg": "a", "not_equals": 0}, {"a": False}, True),
        ({"arg": "a", "not_equals": "x"}, {"a": None}, True),
        # in
        ({"arg": "a", "in": ["x", 2, True]}, {"a": 2}, True),
        ({"arg": "a", "in": ["x", 2, True]}, {"a": "x"}, True),
        ({"arg": "a", "in": ["x", 2]}, {"a": True}, False),
        ({"arg": "a", "in": []}, {"a": "x"}, False),
        # starts_with / matches / not_matches
        ({"arg": "a", "starts_with": "/tmp/"}, {"a": "/tmp/x"}, True),
        ({"arg": "a", "starts_with": "/tmp/"}, {"a": "/tmpx"}, False),
        ({"arg": "a", "matches": "^rm\\b"}, {"a": "rm -rf /"}, True),
        ({"arg": "a", "matches": "(?i)secret"}, {"a": "my SECRET"}, True),
        ({"arg": "a", "matches": "^ls$"}, {"a": "ls -la"}, False),
        ({"arg": "a", "not_matches": "^rm\\b"}, {"a": "ls -la"}, True),
        ({"arg": "a", "not_matches": "^rm\\b"}, {"a": "rm -rf /"}, False),
        # missing arguments make every operator false
        ({"arg": "a", "equals": "x"}, {}, False),
        ({"arg": "a", "not_equals": "x"}, {}, False),
        ({"arg": "a", "in": ["x"]}, {}, False),
        ({"arg": "a", "matches": "."}, {"b": "x"}, False),
        ({"arg": "a", "not_matches": "."}, {"b": "x"}, False),
        ({"arg": "a", "within": ["/"]}, {}, False),
        # nested paths
        ({"arg": "options.mode", "equals": "x"}, {"options": {"mode": "x"}}, True),
        ({"arg": "options.mode", "equals": "x"}, {"options": "x"}, False),
        ({"arg": "options.mode", "equals": "x"}, {"options": [{"mode": "x"}]}, False),
        ({"arg": "a.b.c", "equals": 1}, {"a": {"b": {"c": 1}}}, True),
        # '*' scans string values at any depth, but not keys or non-strings
        ({"arg": "*", "matches": "key"}, {"a": {"b": ["x", {"c": "api key"}]}}, True),
        ({"arg": "*", "matches": "key"}, {"key": "x", "a": {"key": 1}}, False),
        ({"arg": "*", "equals": 1}, {"a": 1}, False),
        ({"arg": "*", "starts_with": "x"}, {"a": [1, None, True, "xyz"]}, True),
        ({"arg": "*", "matches": "."}, {}, False),
    ],
)
def test_condition_holds(condition: dict[str, Any], arguments: Any, expected: bool) -> None:
    assert condition_holds(cond(**condition), arguments) is expected


@pytest.mark.parametrize("operator", ["starts_with", "matches"])
@pytest.mark.parametrize("value", [1, None, ["x", 1], [["x"]], {"x": "y"}, True])
def test_string_operators_reject_non_strings(operator: str, value: Any) -> None:
    with pytest.raises(IndeterminateError, match="needs a string or a list of strings"):
        condition_holds(cond(arg="a", **{operator: "x"}), {"a": value})


@pytest.mark.parametrize(
    ("condition", "value", "allow_rule", "deny_rule"),
    [
        ({"starts_with": "x"}, ["xa", "xb"], True, True),
        ({"starts_with": "x"}, ["xa", "b"], False, True),
        ({"starts_with": "x"}, ["a", "b"], False, False),
        ({"matches": "^-"}, ["-v", "--all"], True, True),
        ({"matches": "^-"}, ["status", "-v"], False, True),
        ({"matches": "."}, [], False, False),
    ],
)
def test_string_operators_check_every_item_of_a_list(
    condition: dict[str, Any], value: list[str], allow_rule: bool, deny_rule: bool
) -> None:
    c = cond(arg="a", **condition)
    assert condition_holds(c, {"a": value}, require_all=True) is allow_rule
    assert condition_holds(c, {"a": value}, require_all=False) is deny_rule


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        ("command.0", "git"),
        ("command.2", "--stat"),
        ("command.3", None),
        ("command.-1", None),
        ("command.01", None),
        ("command.x", None),
        ("files.1.path", "b.md"),
        ("files.2.path", None),
        ("map.0", "zero"),
    ],
)
def test_select_reads_list_items_by_index(arg: str, expected: str | None) -> None:
    arguments = {
        "command": ["git", "diff", "--stat"],
        "files": [{"path": "a.md"}, {"path": "b.md"}],
        "map": {"0": "zero"},
    }
    value = select(arguments, arg)
    assert (None if value is _MISSING else value) == expected


@pytest.mark.parametrize("value", [5, None, True, {"x": "/a"}, ["/a", 5], [["/a"]], [None]])
@pytest.mark.parametrize("require_all", [True, False])
def test_within_rejects_values_that_are_not_paths(value: Any, require_all: bool) -> None:
    with pytest.raises(IndeterminateError, match="needs a path or a list of paths"):
        condition_holds(cond(arg="a", within=["/"]), {"a": value}, require_all=require_all)


def test_iter_strings_order_and_depth() -> None:
    assert list(iter_strings({"a": "1", "b": [2, "3", {"c": "4"}], "d": None})) == ["1", "3", "4"]


def test_json_equal_does_not_coerce() -> None:
    assert json_equal(1, 1.0)
    assert not json_equal(True, 1)
    assert not json_equal(None, None)
    assert not json_equal([1], [1])


def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("x")
    return root


def allowed(root: Path) -> list[str]:
    return [canonical_path(str(root))]


def test_within_accepts_paths_inside(tmp_path: Path) -> None:
    root = project(tmp_path)
    for path in [root, root / "src", root / "src" / "new" / "file.py", root / "a" / ".." / "b"]:
        assert within(str(path), allowed(root)), path


def test_within_rejects_traversal(tmp_path: Path) -> None:
    root = project(tmp_path)
    for path in [
        root / "..",
        root / ".." / "outside" / "secret.txt",
        root / "src" / ".." / ".." / "outside",
        Path(str(root) + "-sibling") / "x",
        tmp_path,
    ]:
        assert not within(str(path), allowed(root)), path


def test_within_rejects_prefix_sibling(tmp_path: Path) -> None:
    root = project(tmp_path)
    sibling = tmp_path / "project2"
    sibling.mkdir()
    assert not within(str(sibling / "x"), allowed(root))


def symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:  # Windows without Developer Mode or admin rights
        pytest.skip(f"cannot create symlinks here: {exc}")


def test_within_rejects_symlink_escape(tmp_path: Path) -> None:
    root = project(tmp_path)
    symlink_or_skip(root / "escape", tmp_path / "outside")
    symlink_or_skip(root / "file-link", tmp_path / "outside" / "secret.txt")
    assert not within(str(root / "escape" / "secret.txt"), allowed(root))
    assert not within(str(root / "escape"), allowed(root))
    assert not within(str(root / "file-link"), allowed(root))


def test_within_follows_symlinked_allowed_directory(tmp_path: Path) -> None:
    root = project(tmp_path)
    link = tmp_path / "link-to-project"
    symlink_or_skip(link, root)
    assert within(str(root / "src" / "a"), [canonical_path(str(link))])
    assert within(str(link / "src" / "a"), allowed(root))


def test_within_resolves_relative_paths_against_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = project(tmp_path)
    monkeypatch.chdir(root)
    assert within("src/a.py", allowed(root))
    assert within(".", allowed(root))
    assert not within("../outside/secret.txt", allowed(root))


def test_within_tilde_readings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = project(tmp_path)
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("USERPROFILE", str(root))
    monkeypatch.chdir(tmp_path / "outside")
    # "~/x" means root/x when expanded, but outside/~/x when taken literally:
    # inside for a deny rule, which needs one reading, not for an allow rule.
    assert not within("~/x", allowed(root))
    assert within("~/x", allowed(root), require_all=False)
    assert not within("~/x", [canonical_path(str(tmp_path / "elsewhere"))], require_all=False)
    monkeypatch.chdir(root)
    assert within("~/x", allowed(root))


@pytest.mark.parametrize(
    ("names", "allow_rule", "deny_rule"),
    [
        (["inside"], True, True),
        (["inside", "nested"], True, True),
        (["inside", "outside"], False, True),
        (["outside", "inside"], False, True),
        (["outside"], False, False),
        ([], False, False),
    ],
)
def test_within_checks_every_path_in_a_list(
    tmp_path: Path, names: list[str], allow_rule: bool, deny_rule: bool
) -> None:
    root = project(tmp_path)
    paths = {
        "inside": root / "a.txt",
        "nested": root / "src" / "b.py",
        "outside": tmp_path / "outside" / "secret.txt",
    }
    arguments = {"paths": [str(paths[name]) for name in names]}
    condition = cond(arg="paths", within=allowed(root))
    assert condition_holds(condition, arguments, require_all=True) is allow_rule
    assert condition_holds(condition, arguments, require_all=False) is deny_rule


def test_within_nul_byte_is_indeterminate(tmp_path: Path) -> None:
    root = project(tmp_path)
    with pytest.raises(IndeterminateError):
        within(str(root / "a\x00b"), allowed(root))


def test_is_inside_root_directory() -> None:
    root = canonical_path(os.sep)
    assert is_inside(canonical_path(os.path.join(os.sep, "etc")), root)
    assert is_inside(root, root)


@windows_only
def test_within_is_case_insensitive_on_windows(tmp_path: Path) -> None:
    root = project(tmp_path)
    for require_all in [True, False]:
        assert within(str(root).upper() + "\\SRC\\a.py", allowed(root), require_all=require_all)
        assert within(
            str(root).lower().replace("\\", "/") + "/src", allowed(root), require_all=require_all
        )


@windows_only
def test_within_windows_drive_letters(tmp_path: Path) -> None:
    root = project(tmp_path)
    drive = os.path.splitdrive(str(root))[0]
    other = "Z:" if drive.upper() != "Z:" else "Y:"
    assert not within(other + "\\project\\src", allowed(root))
    assert not within(drive + "\\", allowed(root))
    assert within("\\\\?\\" + str(root / "src"), allowed(root))


@posix_only
def test_within_case_outside_windows(tmp_path: Path) -> None:
    root = project(tmp_path)
    keys = [canonical_path(str(root / "src"))]
    for path in [root / "SRC" / "id_rsa", root.parent / root.name.upper() / "Src" / "id_rsa"]:
        # An allow rule compares names exactly; a deny rule ignores case.
        assert not within(str(path), keys), path
        assert within(str(path), keys, require_all=False), path
    assert within(str(root / "src" / "id_rsa"), keys)
    assert not within(str(root / "SRCX" / "a"), keys, require_all=False)


@posix_only
def test_within_unicode_normalization_outside_windows(tmp_path: Path) -> None:
    root = project(tmp_path)
    secrets = [canonical_path(str(root / "café"))]  # é as one code point
    decomposed = str(root / "café" / "x")  # e followed by a combining accent
    assert not within(decomposed, secrets)
    assert within(decomposed, secrets, require_all=False)
    assert within(str(root / "CAFÉ" / "x"), secrets, require_all=False)


@pytest.mark.parametrize(
    ("a", "b"),
    [("ABC", "abc"), ("café", "CAFÉ"), ("Straße", "STRASSE")],
)
def test_fold_matches_caseless_names(a: str, b: str) -> None:
    assert fold(a) == fold(b)
    assert fold("abc") != fold("abd")


def test_within_in_policy_expands_variables(tmp_path: Path) -> None:
    root = project(tmp_path)
    policy = parse_policy(
        "version: 1\ndefault: deny\nrules:\n"
        "  - id: r\n    tools: ['*']\n    action: allow\n    when:\n"
        "      - arg: path\n        within: ['${PROJECT_DIR}/src', '${DATA}']\n",
        project_dir=str(root),
        env={"DATA": str(tmp_path / "outside")},
    )
    from mcp_leash.policy import evaluate

    assert evaluate(policy, "t", {"path": str(root / "src" / "x")}).allowed
    assert evaluate(policy, "t", {"path": str(tmp_path / "outside" / "secret.txt")}).allowed
    assert not evaluate(policy, "t", {"path": str(root / "README.md")}).allowed
