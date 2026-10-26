"""Print the CHANGELOG.md section for one version, for the release notes.

Usage: python .github/scripts/changelog_notes.py 0.1.0
Exits with an error if the section is missing or empty.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_DEFINITION = re.compile(r"^\[[^\]]+\]: \S+$")


def notes(changelog: str, version: str) -> str:
    """Return the body of the ``## [version]`` section without link definitions."""
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", re.MULTILINE | re.DOTALL
    )
    match = pattern.search(changelog)
    body = match.group(1) if match else ""
    lines = [line for line in body.splitlines() if not LINK_DEFINITION.match(line)]
    text = "\n".join(lines).strip()
    if not text:
        raise SystemExit(f"CHANGELOG.md has no notes for version {version}")
    return text


if __name__ == "__main__":
    print(notes(Path("CHANGELOG.md").read_text(encoding="utf-8"), sys.argv[1]))
