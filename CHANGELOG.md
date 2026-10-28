# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add the `istarts_with` policy operator for Unicode case-insensitive string prefixes.

## [0.1.0] - 2026-10-28

First release: a stdio proxy that checks every MCP `tools/call` against a YAML policy. Install it from GitHub with `uv tool install git+https://github.com/cuong404vn/mcp-leash@v0.1.0`. It is not published to PyPI.

### Added

- `mcp-leash run`: a stdio proxy that checks every `tools/call` against a YAML policy, answers denied calls with an `isError` result and never forwards them.
- `--dry-run` audit mode that logs `would_deny` and forwards every call.
- Strict parsing: lines with invalid UTF-8, duplicate keys or `NaN` are dropped and logged, and so is a JSON-RPC batch that contains a `tools/call`.
- `hide_denied_tools` to remove always-denied tools from `tools/list` responses.
- JSON Lines audit log with redaction of listed keys and truncation of long strings. If the log cannot be written, calls that would be allowed are denied.
- Policy engine: ordered rules where the first match wins, glob tool patterns, and the operators `equals`, `not_equals`, `in`, `starts_with`, `matches` and `within`.
- `arg` selects a nested value (`options.path`), a list item by index (`command.0`), or any string at any depth (`'*'`).
- `starts_with`, `matches` and `within` accept a string or a list of strings: an allow rule needs every item to pass, a deny rule only one, and an empty list never matches.
- `within` path checks that resolve `..`, symlinks and `~`. Windows compares case-insensitively. Elsewhere, deny rules ignore case and Unicode normalization, so on macOS `~/.SSH/id_rsa` matches a deny rule for `~/.ssh`, and allow rules compare names exactly. A path starting with `~` must be inside under both readings (`~` expanded, or a folder named `~`) for an allow rule, and under either for a deny rule.
- `${PROJECT_DIR}` and `${ENV_VAR}` variables; unknown or empty variables fail validation.
- `mcp-leash validate`, `mcp-leash check` and `mcp-leash init`.
- `mcp-leash suggest LOG [--policy FILE]` prints a policy that adds an allow rule for each tool that no rule decided in an audit log, with path arguments kept inside `${PROJECT_DIR}`. The rules of `FILE` come first, unchanged.
- `readonly` and `project` templates for the official filesystem server. `readonly` allows reads inside the project. `project` allows reads, writes and moves inside the project, and blocks deletes, `.env` files and the `.git` directory. Both block `file:` URIs and `%`-escapes in path arguments, and arguments that contain secret values (long `key=value` pairs, private keys, GitHub, OpenAI and AWS key formats).
- `policies/github.yaml` for the GitHub MCP server (tool names of github-mcp-server v2.0.3): every call stays in one repository, pushes to `main` or `master` and workflow files are blocked, and merging, deleting, running workflows, gists, settings and secret-scanning alerts are hidden from the agent.
- `policies/shell.yaml` for mcp-shell-server (written for v1.1.14): read-only `git` subcommands and `ls`, `cat`, `head`, `tail`, `wc` inside the project; no pipes, chaining, redirection, paths outside the project, `.env` files, or git options that write files or run programs.
- Tests that run the `project` template in front of the real filesystem server (`MCP_LEASH_REAL_SERVERS=1`), with a CI job.
- `benchmarks/overhead.py` to measure the time mcp-leash adds per call (about 0.5 ms on Windows 11 with the `project` template).
- Demo GIF in the README, recorded from a real run by `examples/demo/make_demo_gif.py`.
- GitHub Releases from `v*` tags, with notes taken from this file.

[Unreleased]: https://github.com/cuong404vn/mcp-leash/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cuong404vn/mcp-leash/releases/tag/v0.1.0
