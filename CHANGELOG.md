# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Demo GIF in the README, recorded from a real run by `examples/demo/make_demo_gif.py`.
- `mcp-leash run`: a stdio proxy that checks every `tools/call` against a YAML policy, answers denied calls with an `isError` result and never forwards them.
- Policy engine: ordered rules where the first match wins, glob tool patterns, and the operators `equals`, `not_equals`, `in`, `starts_with`, `matches` and `within`.
- `within` path checks that resolve `..`, symlinks and `~`, and compare case-insensitively on Windows.
- `${PROJECT_DIR}` and `${ENV_VAR}` variables; unknown or empty variables fail validation.
- `hide_denied_tools` to remove always-denied tools from `tools/list` responses.
- `--dry-run` audit mode that logs `would_deny` and forwards every call.
- JSON Lines audit log with redaction of listed keys and truncation of long strings.
- Strict parsing: lines with invalid UTF-8, duplicate keys or `NaN` are dropped and logged.
- `mcp-leash validate`, `mcp-leash check` and `mcp-leash init` with `readonly` and `project` templates.

[Unreleased]: https://github.com/cuong404vn/mcp-leash/commits/main
