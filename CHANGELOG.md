# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `mcp-leash run`: a stdio proxy that checks every `tools/call` against a YAML policy, answers denied calls with an `isError` result and never forwards them.
- Policy engine: ordered rules where the first match wins, glob tool patterns, and the operators `equals`, `not_equals`, `in`, `starts_with`, `matches` and `within`.
- `within` path checks that resolve `..`, symlinks and `~`, and compare case-insensitively on Windows.
- `${PROJECT_DIR}` and `${ENV_VAR}` variables; unknown or empty variables fail validation.
- `hide_denied_tools` to remove always-denied tools from `tools/list` responses.
- `--dry-run` audit mode that logs `would_deny` and forwards every call.
- JSON Lines audit log with redaction of listed keys and truncation of long strings.
- Strict parsing: lines with invalid UTF-8, duplicate keys or `NaN` are dropped and logged.
- `mcp-leash validate`, `mcp-leash check` and `mcp-leash init` with `readonly` and `project` templates.
- The templates allow `list_allowed_directories` and `read_media_file` of the official filesystem server.
- Tests that run the `project` template in front of the real filesystem server (`MCP_LEASH_REAL_SERVERS=1`), with a CI job.

### Changed

- The `no-credentials-in-arguments` rule in the templates and the example policy matches secret values (long `key=value` pairs, private keys, GitHub, OpenAI and AWS key formats) instead of words, so files such as `secret.txt` and code such as `os.environ["API_KEY"]` are no longer blocked.

[Unreleased]: https://github.com/cuong404vn/mcp-leash/commits/main
