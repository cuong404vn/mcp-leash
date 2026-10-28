# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `arg` can select a list item by index, such as `command.0` for the program in `{"command": ["git", "status"]}`.
- `starts_with` and `matches` accept a list of strings and check every item: an allow rule needs every item to pass, a deny rule only one. Before, a list could not be evaluated and denied the call.
- `policies/shell.yaml` for mcp-shell-server (written for v1.1.14): read-only `git` subcommands and `ls`, `cat`, `head`, `tail`, `wc` inside the project; no pipes, chaining, redirection, paths outside the project, `.env` files, or git options that write files or run programs.
- `policies/github.yaml` for the GitHub MCP server (tool names of github-mcp-server v2.0.3): every call stays in one repository, pushes to `main` or `master` and workflow files are blocked, and merging, deleting, running workflows, gists, settings and secret-scanning alerts are hidden from the agent.
- `within` accepts a list of paths and checks each one: an allow rule needs every path inside, a deny rule matches if any path is inside, and an empty list never matches.
- The `readonly` and `project` templates allow `read_multiple_files` when every path is inside the project.
- The `readonly` and `project` templates deny `file:` URIs and `%`-escapes in path arguments (`no-encoded-paths`, `no-encoded-paths-multi`), for servers that decode them. File contents are not checked.
- `benchmarks/overhead.py` to measure the time mcp-leash adds per call (about 0.5 ms on Windows 11 with the `project` template).
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
- The templates allow `list_allowed_directories` and `read_media_file` of the official filesystem server.
- Tests that run the `project` template in front of the real filesystem server (`MCP_LEASH_REAL_SERVERS=1`), with a CI job.

### Changed

- Outside Windows, a deny rule with `within` ignores case and Unicode normalization, so on macOS `~/.SSH/id_rsa` matches a deny rule for `~/.ssh`. Allow rules still compare names exactly, so a path in the wrong case is denied.
- A deny rule with `within` now matches a path starting with `~` if either reading (`~` expanded, or a folder named `~`) is inside. Before, both readings had to be inside, so `~/.ssh/id_rsa` could miss a deny rule for `~/.ssh`. Allow rules still need both.
- mcp-leash is installed from GitHub (`uv tool install git+https://github.com/cuong404vn/mcp-leash`) and is not published to PyPI. The release workflow creates a GitHub Release only, and the client config examples run the installed `mcp-leash` command instead of `uvx`.
- The `no-credentials-in-arguments` rule in the templates and the example policy matches secret values (long `key=value` pairs, private keys, GitHub, OpenAI and AWS key formats) instead of words, so files such as `secret.txt` and code such as `os.environ["API_KEY"]` are no longer blocked.

[Unreleased]: https://github.com/cuong404vn/mcp-leash/commits/main
