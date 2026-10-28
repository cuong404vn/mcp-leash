# Threat model

mcp-leash is a policy layer for MCP tool calls. This document says what it protects, what it does not, and the bypasses we know about. If you find a gap that is not listed, report it privately as described in [SECURITY.md](../SECURITY.md).

## The setting

An MCP client (Claude Desktop, Cursor, a custom agent) launches mcp-leash, and mcp-leash launches the real MCP server. The model decides which tools to call, and it can be steered by text it reads: a web page, an email, a file, or a tool result. That steering (prompt injection) is the main threat mcp-leash is built for.

| Party | Trust |
| --- | --- |
| Policy author (you) | Trusted. The policy is assumed to say what you mean. |
| MCP client | Trusted. It launches mcp-leash and chooses the server command. |
| Model and the text it reads | Untrusted. Any `tools/call` it sends may be hostile. |
| MCP server | Not trusted to enforce anything, and not contained either. mcp-leash decides which calls reach it, but cannot control what it does with an allowed call. |

## What mcp-leash protects

- **Tool calls are checked before they run.** Every `tools/call` request from the client is evaluated, and a denied call never reaches the server.
- **Same message, same reading.** Lines are parsed strictly: invalid UTF-8, a byte order mark, duplicate keys and `NaN`/`Infinity` are rejected, and the original bytes are forwarded unchanged. A message cannot look harmless to mcp-leash and different to the server.
- **Path containment.** `within` resolves `..` and symlinks with `realpath` on both sides, compares case-insensitively on Windows, and checks every path in a list. When a value can be read more than one way (several paths in a list, a `~` path that a server may or may not expand, or a name whose case may or may not matter outside Windows), an allow rule needs every reading inside and a deny rule needs only one.
- **Fail closed.** A value that cannot be evaluated (a path that cannot be resolved, a list where a string was expected), a malformed `tools/call`, a batch that contains `tools/call`, an unknown or empty policy variable, and an audit log that cannot be written all lead to a deny or a refusal to start.
- **Accountability.** Every decision is logged with its rule, with secrets redacted from the arguments.

## What mcp-leash does not protect

- **What an allowed tool does.** If the policy allows `run_command`, the agent can run any command. mcp-leash checks arguments; it does not understand their effect. Allow narrow tools, not general ones.
- **The server itself.** mcp-leash is not a sandbox. A buggy or malicious server can read, write or send anything its operating system user can. Run untrusted servers in a container or under a restricted user.
- **Other MCP features.** v0.1 evaluates only `tools/call`. `resources/read`, `prompts/get`, sampling, elicitation and notifications pass through unchecked. If a server exposes files as resources, the agent can read them without a tool call.
- **Tool results.** Responses from the server are not inspected. A tool result can carry a prompt injection into the model (planned for v0.4).
- **Tool descriptions.** `tools/list` descriptions come from the server and can contain hostile instructions ("tool poisoning"). `hide_denied_tools` removes always-denied tools but does not rewrite descriptions.
- **Other transports.** Only stdio is supported. HTTP and SSE connections bypass mcp-leash entirely (planned for v0.3).
- **The client's own settings.** If the client is configured to launch the server directly as well, that connection is not protected.

## Known bypasses and mitigations

| Bypass | Why it works | Mitigation |
| --- | --- | --- |
| **Another tool name for the same action.** A deny rule for `delete_file` misses `remove_path`, or a `move_file` to a trash folder. | Rules match tool names, and servers name tools freely. | Use `default: deny` and allow-list the tools you need. Check real names with `tools/list` in a `--dry-run` session. |
| **Another argument for the same value.** A rule on `path` misses `paths: [...]`, `source`/`destination`, or `options.path`. | Conditions select one argument. A missing argument makes a condition false, so an allow rule does not match, but a deny rule does not either. | Prefer allow rules with `within` on every path argument, combined with AND. Use `arg: '*'` for deny patterns that should apply to every string. |
| **Case and Unicode changes outside Windows.** `~/.SSH/id_rsa` for a deny rule on `~/.ssh`, on macOS, a FAT or exFAT drive, or WSL's `/mnt/c`. | These file systems ignore case (and macOS also Unicode normalization), while most Linux file systems do not, and mcp-leash cannot tell which one a path is on. | Handled: deny rules with `within` compare names caselessly outside Windows, so the call is denied. Allow rules compare exactly, so a path written in another case than the real one fails closed. Deny rules with `matches` are not covered: add `(?i)` to the pattern. |
| **Encoded paths.** `file:///etc/passwd` or `%2e%2e/secret` reach a server that decodes URIs or percent-escapes. | `within` reads the argument as a literal path. Both strings look relative, so they resolve inside the working directory and pass an allow rule. The official filesystem server (tested with 2.0.1) also reads them literally, so it is not affected, but other servers may decode them. | The `readonly` and `project` templates deny `file:` URIs and `%`-escapes in path arguments (`no-encoded-paths`, `no-encoded-paths-multi`), before the allow rules. For another server, add the same deny rule on its path arguments, with `matches: '(?i)^\s*file:\|%[0-9a-f]{2}'`. Avoid `arg: '*'` there if a tool also takes file contents, which often hold `%20` or `%02x`. |
| **Symlink races (TOCTOU).** A path is checked, then a symlink is swapped in before the server opens it. | The check and the server's file access happen at different times. | Do not allow tools that create symlinks or run commands in the same session, and keep untrusted users out of the allowed directories. |
| **Windows path forms.** Short 8.3 names (`PROGRA~1`), alternate data streams (`file.txt::$DATA`), trailing dots and spaces, device paths. | `realpath` normalizes most of these, but not every edge case is covered yet. | Allow-list with `within`. Tracked as a known issue for Windows path edge cases. |
| **Expensive regular expressions.** A pattern like `(a+)+$` on crafted input stalls the proxy. | Python's `re` has no timeout. | Keep `matches` patterns simple, without nested quantifiers. |
| **A broad project directory.** `${PROJECT_DIR}` resolves to `/` or the client's install folder. | It defaults to the directory mcp-leash starts in, which the client chooses. | Always pass `--project-dir`. mcp-leash warns when the project directory is a filesystem root. |
| **Editing the audit log.** The agent writes to the log file through an allowed tool. | The log is an ordinary file. | Keep `audit.path` outside every directory the agent can write to. The templates use `~/.mcp-leash/audit.jsonl`. |
| **Secrets in unlisted keys.** A secret under `apiToken` or in free text reaches the log. | Redaction matches exact key names only. | Add your own key names to `redact_keys`, and deny credential-looking arguments with `matches`. |

## Reporting

Please report new bypasses privately as described in [SECURITY.md](../SECURITY.md), so a fix can ship before the details are public.
