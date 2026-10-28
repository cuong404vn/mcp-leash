# Policy reference

A policy is one YAML file. mcp-leash validates it at startup: if anything is wrong, it prints the error to stderr, exits with code 2 and starts nothing. Run `mcp-leash validate FILE` to check a policy without starting a server.

```yaml
version: 1
default: deny
hide_denied_tools: true
audit:
  path: ~/.mcp-leash/audit.jsonl
  redact_keys: [token, password, api_key, authorization, secret]
rules:
  - id: no-deletes
    tools: ['delete_*', 'remove_*', 'rm']
    action: deny
    reason: Deleting files is not permitted for agents.

  - id: read-inside-project
    tools: ['read_file', 'list_directory']
    action: allow
    when:
      - arg: path
        within: ['${PROJECT_DIR}']
```

Unknown keys anywhere in the file are errors, so a typo such as `whne:` is caught instead of silently ignored. Duplicate keys in the same mapping are also errors.

## Top-level fields

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `version` | yes | | Schema version. Must be `1`. |
| `default` | yes | | `allow` or `deny`: the action when no rule matches. |
| `hide_denied_tools` | no | `false` | Remove always-denied tools from `tools/list` responses. |
| `audit` | no | see below | Where the audit log goes and what is redacted. |
| `rules` | no | `[]` | The ordered list of rules. |

### `default`

```yaml
default: deny   # recommended: only what a rule allows can run
```

With `default: allow`, every tool you did not think of is allowed. Prefer `deny` and list what the agent may do.

### `hide_denied_tools`

```yaml
hide_denied_tools: true
```

When `true`, mcp-leash removes a tool from the server's `tools/list` response if a rule without `when` denies it before any rule could allow it, so the model does not try to use it. A call to a hidden tool is still evaluated and denied.

- A tool denied only by `default: deny` is not hidden.
- A tool that some earlier `allow` rule could match (even with conditions) is not hidden.
- Nothing is hidden in `--dry-run` mode, which never changes traffic.

### `audit`

```yaml
audit:
  path: ~/.mcp-leash/audit.jsonl
  redact_keys: [token, password, api_key, authorization, secret]
```

| Field | Default | Meaning |
| --- | --- | --- |
| `path` | none | Audit log file. `~` and `${VAR}` are expanded, a relative path is resolved against the directory mcp-leash starts in, and missing parent directories are created. Without `path`, audit records are written to stderr. |
| `redact_keys` | `[token, password, api_key, authorization, secret]` | Argument keys whose values are replaced by `"[REDACTED]"` in the log. |

If the log file cannot be opened at startup, mcp-leash exits with code 2. If a record cannot be written later, calls that would have been allowed are denied, because an allowed call must never go unrecorded.

Keep the log outside every directory the agent may write to, or the agent could edit its own audit trail.

## Rules

```yaml
rules:
  - id: write-docs
    tools: ['write_file', 'edit_file']
    action: allow
    when:
      - arg: path
        within: ['${PROJECT_DIR}/docs']
    reason: Agents may only edit the docs.
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique name, shown in blocked responses and the audit log. `default` and `invalid-request` are reserved. |
| `tools` | yes | Non-empty list of glob patterns matched against the tool name. |
| `action` | yes | `allow` or `deny`. |
| `when` | no | List of conditions. All must hold (AND). An empty or missing list always holds. |
| `reason` | no | Text returned to the model and written to the log when the rule denies a call. |

### Evaluation order

1. Rules are checked top to bottom.
2. A rule matches when one of its `tools` patterns matches the tool name and all its `when` conditions hold.
3. The first matching rule decides. If none matches, `default` applies, and the log shows `"rule": "default"`.

Put specific `deny` rules before broad `allow` rules.

```yaml
rules:
  - id: no-secrets-dir              # checked first
    tools: ['*']
    action: deny
    when:
      - arg: path
        within: ['${PROJECT_DIR}/secrets']
  - id: read-project                # only reached if the rule above did not match
    tools: ['read_file']
    action: allow
    when:
      - arg: path
        within: ['${PROJECT_DIR}']
```

### Tool patterns

`tools` uses shell-style globs, matched case-sensitively against the full tool name:

| Pattern | Matches |
| --- | --- |
| `*` | any sequence of characters, including none |
| `?` | exactly one character |
| `[abc]` | one of the listed characters |
| `[!abc]` | one character not listed |

```yaml
tools: ['*']                 # every tool
tools: ['delete_*', 'rm']    # delete_file, delete_branch, ... and rm
tools: ['git_?']             # git_a, git_b, ... but not git_ab
```

Servers name their tools freely. Check the real names with the server's `tools/list` (for example in the audit log of a `--dry-run` session) rather than guessing.

## Conditions

Each condition has an `arg` and exactly one operator.

```yaml
when:
  - arg: options.mode
    equals: safe
```

### Selecting arguments with `arg`

| `arg` | Selects |
| --- | --- |
| `path` | The top-level argument `path`. |
| `options.mode` | A nested value: `{"options": {"mode": ...}}`. |
| `command.0` | An item of a list, counted from 0: `"git"` in `{"command": ["git", "status"]}`. An index past the end is a missing argument. Indexes and keys mix: `files.1.path`. |
| `'*'` | Every string value at any depth, inside objects and lists. Keys, numbers, booleans and `null` are skipped. The condition holds if any of those strings satisfies the operator. |

A missing argument makes the condition false, for every operator, including `not_equals`. A rule like `action: allow, when: [{arg: mode, not_equals: unsafe}]` therefore does not match a call that has no `mode` at all.

Quote `'*'` in YAML, because a bare `*` starts an alias.

### Operators

| Operator | Operand | Holds when |
| --- | --- | --- |
| `equals` | string, number or boolean | The value is equal, with no type conversion. |
| `not_equals` | string, number or boolean | The value exists and is not equal. |
| `in` | list of strings, numbers or booleans | The value equals one of the items. |
| `starts_with` | string | The value is a string, or a list of strings, with this prefix. |
| `matches` | regular expression | Python `re.search` finds the pattern in the string value, or in the items of a list of strings. |
| `within` | non-empty list of directories | The value is a path, or a list of paths, inside the directories. |

#### `equals` and `not_equals`

```yaml
- arg: dry_run
  equals: true
- arg: branch
  not_equals: main
```

Comparison is by JSON type: `1` equals `1.0`, but `1` does not equal `true` or `"1"`. `null` is not a valid operand.

#### `in`

```yaml
- arg: method
  in: [GET, HEAD, OPTIONS]
```

#### `starts_with`

```yaml
- arg: url
  starts_with: 'https://api.github.com/'
```

#### `matches`

```yaml
- arg: '*'
  matches: 'BEGIN [A-Z ]*PRIVATE KEY'
```

Match the shape of the value you want to stop, not a word. A pattern like `secret` also matches `secret.txt` and `secrets_manager.py`, which blocks ordinary file access. The `no-credentials-in-arguments` rule in the shipped templates shows a pattern that matches `key=value` pairs with a long value, private keys, and GitHub, OpenAI and AWS key formats.

The pattern uses Python [`re`](https://docs.python.org/3/library/re.html) syntax and is checked when the policy loads; an invalid pattern is a validation error. `re.search` matches anywhere in the string, so anchor with `^` and `$` when you mean the whole value. Use `(?i)` for case-insensitive matching. Write patterns in single quotes so YAML keeps backslashes as they are.

Patterns run on text the agent controls. Avoid nested quantifiers such as `(a+)+`, which can take a very long time on crafted input.

#### Lists of strings

`starts_with` and `matches` also take an argument that is a list of strings, and check every item. An allow rule needs every item to pass and a deny rule needs only one, as with lists of paths under [`within`](#when-a-value-can-be-read-more-than-one-way); an empty list never matches. With list indexes in `arg`, this covers tools that take a command as a list, such as the shell server in [`policies/shell.yaml`](https://github.com/cuong404vn/mcp-leash/blob/main/policies/shell.yaml):

```yaml
- id: no-chaining
  tools: ['shell_execute']
  action: deny
  when:
    - arg: command               # any item that is exactly |, ; or &&
      matches: '^(\||;|&&)$'
- id: git-status
  tools: ['shell_execute']
  action: allow
  when:
    - arg: command.0
      equals: git
    - arg: command.1
      equals: status
```

#### `within`

```yaml
- arg: path
  within: ['${PROJECT_DIR}/src', '${PROJECT_DIR}/docs']
```

`within` decides whether a path is inside one of the listed directories. Both sides are resolved before comparing:

- `~` and `${VAR}` are expanded in the listed directories.
- Relative paths, in the policy and in the argument, are resolved against the directory mcp-leash starts in.
- `os.path.realpath` is applied to both sides, so `..` segments and symlinks cannot escape.
- On Windows the comparison is case-insensitive and `\\?\` prefixes are removed. Elsewhere an allow rule compares names exactly, and a deny rule ignores case and Unicode normalization (see below).
- A directory matches itself and everything below it. `/project` does not match `/project2`.

Some tools take a list of paths, such as `read_multiple_files` in the official filesystem server. `within` checks every path in the list:

```yaml
- id: read-many-inside-project
  tools: ['read_multiple_files']
  action: allow
  when:
    - arg: paths
      within: ['${PROJECT_DIR}']
```

##### When a value can be read more than one way

A list of paths is several values, and a path that starts with `~` means two different paths: one with `~` expanded to the home directory, and one with a folder literally named `~` (servers differ in how they treat it). Outside Windows, `.SSH` and `.ssh`, or `é` written as one character and as `e` plus an accent, are the same folder on macOS and on FAT or exFAT drives, but two folders on most Linux file systems. `within` checks every reading, and the rule's action decides how they combine, so an ambiguous value always leans toward deny:

| Rule | Condition holds when |
| --- | --- |
| `action: allow` | every path in the list, under every reading, is inside |
| `action: deny` | any path in the list, under any reading, is inside |

So `read_multiple_files` with one path outside the project does not match an allow rule for the project, and one path in `~/.ssh` is enough to match a deny rule for `~/.ssh`. An empty list never matches. On macOS, a deny rule for `~/.ssh` also matches `~/.SSH/id_rsa`, while an allow rule for `/Users/me/project` does not match `/users/me/project/a.txt`: the call is denied, and the agent has to use the path with its real case.

### Values that cannot be evaluated

When a condition cannot be evaluated with certainty, the call is denied by the rule being checked, whatever that rule's action is. The reason starts with `Could not evaluate the policy:`. This happens when:

- `starts_with` or `matches` meets a value that is neither a string nor a list of strings (for example a number, an object, or a list that holds one);
- `within` meets a value that is neither a string nor a list of strings (for example a number, an object, or a list that holds one);
- a path contains a NUL byte or cannot be resolved.

## Variables

`${NAME}` is replaced when the policy loads, in these places:

- `within` directories and `audit.path` (which also expand `~`);
- string operands of `equals`, `not_equals`, `in` and `starts_with`.

It is not replaced in `matches` patterns, where `$` and `{` are regex syntax, nor in `id`, `tools` or `reason`.

| Variable | Value |
| --- | --- |
| `${PROJECT_DIR}` | The `--project-dir` option, or else the directory mcp-leash starts in, fully resolved. |
| `${ANY_OTHER}` | The environment variable with that name. |

An unknown variable, an empty one, or a malformed reference such as `${PROJECT_DIR` is a validation error. mcp-leash never expands a variable to an empty string, because `${UNSET}/secrets` would otherwise become `/secrets`.

MCP clients often start servers from `/` or from their own install folder, so always pass `--project-dir` when a policy uses `${PROJECT_DIR}`. mcp-leash prints a warning when `${PROJECT_DIR}` resolves to a filesystem root.

## What the model sees when a call is blocked

The client receives a normal JSON-RPC result with `isError: true`, so the model can read the reason and adapt:

```json
{"jsonrpc":"2.0","id":7,"result":{"isError":true,"content":[{"type":"text","text":"Blocked by mcp-leash (rule no-deletes): Deleting files is not permitted for agents."}]}}
```

| Situation | Text after `Blocked by mcp-leash (rule ID):` |
| --- | --- |
| A rule with a `reason` denied the call | the rule's `reason` |
| A rule without a `reason` denied the call | `Denied by policy.` |
| No rule matched and `default` is `deny` | `No rule allows this call.` (rule `default`) |
| The request has no string `params.name`, or `arguments` is not an object | `The tools/call request is malformed.` (rule `invalid-request`) |
| The audit log could not be written | `The audit log could not be written.` |

A denied `tools/call` sent as a notification (without an `id`) is dropped without a response, because notifications have none.

Messages that are not `tools/call` requests are never evaluated. Lines that are not strict JSON (invalid UTF-8, duplicate keys, `NaN`, longer than 64 MiB) are dropped and logged, and so is a JSON-RPC batch that contains a `tools/call`.

## Audit log

The log is JSON Lines: one object per line, appended and flushed immediately.

```json
{"ts":"2026-10-26T14:43:05.120Z","event":"tool_call","session":"b1f6","request_id":7,"tool":"delete_file","decision":"deny","rule":"no-deletes","reason":"Deleting files is not permitted for agents.","arguments":{"path":"/home/me/project/a.txt"}}
{"ts":"2026-10-26T14:43:06.004Z","event":"tool_result","session":"b1f6","request_id":8,"tool":"read_file","is_error":false,"latency_ms":12}
{"ts":"2026-10-26T14:43:07.311Z","event":"invalid_message","session":"b1f6","source":"client","error":"duplicate key 'id'"}
```

Every record has `ts` (UTC with milliseconds), `event` and `session` (a short random id per proxy run).

| Event | Fields | Written when |
| --- | --- | --- |
| `tool_call` | `request_id`, `tool`, `decision`, `rule`, `reason`, `arguments` | A `tools/call` request is evaluated. |
| `tool_result` | `request_id`, `tool`, `is_error`, `latency_ms` | The server answers a forwarded call. `is_error` is true for an `isError` result or a JSON-RPC error. |
| `invalid_message` | `source`, `error` | A line is dropped because it is not strict JSON, is too large, or is a batch containing `tools/call`. |

`decision` is `allow`, `deny` or `would_deny` (`--dry-run`). `rule` is the deciding rule's `id`, `default`, or `invalid-request`.

Before writing `arguments`, mcp-leash:

- replaces the value under any key listed in `redact_keys` with `"[REDACTED]"`, at any depth. Keys are compared case-insensitively and must match exactly: `token` redacts `Token` but not `tokens`;
- cuts every string longer than 2,000 characters and appends `…[truncated]`.

Redaction applies to the log only. The server receives the arguments unchanged.

## Command line

| Command | Exit code |
| --- | --- |
| `mcp-leash run --policy FILE [--project-dir DIR] [--dry-run] -- CMD [ARGS...]` | The server's exit code; `128 + N` if the server was killed by signal `N`; `2` for an invalid policy or an audit log that cannot be opened; `127` if `CMD` cannot be started. |
| `mcp-leash validate FILE` | `0` if valid, `2` if not. |
| `mcp-leash check FILE --tool NAME [--args JSON] [--project-dir DIR]` | `0` after printing the decision; `2` for an invalid policy or arguments that are not a JSON object. |
| `mcp-leash init [--template readonly\|project] [--force]` | `0` after writing `mcp-leash.yaml`; `1` if the file exists and `--force` is not given. |

`run` writes only protocol messages to stdout. Diagnostics, including one line per blocked call, go to stderr, which most MCP clients keep in their server logs. When the client closes stdin, `run` closes the server's stdin and waits for the server to finish. On SIGINT or SIGTERM it terminates the server. It exits as soon as the server exits.

## YAML pitfalls

- YAML 1.1 reads `yes`, `no`, `on` and `off` as booleans. Quote them when you mean strings: `equals: 'no'`.
- Quote `'*'` and any pattern that starts with `*`, `[` or `{`.
- Write regular expressions in single quotes. In double quotes YAML processes backslash escapes first.
