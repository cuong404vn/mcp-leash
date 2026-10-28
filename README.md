# mcp-leash

**A firewall for your AI agent's tools.** Write one policy, enforce it on any MCP server, audit every call.

[![CI](https://github.com/cuong404vn/mcp-leash/actions/workflows/ci.yml/badge.svg)](https://github.com/cuong404vn/mcp-leash/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cuong404vn/mcp-leash/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/cuong404vn/mcp-leash/blob/main/pyproject.toml)

[Tiếng Việt](https://github.com/cuong404vn/mcp-leash/blob/main/README.vi.md)

AI agents get broad tool access (files, shell, GitHub, databases), and a prompt injection hidden in a web page or an email can steer them. mcp-leash sits between the MCP client and the MCP server, checks every `tools/call` against a YAML policy, and blocks what the policy does not allow. The server never sees a blocked call, and every decision lands in an audit log.

- **No code changes.** Put `mcp-leash run --policy FILE --` in front of the server command.
- **Readable policy.** A YAML file you can commit, review and share.
- **Deterministic.** The same call and the same policy always give the same decision. No LLM in the decision path.
- **Audited.** One JSON line per decision, with secrets redacted.
- **Low overhead.** About 0.5 ms per call with the `project` template and its audit log (median of 2,000 calls on Windows 11, Python 3.12; [`benchmarks/overhead.py`](https://github.com/cuong404vn/mcp-leash/blob/main/benchmarks/overhead.py)).
- **Cross-platform.** Windows, macOS and Linux, Python 3.10+.

## Demo

![An agent tries to delete a file and read outside the project; mcp-leash blocks both, allows a read inside the project, and logs every decision](https://raw.githubusercontent.com/cuong404vn/mcp-leash/main/docs/demo.gif)

This is a real run, recorded by [`examples/demo/make_demo_gif.py`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/demo/make_demo_gif.py). When a call is blocked, mcp-leash answers in place of the server, and the model reads why:

```text
agent  → tools/call delete_file {"path": "/home/me/project/notes.txt"}
leash  ← isError: Blocked by mcp-leash (rule no-deletes): Deleting files is not permitted for agents.
server   (never receives the call)
```

The audit log records the decision:

```json
{"ts":"2026-10-26T14:43:05.120Z","event":"tool_call","session":"b1f6","request_id":7,"tool":"delete_file","decision":"deny","rule":"no-deletes","reason":"Deleting files is not permitted for agents.","arguments":{"path":"/home/me/project/notes.txt"}}
```

## Install

mcp-leash installs straight from GitHub. With [uv](https://docs.astral.sh/uv/) and Git installed:

```bash
uv tool install git+https://github.com/cuong404vn/mcp-leash
```

uv picks a suitable Python and puts the `mcp-leash` command on your PATH. Check it with `mcp-leash --version`, and update later with `uv tool upgrade mcp-leash`.

Without uv, [pipx](https://pipx.pypa.io/) works too (Python 3.10 or newer):

```bash
pipx install git+https://github.com/cuong404vn/mcp-leash
```

## Quickstart

**1. Write a policy.** Create a starter policy in the current directory, then edit it:

```bash
mcp-leash init --template project
```

The `project` template lets the agent read and write inside the project, and blocks deletes, `.env` files, the `.git` directory, encoded paths such as `%2e%2e/` or `file:` URIs, and arguments that look like credentials. The `readonly` template allows reads only.

For the [GitHub MCP server](https://github.com/github/github-mcp-server), start from [`policies/github.yaml`](https://github.com/cuong404vn/mcp-leash/blob/main/policies/github.yaml) and put your repository in it. The agent can read, comment, open issues, push to its own branches and open pull requests in that one repository, and cannot merge, delete, run or edit workflows, publish gists, or reach any other repository. That last part stops the known attack where an injected issue makes the agent copy a private repository into a public one.

**2. Point your MCP client at mcp-leash.** Prefix the server command with `mcp-leash run --policy FILE --project-dir DIR --`. Always pass `--project-dir`: clients often start servers from `/` or from their own install folder, and `${PROJECT_DIR}` defaults to the directory mcp-leash starts in.

Claude Desktop (`claude_desktop_config.json`) and Cursor (`.cursor/mcp.json` or `~/.cursor/mcp.json`) use the same format:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-leash",
      "args": [
        "run",
        "--policy", "/ABSOLUTE/PATH/TO/mcp-leash.yaml",
        "--project-dir", "/ABSOLUTE/PATH/TO/project",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/ABSOLUTE/PATH/TO/project"
      ]
    }
  }
}
```

If the client reports that it cannot find `mcp-leash` (desktop apps, especially on macOS, often start without your shell's PATH), set `command` to the full path: the folder printed by `uv tool dir --bin`, followed by `mcp-leash` (`mcp-leash.exe` on Windows).

Ready-to-edit files: [`examples/claude_desktop_config.json`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/claude_desktop_config.json) and [`examples/cursor_mcp.json`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/cursor_mcp.json).

**3. See a blocked call.** Restart the client and ask the agent to delete a file in the project. It gets the "Blocked by mcp-leash" message above, and the audit log (`~/.mcp-leash/audit.jsonl` with the templates) shows the decision. To test a policy without a client:

```bash
mcp-leash check mcp-leash.yaml --tool delete_file --args '{"path": "notes.txt"}'
```

```text
decision: deny
rule: no-deletes
reason: Deleting files is not permitted for agents.
```

To watch what a policy would block before enforcing it, add `--dry-run`: every call is forwarded and the log records `would_deny`.

## Policy

Rules are checked top to bottom and the first match wins. When no rule matches, `default` applies.

```yaml
version: 1
default: deny                # action when no rule matches: allow | deny
hide_denied_tools: true      # drop always-denied tools from tools/list responses
audit:
  path: ./mcp-leash-audit.jsonl
  redact_keys: [token, password, api_key, authorization, secret]
rules:
  - id: no-deletes
    tools: ['delete_*', 'remove_*', 'rm']
    action: deny
    reason: Deleting files is not permitted for agents.

  - id: read-inside-project
    tools: ['read_file', 'list_directory', 'search_files']
    action: allow
    when:
      - arg: path
        within: ['${PROJECT_DIR}']
```

Conditions support `equals`, `not_equals`, `in`, `starts_with`, `matches` (regex) and `within` (path containment that resolves `..` and symlinks). Every field and operator is described in the [policy reference](https://github.com/cuong404vn/mcp-leash/blob/main/docs/policy-reference.md).

| Command | Purpose |
| --- | --- |
| `mcp-leash run --policy FILE [--project-dir DIR] [--dry-run] -- CMD [ARGS...]` | Start the proxy and launch the real server as `CMD` |
| `mcp-leash validate FILE` | Check a policy file. Exit 0 if valid, 2 if not |
| `mcp-leash check FILE --tool NAME --args JSON` | Evaluate one call offline and print the decision |
| `mcp-leash init [--template readonly\|project]` | Write a starter policy to `mcp-leash.yaml` |

## How it works

mcp-leash is a transparent man-in-the-middle for one MCP stdio connection. The client launches mcp-leash, and mcp-leash launches the real server as a child process.

```text
MCP client                        mcp-leash                         MCP server
(Claude Desktop,      ┌─────────────────────────────────────┐     (child process)
 Cursor, agent)       │ 1. parse   strict JSON-RPC line     │
       │              │ 2. decide  evaluate(policy, tool,   │
       │  tools/call  │            arguments) -> Decision   │  allow
       ├─────────────►│ 3. audit   append one JSONL entry   ├───────────────►│
       │◄─────────────┤                                     │                │
       │  deny:       └─────────────────────────────────────┘                │
       │  isError result                                                     │
       │                                                                     │
       │◄─────────── every other message and every server response ─────────►│
                                pass through unchanged
```

- Only `tools/call` requests are evaluated. Every other message passes through unchanged.
- Messages are parsed strictly: a line with duplicate keys, `NaN` or invalid UTF-8 is dropped, so mcp-leash never reads a message differently from the server.
- It fails closed. A path that cannot be resolved, a malformed `tools/call` or an audit log that cannot be written leads to a deny.

## What mcp-leash is not

- **Not a sandbox.** It only sees MCP traffic. An allowed tool can still do anything the server can do, and a server can misbehave on its own. For strong isolation, also run the server in a container or under a restricted OS user.
- **Not a content filter.** There is no AI classifier. Decisions come only from your rules.
- **Not complete coverage of MCP.** v0.1 checks `tools/call` over stdio. Resources, prompts and sampling pass through unchecked, and HTTP transports are planned for v0.3.

The [threat model](https://github.com/cuong404vn/mcp-leash/blob/main/docs/threat-model.md) lists what is protected, what is not, and known bypasses.

## Roadmap

| Version | Theme |
| --- | --- |
| v0.2 | Tested sample policies for the filesystem, GitHub and shell MCP servers |
| v0.3 | HTTP and SSE (streamable HTTP) transports |
| v0.4 | Detect suspicious instructions in tool results |
| v0.5 | `ask` action: approve a call in the terminal before it runs |
| v0.6 | Rate limits and per-session call budgets |
| v0.7 | `mcp-leash logs` to filter and summarise the audit log |
| v0.8 | TypeScript package with the same policy format |

Progress is tracked in the [milestones](https://github.com/cuong404vn/mcp-leash/milestones).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](https://github.com/cuong404vn/mcp-leash/blob/main/CONTRIBUTING.md) for the development setup, and report security problems privately as described in [SECURITY.md](https://github.com/cuong404vn/mcp-leash/blob/main/SECURITY.md).

## License

[MIT](https://github.com/cuong404vn/mcp-leash/blob/main/LICENSE)
