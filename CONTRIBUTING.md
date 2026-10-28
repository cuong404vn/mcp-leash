# Contributing to mcp-leash

Thanks for helping. Bug reports, sample policies, docs fixes and code are all welcome. By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Git. uv installs a suitable Python for you.

```bash
git clone https://github.com/cuong404vn/mcp-leash
cd mcp-leash
uv sync
uv run mcp-leash --help
```

## Running the checks

CI runs these on Linux with Python 3.10 to 3.13, and on Windows and macOS with Python 3.13. Run them before opening a pull request:

```bash
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest --cov
```

`uv run ruff format` and `uv run ruff check --fix` fix most style problems. Coverage must stay at 85% or more.

To try another Python version, for example 3.10:

```bash
uv run --python 3.10 pytest
```

On Windows, keep the checkout in a folder whose path has only ASCII characters. Python 3.10 and 3.11 cannot import the editable install from a path such as `C:\Dự án\mcp-leash`.

### How the tests are organized

- `tests/unit/` tests pure functions: the engine, operators, path checks, loader, redaction and the CLI. No processes.
- `tests/integration/` runs the proxy against `tests/fixtures/fake_server.py`, a tiny stdio MCP server that records every line it receives, so tests can prove a blocked call never reached it. `test_cli_run.py` starts `mcp-leash run` as a real process.

- `tests/realserver/` runs the `project` template in front of the real filesystem MCP server, downloaded with `npx`. These tests need Node.js and network access, so they are skipped unless you opt in:

  ```bash
  MCP_LEASH_REAL_SERVERS=1 uv run pytest tests/realserver
  ```

Every policy behaviour needs a test. Prefer table-driven tests with `pytest.mark.parametrize`.

## Adding an operator

1. Add the field to `Condition` in `src/mcp_leash/policy/models.py` and its name to `OPERATORS`. Validate the operand there, as `_valid_regex` does for `matches`.
2. Apply it in `apply_operator` in `src/mcp_leash/policy/matchers.py`. If it only makes sense for strings, take the values from `_strings`, which accepts a string or a list of strings and fails closed on anything else, and combine the results with `require_all` as the other string operators do.
3. If its operand may contain `${VAR}`, expand it in `_expand_condition` in `src/mcp_leash/policy/loader.py`.
4. Add cases to `tests/unit/test_matchers.py` (including a missing argument and `arg: '*'`) and a validation case to `tests/unit/test_loader.py`.
5. Document it in `docs/policy-reference.md` with an example.

## Adding a sample policy

1. Put the policy in `policies/` with a header comment that says which server it is for and what it allows.
2. Add its file name to `test_shipped_policies_are_valid` in `tests/unit/test_loader.py`.
3. Run it against the real server with `--dry-run` and check the audit log: every call you expect to be allowed should say `allow`.
4. Mention it in `README.md` if it is a policy most users will want.

## Measuring overhead

The spec targets less than 5 ms added per call. `benchmarks/overhead.py` sends the same tools/call requests to the test server directly and through `mcp-leash run` with the `project` template, and prints the difference:

```bash
uv run python benchmarks/overhead.py
```

Run it before and after a change to the proxy, the parser or the policy engine.

## Regenerating the demo GIF

`docs/demo.gif` is a real run of mcp-leash in front of `examples/demo/demo_server.py`. After a change to the output the model sees or to the audit log, record it again:

```bash
uv run --with pillow python examples/demo/make_demo_gif.py
```

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`. One logical change per commit.
- Work on a branch and open a pull request against `main`. Fill in the template.
- Keep `README.md`, `CHANGELOG.md` and `docs/` in sync with the code in the same pull request. Add your change under `Unreleased` in `CHANGELOG.md`.
- Do not describe a feature in the README until it works and is tested.
- Never commit secrets, real API keys or personal paths. Use placeholders such as `/ABSOLUTE/PATH/TO/project`.

## Ground rules for the code

- Type hints everywhere; `mypy --strict` must pass.
- Short docstrings on public functions and classes.
- `run` must never write anything but protocol messages to stdout. Use the `mcp_leash` logger, which writes to stderr.
- The policy engine stays deterministic, with no network calls and no LLM.
- When something cannot be interpreted with certainty, deny and log. Never allow.
- No telemetry and no network calls made by mcp-leash itself.
