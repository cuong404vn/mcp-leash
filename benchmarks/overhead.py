"""Measure how much time mcp-leash adds to each tools/call.

Run from the repository root:

    uv run python benchmarks/overhead.py

It sends the same sequence of tools/call requests to the test server twice:
once directly, and once through ``mcp-leash run`` with the ``project`` template
and its audit log. Each request waits for its response, so the difference in
round-trip time is the proxy's overhead: parsing, policy evaluation (including
``realpath`` on the path argument), the audit write and the extra pipe hop.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import timeit
from pathlib import Path

from mcp_leash.policy import evaluate, parse_policy

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "tests" / "fixtures" / "fake_server.py"
TEMPLATE = ROOT / "src" / "mcp_leash" / "templates" / "project.yaml"


def round_trips(
    command: list[str], cwd: Path, calls: int, arguments: dict[str, str]
) -> list[float]:
    """Send ``calls`` sequential tools/call requests and return each round trip in ms."""
    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=cwd
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    timings: list[float] = []
    for request_id in range(calls):
        params = {"name": "read_file", "arguments": arguments}
        line = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}
        )
        start = time.perf_counter()
        proc.stdin.write(line.encode() + b"\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
        timings.append((time.perf_counter() - start) * 1000)
        if reply["result"]["isError"]:
            raise SystemExit(f"call was not allowed: {reply}")
    proc.stdin.close()
    proc.wait(timeout=30)
    return timings


def summary(values: list[float]) -> str:
    ordered = sorted(values)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    return f"median {statistics.median(ordered):6.3f} ms   p95 {p95:6.3f} ms"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--calls", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        project = work / "project"
        (project / "src").mkdir(parents=True)
        (project / "src" / "app.py").write_text("print('hi')\n")
        policy = work / "policy.yaml"
        text = TEMPLATE.read_text(encoding="utf-8")
        policy.write_text(text.replace("~/.mcp-leash/audit.jsonl", "audit.jsonl"), encoding="utf-8")
        arguments = {"path": str(project / "src" / "app.py")}

        server = [sys.executable, str(SERVER)]
        proxied = [
            sys.executable, "-m", "mcp_leash", "run",
            "--policy", str(policy), "--project-dir", str(project), "--", *server,
        ]  # fmt: skip
        total = args.warmup + args.calls
        direct = round_trips(server, work, total, arguments)[args.warmup :]
        through = round_trips(proxied, work, total, arguments)[args.warmup :]

        loaded = parse_policy(policy.read_text(encoding="utf-8"), project_dir=str(project))
        runs = 5000
        engine = timeit.timeit(lambda: evaluate(loaded, "read_file", arguments), number=runs)

    print(f"{platform.system()} {platform.release()}, Python {platform.python_version()}")
    print(f"{args.calls} sequential tools/call round trips after {args.warmup} warm-up calls")
    print(f"  direct to server     {summary(direct)}")
    print(f"  through mcp-leash    {summary(through)}")
    overhead = statistics.median(through) - statistics.median(direct)
    print(f"  added by mcp-leash   median {overhead:6.3f} ms")
    print(f"  policy evaluation    {engine / runs * 1000:6.3f} ms per call (engine only)")


if __name__ == "__main__":
    main()
