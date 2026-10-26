"""Record the README demo: an agent tries to delete a file and mcp-leash blocks it.

Run from the repository root:

    uv run --with pillow python examples/demo/make_demo_gif.py

The script starts mcp-leash for real, in front of demo_server.py, sends the
calls an agent would send, and renders the real responses, the files left on
disk and the audit log as docs/demo.gif.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
OUTPUT = HERE.parents[1] / "docs" / "demo.gif"

CALLS = [
    ("delete_file", "project/notes.txt"),
    ("read_file", "project/../../.ssh/id_rsa"),
    ("read_file", "project/notes.txt"),
]

BACKGROUND = (13, 17, 23)
TITLE_BAR = (22, 27, 34)
TEXT = (201, 209, 217)
DIM = (139, 148, 158)
PROMPT = (63, 185, 80)
AGENT = (210, 153, 34)
BLOCKED = (248, 81, 73)
ALLOWED = (88, 166, 255)

WIDTH = 980
PADDING = 22
FONT_SIZE = 16
LINE_HEIGHT = 24
TITLE_HEIGHT = 34
CHARS_PER_FRAME = 3
TYPE_MS = 35
FONTS = [
    "C:/Windows/Fonts/CascadiaMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]


@dataclass
class Line:
    """One line of the transcript."""

    text: str
    color: tuple[int, int, int]
    typed: bool = False
    pause_ms: int = 0


def rpc(request_id: int | None, method: str, params: dict[str, Any] | None = None) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode() + b"\n"


def record() -> list[Line]:
    """Run mcp-leash in front of the demo server and turn what happened into a transcript."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "project").mkdir()
        (work / "project" / "notes.txt").write_bytes(b"hello from the project\n")
        shutil.copy(HERE / "policy.yaml", work / "policy.yaml")
        shutil.copy(HERE / "demo_server.py", work / "demo_server.py")

        requests = [
            rpc(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}),
            rpc(None, "notifications/initialized"),
        ]
        for request_id, (tool, path) in enumerate(CALLS, start=1):
            params = {"name": tool, "arguments": {"path": path}}
            requests.append(rpc(request_id, "tools/call", params))
        command = [
            sys.executable, "-m", "mcp_leash", "run",
            "--policy", "policy.yaml", "--project-dir", "project",
            "--", sys.executable, "demo_server.py",
        ]  # fmt: skip
        proc = subprocess.run(
            command, input=b"".join(requests), capture_output=True, cwd=work, timeout=60, check=True
        )
        replies = {reply["id"]: reply for reply in map(json.loads, proc.stdout.splitlines())}
        files_left = sorted(os.listdir(work / "project"))
        audit = [json.loads(x) for x in (work / "audit.jsonl").read_text("utf-8").splitlines()]

    lines = [
        Line("# The MCP client starts mcp-leash in front of the server:", DIM),
        Line(
            "$ mcp-leash run --policy policy.yaml --project-dir project -- python demo_server.py",
            PROMPT,
            typed=True,
            pause_ms=500,
        ),
        Line("", TEXT),
    ]
    for request_id, (tool, path) in enumerate(CALLS, start=1):
        result = replies[request_id]["result"]
        text = result["content"][0]["text"].strip()
        lines.append(Line(f'agent > {tool} {{"path": "{path}"}}', AGENT, typed=True, pause_ms=250))
        lines.append(
            Line(f"        {text}", BLOCKED if result["isError"] else ALLOWED, pause_ms=1300)
        )
    lines += [
        Line("", TEXT),
        Line("$ ls project", PROMPT, typed=True, pause_ms=250),
        Line("  ".join(files_left), TEXT, pause_ms=900),
        Line(
            "$ jq -c 'select(.event==\"tool_call\") | {tool, decision, rule}' audit.jsonl",
            PROMPT,
            typed=True,
            pause_ms=250,
        ),
    ]
    for record_ in audit:
        if record_["event"] == "tool_call":
            summary = {key: record_[key] for key in ("tool", "decision", "rule")}
            lines.append(Line(json.dumps(summary, separators=(",", ":")), TEXT, pause_ms=200))
    return lines


def load_font() -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for candidate in FONTS:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, FONT_SIZE)
    return ImageFont.load_default(size=FONT_SIZE)


def wrap(lines: list[Line], max_chars: int) -> list[Line]:
    """Split lines that are too wide, keeping the indentation of continuation lines."""
    out: list[Line] = []
    for line in lines:
        indent = " " * (len(line.text) - len(line.text.lstrip()) or 2)
        parts = textwrap.wrap(line.text, max_chars, subsequent_indent=indent) or [""]
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            out.append(Line(part, line.color, line.typed, line.pause_ms if last else 0))
    return out


def render(lines: list[Line]) -> tuple[list[Image.Image], list[int]]:
    font = load_font()
    char_width = font.getlength("M")
    lines = wrap(lines, int((WIDTH - 2 * PADDING) / char_width))
    height = TITLE_HEIGHT + 2 * PADDING + LINE_HEIGHT * len(lines)

    def frame(visible: list[str], cursor: bool) -> Image.Image:
        image = Image.new("RGB", (WIDTH, height), BACKGROUND)
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, WIDTH, TITLE_HEIGHT), fill=TITLE_BAR)
        for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            x = 18 + i * 20
            draw.ellipse((x, 11, x + 12, 23), fill=color)
        draw.text((WIDTH / 2, TITLE_HEIGHT / 2), "mcp-leash", fill=DIM, font=font, anchor="mm")
        for row, text in enumerate(visible):
            y = TITLE_HEIGHT + PADDING + row * LINE_HEIGHT
            draw.text((PADDING, y), text, fill=lines[row].color, font=font)
        if cursor:
            row = len(visible) - 1
            x = PADDING + char_width * len(visible[row])
            y = TITLE_HEIGHT + PADDING + row * LINE_HEIGHT
            draw.rectangle((x, y + 2, x + char_width - 1, y + LINE_HEIGHT - 4), fill=TEXT)
        return image

    frames: list[Image.Image] = []
    durations: list[int] = []
    shown: list[str] = []
    for line in lines:
        if line.typed:
            for end in range(0, len(line.text) + 1, CHARS_PER_FRAME):
                frames.append(frame([*shown, line.text[:end]], cursor=True))
                durations.append(TYPE_MS)
        shown.append(line.text)
        frames.append(frame(shown, cursor=False))
        durations.append(max(line.pause_ms, 60))
    durations[-1] = 5000
    return frames, durations


def main() -> None:
    frames, durations = render(record())
    palette = frames[-1].quantize(colors=48, dither=Image.Dither.NONE)
    images = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(
        OUTPUT, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True
    )
    print(f"wrote {OUTPUT} ({len(images)} frames, {OUTPUT.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
