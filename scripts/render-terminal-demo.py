#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import textwrap
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFont
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Terminal GIF rendering requires Pillow. Install it with: "
        "python3 -m pip install -r requirements-media.txt"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAST = ROOT / "docs" / "demo-evidence" / "argus-terminal-demo.cast"
DEFAULT_OUTPUT = ROOT / "docs" / "assets" / "argus-demo.gif"
WIDTH = 1280
HEIGHT = 720
MAX_COLUMNS = 112
MAX_ROWS = 23
LINE_HEIGHT = 24
TARGET_DURATION_MS = 150_000

BACKGROUND = "#071017"
TERMINAL = "#0B141C"
TITLEBAR = "#111D26"
BORDER = "#29404D"
TEXT = "#E6EDF3"
MUTED = "#8193A1"
GREEN = "#4DDBA7"
BLUE = "#65B8FF"
AMBER = "#F1C56B"
RED = "#FF6B78"
CYAN = "#62D9E8"
PURPLE = "#C7A0FF"

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SCENE = re.compile(r"ARGUS LIVE DEMO  \[(\d{2})/13\]  ([^\r\n]+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the evidence-backed Argus terminal cast as an animated GIF"
    )
    parser.add_argument("--cast", type=Path, default=DEFAULT_CAST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def load_cast(path: Path) -> tuple[dict[str, Any], list[tuple[float, str]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise ValueError("terminal cast contains no output events")
    header = json.loads(lines[0])
    if header.get("version") != 2:
        raise ValueError("only Asciinema v2 casts are supported")
    events: list[tuple[float, str]] = []
    for raw in lines[1:]:
        timestamp, stream, output = json.loads(raw)
        if stream == "o":
            events.append((float(timestamp), str(output)))
    if not events or events[0][0] != 0 or events[-1][0] != 150:
        raise ValueError("terminal cast must span exactly 0 to 150 seconds")
    return header, events


def wrap_line(line: str) -> list[str]:
    if len(line) <= MAX_COLUMNS:
        return [line]
    indent = line[: len(line) - len(line.lstrip())]
    return textwrap.wrap(
        line,
        width=MAX_COLUMNS,
        subsequent_indent=indent + "  ",
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]


def update_screen(
    screen: list[str], output: str, scene_number: int, scene_title: str
) -> tuple[list[str], int, str]:
    if "\x1b[2J" in output:
        screen = []
    cleaned = ANSI.sub("", output).replace("\r", "")
    match = SCENE.search(cleaned)
    if match:
        scene_number = int(match.group(1))
        scene_title = match.group(2).strip()
    for line in cleaned.split("\n"):
        if not line and cleaned.endswith("\n") and line == cleaned.split("\n")[-1]:
            continue
        screen.extend(wrap_line(line))
    return screen[-MAX_ROWS:], scene_number, scene_title


def font_path(candidates: tuple[str, ...]) -> Path:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path
    raise SystemExit("A supported terminal font is required to render the demo")


def load_fonts() -> dict[str, ImageFont.FreeTypeFont]:
    mono = font_path(
        (
            "/System/Library/Fonts/Menlo.ttc",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        )
    )
    sans = font_path(
        (
            "/System/Library/Fonts/HelveticaNeue.ttc",
            "/System/Library/Fonts/Helvetica.ttc",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        )
    )
    return {
        "mono": ImageFont.truetype(str(mono), 17),
        "small_mono": ImageFont.truetype(str(mono), 13),
        "title": ImageFont.truetype(str(sans), 17),
        "brand": ImageFont.truetype(str(sans), 21),
    }


def line_color(line: str) -> str:
    lowered = line.lower()
    if line.startswith("$"):
        return GREEN
    if "argus live demo" in lowered or line.startswith("==="):
        return CYAN
    if "denied" in lowered or "http 400" in lowered or '"error"' in lowered:
        return RED
    if "propose_only" in lowered or "awaiting_approval" in lowered:
        return AMBER
    if "[pass]" in lowered or '"valid": true' in lowered or '"status": "succeeded"' in lowered:
        return GREEN
    if "->" in line or "--->" in line or " v" == line.rstrip():
        return PURPLE
    if line.startswith("argus-") or line.startswith(" inc_"):
        return MUTED
    if line.startswith("{") or line.startswith("}") or line.lstrip().startswith('"'):
        return BLUE
    return TEXT


def draw_frame(
    screen: list[str],
    scene_number: int,
    scene_title: str,
    elapsed: float,
    fonts: dict[str, ImageFont.FreeTypeFont],
) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (18, 18, WIDTH - 18, HEIGHT - 18),
        radius=14,
        fill=TERMINAL,
        outline=BORDER,
        width=2,
    )
    draw.rounded_rectangle((18, 18, WIDTH - 18, 70), radius=14, fill=TITLEBAR)
    draw.rectangle((18, 53, WIDTH - 18, 70), fill=TITLEBAR)
    for x, color in ((44, RED), (68, AMBER), (92, GREEN)):
        draw.ellipse((x - 7, 37 - 7, x + 7, 37 + 7), fill=color)
    draw.text((124, 36), "ARGUS", font=fonts["brand"], fill=TEXT, anchor="lm")
    draw.text(
        (WIDTH // 2, 37),
        f"LIVE CONTROL PLANE | {scene_title}",
        font=fonts["title"],
        fill=MUTED,
        anchor="mm",
    )
    draw.text(
        (WIDTH - 38, 37),
        f"{elapsed:05.1f}s / 150.0s",
        font=fonts["small_mono"],
        fill=CYAN,
        anchor="rm",
    )

    y = 88
    for line in screen[-MAX_ROWS:]:
        draw.text((40, y), line, font=fonts["mono"], fill=line_color(line))
        y += LINE_HEIGHT

    draw.rectangle((18, HEIGHT - 48, WIDTH - 18, HEIGHT - 18), fill=TITLEBAR)
    draw.text(
        (40, HEIGHT - 34),
        "ACTUAL TERMINAL INPUT + PROCESSING + OUTPUT",
        font=fonts["small_mono"],
        fill=GREEN,
        anchor="lm",
    )
    draw.text(
        (WIDTH - 40, HEIGHT - 34),
        f"scene {scene_number:02d}/13 | verified cast",
        font=fonts["small_mono"],
        fill=MUTED,
        anchor="rm",
    )
    return image


def render(cast_path: Path, output_path: Path) -> dict[str, Any]:
    _, events = load_cast(cast_path)
    fonts = load_fonts()
    frames: list[Image.Image] = []
    durations: list[int] = []
    screen: list[str] = []
    scene_number = 1
    scene_title = "INCIDENT TO SAFE REMEDIATION"

    for index, (timestamp, output) in enumerate(events[:-1]):
        screen, scene_number, scene_title = update_screen(
            screen, output, scene_number, scene_title
        )
        next_timestamp = events[index + 1][0]
        duration_ms = int(round((next_timestamp - timestamp) * 1000))
        if duration_ms <= 0 or duration_ms % 10:
            raise ValueError(f"GIF-incompatible frame duration: {duration_ms}ms")
        frames.append(draw_frame(screen, scene_number, scene_title, timestamp, fonts))
        durations.append(duration_ms)

    if sum(durations) != TARGET_DURATION_MS:
        raise ValueError(
            f"expected {TARGET_DURATION_MS}ms of frames, got {sum(durations)}ms"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    palette_frames = [
        frame.convert("P", palette=Image.Palette.ADAPTIVE, colors=64)
        for frame in frames
    ]
    palette_frames[0].save(
        output_path,
        save_all=True,
        append_images=palette_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    return {
        "source": str(cast_path.relative_to(ROOT)),
        "output": str(output_path.relative_to(ROOT)),
        "width": WIDTH,
        "height": HEIGHT,
        "frames": len(frames),
        "duration_seconds": sum(durations) / 1000,
        "bytes": output_path.stat().st_size,
    }


def main() -> None:
    args = parse_args()
    print(json.dumps(render(args.cast, args.output), indent=2))


if __name__ == "__main__":
    main()
