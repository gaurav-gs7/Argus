#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CAST_PATH = ROOT / "docs" / "demo-evidence" / "argus-terminal-demo.cast"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def fail(message: str) -> None:
    print(f"Terminal demo validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if not CAST_PATH.is_file():
        fail(f"missing capture {CAST_PATH.relative_to(ROOT)}")

    lines = CAST_PATH.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        fail("capture contains no terminal events")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        fail(f"invalid cast header: {exc}")
    if header.get("version") != 2 or header.get("width") != 120 or header.get("height") != 36:
        fail(f"unexpected cast header: {header}")

    events: list[list[object]] = []
    for line_number, raw in enumerate(lines[1:], start=2):
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            fail(f"invalid event on line {line_number}: {exc}")
        if not isinstance(event, list) or len(event) != 3 or event[1] != "o":
            fail(f"invalid output event on line {line_number}: {event}")
        events.append(event)

    timestamps = [float(event[0]) for event in events]
    if timestamps != sorted(timestamps):
        fail("event timestamps are not monotonic")
    duration = timestamps[-1]
    if not 149.5 <= duration <= 155.0:
        fail(f"capture duration is {duration:.3f}s, expected 150s")

    transcript = ANSI.sub("", "".join(str(event[2]) for event in events))
    required = [
        "ARGUS LIVE DEMO  [01/13]",
        "ARGUS LIVE DEMO  [13/13]",
        "POST localhost:8080/v1/alerts/alertmanager",
        '"suppressed_alert_count": 18',
        '"primary_hypothesis": "PostgreSQL connection pool exhaustion"',
        '"advisory_only": true',
        '"action": "PROPOSE_ONLY"',
        '"executed": false',
        "HTTP 400",
        '"status": "approved"',
        '"status": "succeeded"',
        '"status": "reused"',
        '"jetstream": "enabled"',
        '"valid": true',
        "argus_audit_chain_integrity 1",
        "[PASS] 20 alerts -> 1 PostgreSQL root",
    ]
    missing = [marker for marker in required if marker not in transcript]
    if missing:
        fail("capture is missing required proof markers: " + ", ".join(missing))

    if len(re.findall(r"ARGUS LIVE DEMO  \[\d{2}/13\]", transcript)) != 13:
        fail("capture must contain exactly 13 terminal scenes")
    if not re.search(r"inc_[0-9a-f]{32}", transcript):
        fail("capture has no runtime-generated incident ID")
    if not re.search(r"rem_[0-9a-f]{32}", transcript):
        fail("capture has no runtime-generated remediation ID")

    forbidden = [
        "Bearer eyJ",
        "/" + "Users/",
        "argus-local-admin-client-secret",
        "argus-local-operator-client-secret",
        "DEMO FAILED",
    ]
    leaked = [marker for marker in forbidden if marker in transcript]
    if leaked:
        fail("capture contains forbidden material: " + ", ".join(leaked))

    print(
        f"Validated 150-second terminal demo: {len(events)} output events, "
        f"13 scenes, duration {duration:.3f}s."
    )


if __name__ == "__main__":
    main()
