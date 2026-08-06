#!/usr/bin/env python3
"""Recompute committed deterministic RCA score breakdowns."""

from __future__ import annotations

import json
import math
from pathlib import Path


EVIDENCE_DIR = Path("docs/demo-evidence")
SCENARIOS = (
    "postgres-connection-exhaustion.json",
    "redis-memory-pressure.json",
    "nginx-5xx-spike.json",
    "dependency-latency.json",
    "bad-config-rollout.json",
)
TOLERANCE = 1e-9


def close(actual: float, expected: float) -> bool:
    return math.isclose(actual, expected, rel_tol=0.0, abs_tol=TOLERANCE)


def validate(path: Path) -> None:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)

    rca = document["rca"]
    breakdown = rca["score_breakdown"]
    contributions = []
    for item in breakdown["items"]:
        calculated = item["confidence"] * item["weight"]
        if not close(calculated, item["contribution"]):
            raise ValueError(
                f"{path}: {item['type']} contribution {item['contribution']} != {calculated}"
            )
        contributions.append(calculated)

    evidence_score = sum(contributions)
    if not close(evidence_score, breakdown["evidence_score"]):
        raise ValueError(
            f"{path}: evidence score {breakdown['evidence_score']} != {evidence_score}"
        )

    uncapped = breakdown["baseline"] + evidence_score
    expected = min(0.95, max(0.35, uncapped))
    if not close(expected, breakdown["final_confidence"]):
        raise ValueError(
            f"{path}: final confidence {breakdown['final_confidence']} != {expected}"
        )
    if not close(expected, rca["confidence"]):
        raise ValueError(f"{path}: RCA confidence does not match its score breakdown")
    if breakdown["capped"] != (uncapped > 0.95):
        raise ValueError(f"{path}: capped flag does not match the calculated score")


def main() -> None:
    for filename in SCENARIOS:
        validate(EVIDENCE_DIR / filename)
    print(f"Validated deterministic RCA arithmetic for {len(SCENARIOS)} scenarios.")


if __name__ == "__main__":
    main()
