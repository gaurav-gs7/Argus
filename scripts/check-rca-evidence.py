#!/usr/bin/env python3
"""Independently recompute committed RCA scores from their recorded evidence.

For every demo-evidence snapshot this checks that:
- each probe's status agrees with its recorded value, comparator and threshold
- corroborated/refuted weights, independent sources (cause-specific probes
  only), cap and final confidence match the documented formula
- no evidence line cites a backend that did not corroborate the hypothesis
"""

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
BASELINE = 0.35
ALERT_MATCH = 0.45
REFUTATION_FACTOR = 0.5
TOLERANCE = 1e-9
COMPARATORS = {
    ">=": lambda value, threshold: value >= threshold,
    ">": lambda value, threshold: value > threshold,
    "<=": lambda value, threshold: value <= threshold,
    "<": lambda value, threshold: value < threshold,
}


def close(actual: float, expected: float) -> bool:
    return math.isclose(actual, expected, rel_tol=0.0, abs_tol=TOLERANCE)


def source_cap(sources: int) -> float:
    if sources <= 1:
        return 0.55
    if sources == 2:
        return 0.80
    return 0.95


def fail(path: Path, message: str) -> None:
    raise ValueError(f"{path}: {message}")


def validate(path: Path) -> str:
    with path.open(encoding="utf-8") as handle:
        rca = json.load(handle)["rca"]
    score = rca["score_breakdown"]
    rule_id = score.get("rule_id", "")

    if not rule_id:
        if not close(rca["confidence"], BASELINE):
            fail(path, "unmatched incident must report the baseline confidence")
        return f"{path.name}: no rule matched, confidence {BASELINE:.2f}"

    corroborated = refuted = 0.0
    backends: set[str] = set()
    symptom_backends: set[str] = set()
    for item in rca["evidence_items"]:
        if item["rule_id"] != rule_id or item["kind"] != "probe":
            continue
        status, value = item["status"], item.get("value")
        if status in ("corroborated", "refuted"):
            if value is None:
                fail(path, f"{item['reference']} is {status} without a recorded value")
            held = COMPARATORS[item["comparator"]](value, item["threshold"])
            if held != (status == "corroborated"):
                fail(path, f"{item['reference']} status {status} disagrees with {value} {item['comparator']} {item['threshold']}")
            if status == "corroborated":
                corroborated += item["weight"]
                # Symptom probes (error ratio, latency) add weight but do not
                # make their backend an independent source.
                if item.get("symptom", False):
                    symptom_backends.add(item["source"])
                else:
                    backends.add(item["source"])
            else:
                refuted += item["weight"]
        elif value is not None:
            fail(path, f"{item['reference']} is {status} but records a value")

    sources = ["alertmanager", *sorted(backends)]
    raw = round(ALERT_MATCH + corroborated - REFUTATION_FACTOR * refuted, 4)
    cap = source_cap(len(sources))
    final = min(cap, max(BASELINE, raw))
    checks = {
        "corroborated": corroborated,
        "refuted": refuted,
        "raw": raw,
        "source_cap": cap,
        "final": final,
    }
    for key, expected in checks.items():
        if not close(score[key], expected):
            fail(path, f"score_breakdown.{key}={score[key]} but recomputed {expected}")
    if score["sources"] != sources:
        fail(path, f"sources {score['sources']} != recomputed {sources}")
    if score["contradicted"] != (refuted > corroborated):
        fail(path, "contradicted flag does not match the evidence")
    if not close(rca["confidence"], final + score.get("topology_adjustment", 0)):
        fail(path, "report confidence does not match its score breakdown")

    for line in rca["evidence"]:
        prefix = line.split(":", 1)[0]
        backend = prefix.split(" ", 1)[0]
        if backend not in ("prometheus", "loki"):
            continue
        allowed = symptom_backends if prefix.endswith("(symptom)") else backends
        if backend not in allowed:
            fail(path, f"evidence line {line!r} has no matching corroborated probe from {backend}")
    if score["contradicted"] and any(c["action_type"] != "collect_diagnostics" for c in rca["candidates"]):
        fail(path, "contradicted hypothesis proposes remediation")

    return f"{path.name}: {rule_id} {final:.2f} from {', '.join(sources)}"


def main() -> None:
    for filename in SCENARIOS:
        print(validate(EVIDENCE_DIR / filename))
    print(f"Recomputed RCA scores for {len(SCENARIOS)} scenarios from recorded evidence.")


if __name__ == "__main__":
    main()
