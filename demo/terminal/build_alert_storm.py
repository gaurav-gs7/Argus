#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


SERVICES = [
    "nginx",
    "checkout-api",
    "payments-api",
    "nginx",
    "checkout-api",
    "payments-api",
    "postgres",
    "nginx",
    "checkout-api",
    "payments-api",
    "nginx",
    "checkout-api",
    "payments-api",
    "postgres",
    "nginx",
    "checkout-api",
    "payments-api",
    "nginx",
    "checkout-api",
    "payments-api",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the live terminal demo alert storm")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    started_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=len(SERVICES))
    alerts: list[dict[str, object]] = []
    for index, service in enumerate(SERVICES):
        root_evidence = service == "postgres"
        alert_name = "PostgresConnectionPoolExhausted" if root_evidence else "DependencyFailure"
        summary = (
            "postgres connection pool saturation; connection acquisition timeout increased"
            if root_evidence
            else f"{service} errors followed the shared postgres connection outage"
        )
        alerts.append(
            {
                "status": "firing",
                "labels": {
                    "alertname": alert_name,
                    "service": service,
                    "environment": args.environment,
                    "severity": "sev2",
                },
                "annotations": {"summary": summary},
                "startsAt": (started_at + dt.timedelta(seconds=index))
                .isoformat()
                .replace("+00:00", "Z"),
                "fingerprint": f"terminal-{args.run_id}-{index:02d}",
            }
        )

    payload = {"status": "firing", "receiver": "terminal-demo", "alerts": alerts}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
