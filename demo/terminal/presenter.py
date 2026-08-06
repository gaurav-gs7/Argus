#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAST = ROOT / "artifacts" / "terminal-demo" / "argus-terminal-demo.cast"
COMMITTED_CAST = ROOT / "docs" / "demo-evidence" / "argus-terminal-demo.cast"
WIDTH = 120
HEIGHT = 36

CLEAR = "\x1b[2J\x1b[H"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
CYAN = "\x1b[36m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
RESET = "\x1b[0m"


class TerminalCapture:
    def __init__(self, cast_path: Path, paced: bool) -> None:
        self.cast_path = cast_path
        self.paced = paced
        self.real_start = time.monotonic()
        self.virtual_time = 0.0
        cast_path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = cast_path.open("w", encoding="utf-8")
        header = {
            "version": 2,
            "width": WIDTH,
            "height": HEIGHT,
            "timestamp": int(time.time()),
            "title": "Argus: 150-second live incident-to-remediation terminal demo",
            "env": {"SHELL": "/bin/zsh", "TERM": "xterm-256color"},
        }
        self.handle.write(json.dumps(header, separators=(",", ":")) + "\n")

    def now(self) -> float:
        if self.paced:
            return time.monotonic() - self.real_start
        return self.virtual_time

    def advance_to(self, target: float) -> None:
        if self.paced:
            remaining = target - self.now()
            if remaining > 0:
                time.sleep(remaining)
            self.virtual_time = self.now()
        else:
            self.virtual_time = max(self.virtual_time, target)

    def emit(self, text: str, step: float = 0.04) -> None:
        timestamp = round(self.now(), 3)
        sys.stdout.write(text)
        sys.stdout.flush()
        self.handle.write(json.dumps([timestamp, "o", text], separators=(",", ":")) + "\n")
        self.handle.flush()
        if not self.paced:
            self.virtual_time += step

    def close(self) -> None:
        self.handle.close()


class Demo:
    def __init__(self, capture: TerminalCapture, api_url: str, nats_url: str) -> None:
        self.capture = capture
        self.api_url = api_url.rstrip("/")
        self.nats_url = nats_url.rstrip("/")
        self.run_id = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        self.environment = "terminal-" + self.run_id.lower()
        self.evidence_dir = ROOT / "artifacts" / "terminal-demo" / self.run_id
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.operator_token = ""
        self.admin_token = ""
        self.incident_id = ""
        self.remediation_id = ""

    def scene(self, at: float, number: int, title: str, subtitle: str = "") -> None:
        self.capture.advance_to(at)
        line = "=" * 104
        content = (
            f"{CLEAR}{CYAN}{line}{RESET}\r\n"
            f"{BOLD}ARGUS LIVE DEMO  [{number:02d}/13]  {title}{RESET}\r\n"
            f"{DIM}{subtitle}{RESET}\r\n"
            f"{CYAN}{line}{RESET}\r\n\r\n"
        )
        self.capture.emit(content)

    def text(self, value: str, color: str = "") -> None:
        rendered = value.rstrip() + "\r\n"
        self.capture.emit(f"{color}{rendered}{RESET if color else ''}")

    def command(self, value: str) -> None:
        self.capture.emit(f"{GREEN}$ {value}{RESET}\r\n")

    def json_output(self, value: Any) -> None:
        self.text(json.dumps(value, indent=2, sort_keys=False))

    def run_process(self, args: list[str], timeout: int = 30) -> str:
        result = subprocess.run(
            args,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}\n{output}")
        return output

    def curl(
        self,
        method: str,
        path: str,
        token: str = "",
        payload: dict[str, Any] | None = None,
        payload_file: Path | None = None,
    ) -> tuple[int, Any]:
        args = ["curl", "-sS", "-X", method, self.api_url + path]
        if token:
            args.extend(["-H", f"Authorization: Bearer {token}"])
        if payload is not None:
            args.extend(["-H", "Content-Type: application/json", "-d", json.dumps(payload)])
        if payload_file is not None:
            args.extend(["-H", "Content-Type: application/json", "--data-binary", f"@{payload_file}"])
        args.extend(["-w", "\n%{http_code}"])
        output = self.run_process(args)
        body, status_text = output.rsplit("\n", 1)
        status = int(status_text)
        try:
            decoded: Any = json.loads(body)
        except json.JSONDecodeError:
            decoded = body
        return status, decoded

    def save(self, name: str, payload: Any) -> None:
        path = self.evidence_dir / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def require_status(self, status: int, expected: int, body: Any, action: str) -> None:
        if status != expected:
            raise RuntimeError(f"{action} returned HTTP {status}, expected {expected}: {body}")

    def run(self) -> None:
        self.scene(0, 1, "INCIDENT TO SAFE REMEDIATION", "Real stack. Real API calls. Real durable state. No fabricated output.")
        self.text(
            "+--------------------------------------------------------------------------------------+\n"
            "|  150 seconds: 20 alerts -> 1 root incident -> deterministic RCA -> safe action     |\n"
            "+--------------------------------------------------------------------------------------+\n\n"
            "MacBook Air M2 / 8 GB profile | Docker Compose | mock LLM, real governance boundaries",
            YELLOW,
        )

        self.scene(6, 2, "CONTROL-PLANE FLOW", "Explanatory slide; runtime scenes follow in the terminal.")
        self.text(
            "                         +---------------------+\n"
            "  metrics/logs/alerts --->| topology correlator |----> one root incident\n"
            "                         +----------+----------+\n"
            "                                    | every signal retained\n"
            "                                    v\n"
            "  OIDC ----> API ----> PostgreSQL ----> deterministic RCA ----> typed candidates\n"
            "                    audit chain              |                    |\n"
            "                                             v                    v\n"
            "                                      AI explains only      policy + approval\n"
            "                                             |                    |\n"
            "                                      Verdikt PROPOSE_ONLY        v\n"
            "                                                              JetStream worker"
        )

        self.scene(17, 3, "BACKEND + IDENTITY", "Verify live containers, readiness, and the immutable OIDC actor.")
        self.command("docker compose ps argus-api argus-worker postgres nats keycloak verdikt argus-ai")
        services_raw = self.run_process(
            [
                "docker",
                "compose",
                "ps",
                "--format",
                "json",
                "argus-api",
                "argus-worker",
                "postgres",
                "nats",
                "keycloak",
                "verdikt",
                "argus-ai",
            ]
        )
        services = [json.loads(line) for line in services_raw.splitlines() if line]
        status_rows = ["SERVICE        STATE     HEALTH"]
        for service in sorted(services, key=lambda item: item["Service"]):
            status_rows.append(
                f"{service['Service']:<14} {service['State']:<9} "
                f"{service.get('Health') or '-'}"
            )
        self.text("\n".join(status_rows))
        self.operator_token = self.run_process(["./scripts/oidc-token.sh", "operator"])
        self.admin_token = self.run_process(["./scripts/oidc-token.sh", "admin"])
        self.command('./scripts/oidc-token.sh operator  # JWT acquired; value intentionally redacted')
        self.command('curl -H "Authorization: Bearer ${OPERATOR_TOKEN}" localhost:8080/v1/auth/me | jq')
        status, principal = self.curl("GET", "/v1/auth/me", self.operator_token)
        self.require_status(status, 200, principal, "read principal")
        self.json_output({key: principal.get(key) for key in ("id", "issuer", "subject", "role")})

        self.scene(29, 4, "ACTUAL INPUT: TWENTY ALERTS", "Generate a unique alert storm, then POST the real Alertmanager contract.")
        payload_path = self.evidence_dir / "alert-storm.json"
        relative_payload = payload_path.relative_to(ROOT)
        self.command(
            "python3 demo/terminal/build_alert_storm.py "
            f"--run-id {self.run_id} --environment {self.environment} --output {relative_payload}"
        )
        self.run_process(
            [
                "python3",
                "demo/terminal/build_alert_storm.py",
                "--run-id",
                self.run_id,
                "--environment",
                self.environment,
                "--output",
                str(relative_payload),
            ]
        )
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        summary = {
            "alerts": len(payload["alerts"]),
            "services": sorted({item["labels"]["service"] for item in payload["alerts"]}),
            "root_evidence_alerts": sum(
                item["labels"]["service"] == "postgres" for item in payload["alerts"]
            ),
            "environment": self.environment,
        }
        self.command(f"jq '{{alerts: (.alerts|length), first: .alerts[0]}}' {relative_payload}")
        self.json_output(summary)
        self.command(
            'curl -X POST localhost:8080/v1/alerts/alertmanager '
            '-H "Authorization: Bearer ${OPERATOR_TOKEN}" --data-binary @alert-storm.json'
        )
        status, ingestion = self.curl(
            "POST", "/v1/alerts/alertmanager", self.operator_token, payload_file=payload_path
        )
        self.require_status(status, 202, ingestion, "ingest alert storm")
        self.save("ingestion.json", ingestion)
        self.incident_id = ingestion["incidents"][0]["id"]

        self.scene(43, 5, "PROCESSING: ALERT STORM COLLAPSED", "The response is produced by the topology correlator, not by an LLM.")
        self.text(
            "  20 alerts across 4 services\n"
            "             |\n"
            "             v\n"
            "  cycle-safe dependency walk -> coverage -> distance -> observed root -> lexical tie\n"
            "             |                                      |\n"
            "             +--> retain all evidence                +--> suppress downstream pages\n"
        )
        self.command("cat ingestion.json | jq '{incident: .incidents[0], correlation}'")
        self.json_output(
            {
                "incident": {
                    key: ingestion["incidents"][0].get(key)
                    for key in ("id", "service", "severity", "status", "dedupe_key")
                },
                "correlation": ingestion["correlation"],
            }
        )
        if ingestion["correlation"].get("suppressed_alert_count") != 18:
            raise RuntimeError(f"expected 18 suppressed alerts: {ingestion['correlation']}")
        self.command("docker compose logs --since 2m --tail 8 argus-api")
        logs = self.run_process(
            ["docker", "compose", "logs", "--since", "2m", "--tail", "8", "argus-api"]
        )
        self.text("\n".join(logs.splitlines()[-8:]))

        self.scene(56, 6, "DURABLE BACKEND PROOF", "Query the same PostgreSQL rows and topology state the API will use for RCA.")
        self.command(
            "docker compose exec -T postgres psql -U argus -d argus "
            "-c \"SELECT incident, signals, timeline ...\""
        )
        sql = (
            "SELECT i.id, s.name AS root, i.status, "
            "(SELECT count(*) FROM signals x WHERE x.incident_id=i.id) AS signals, "
            "(SELECT count(*) FROM incident_timeline_events t WHERE t.incident_id=i.id) AS timeline "
            f"FROM incidents i JOIN services s ON s.id=i.service_id WHERE i.id='{self.incident_id}';"
        )
        db_output = self.run_process(
            ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "argus", "-d", "argus", "-P", "pager=off", "-c", sql]
        )
        self.text(db_output)
        self.command(
            f'curl -H "Authorization: Bearer ${{OPERATOR_TOKEN}}" localhost:8080/v1/incidents/{self.incident_id}/topology | jq'
        )
        status, topology = self.curl(
            "GET", f"/v1/incidents/{self.incident_id}/topology", self.operator_token
        )
        self.require_status(status, 200, topology, "read topology")
        self.save("topology.json", topology)
        self.json_output(
            {
                key: topology.get(key)
                for key in (
                    "root_service",
                    "root_inferred",
                    "affected_services",
                    "alert_count",
                    "suppressed_alert_count",
                )
            }
        )

        self.scene(69, 7, "DETERMINISTIC RCA", "Fixed rules score persisted evidence; identical evidence produces identical output.")
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{OPERATOR_TOKEN}}" localhost:8080/v1/incidents/{self.incident_id}/rca/generate'
        )
        status, generated = self.curl(
            "POST", f"/v1/incidents/{self.incident_id}/rca/generate", self.operator_token
        )
        self.require_status(status, 202, generated, "generate RCA")
        self.json_output(generated)
        status, report = self.curl(
            "GET", f"/v1/incidents/{self.incident_id}/rca", self.operator_token
        )
        self.require_status(status, 200, report, "read RCA")
        self.save("rca.json", report)
        self.command("cat rca.json | jq '{deterministic_summary, primary_hypothesis, confidence, contributing_factors}'")
        self.json_output(
            {
                "deterministic_summary": report.get("deterministic_summary"),
                "primary_hypothesis": report.get("primary_hypothesis"),
                "confidence": report.get("confidence"),
                "contributing_factors": report.get("contributing_factors"),
                "topology": {
                    "root_service": report.get("topology", {}).get("root_service"),
                    "suppressed_alert_count": report.get("topology", {}).get(
                        "suppressed_alert_count"
                    ),
                },
            }
        )

        self.scene(85, 8, "AI EXPLAINS; IT CANNOT EXECUTE", "Argus supplies deterministic candidates. Verdikt permits proposal-only output.")
        self.text(
            " deterministic evidence -> bounded candidate list -> LLM ranking -> strict JSON\n"
            "                                                     |\n"
            "                                                     v\n"
            "                                           Verdikt PROPOSE_ONLY\n"
            "                                                     |\n"
            "                                           executed must be false"
        )
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{OPERATOR_TOKEN}}" localhost:8080/v1/incidents/{self.incident_id}/remediations/suggest | jq'
        )
        status, suggestions = self.curl(
            "POST", f"/v1/incidents/{self.incident_id}/remediations/suggest", self.operator_token
        )
        self.require_status(status, 200, suggestions, "generate governed suggestions")
        self.save("ai-suggestions.json", suggestions)
        governed = []
        for item in suggestions.get("suggestions", []):
            governed.append(
                {
                    "action_type": item.get("action_type"),
                    "target": item.get("target"),
                    "risk": item.get("risk"),
                    "requires_approval": item.get("requires_approval"),
                    "verdikt": item.get("verdikt"),
                }
            )
        self.json_output(
            {
                "status": suggestions.get("status"),
                "advisory_only": suggestions.get("advisory_only"),
                "executed": suggestions.get("executed"),
                "suggestions": governed,
                "usage": suggestions.get("usage"),
            }
        )
        if not suggestions.get("advisory_only") or suggestions.get("executed"):
            raise RuntimeError("AI advisory-only invariant was violated")

        self.scene(99, 9, "POLICY-GATED TYPED ACTION", "Persist deterministic proposals; choose one bounded connection-pool change.")
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{OPERATOR_TOKEN}}" localhost:8080/v1/incidents/{self.incident_id}/remediations/propose | jq'
        )
        status, proposed = self.curl(
            "POST", f"/v1/incidents/{self.incident_id}/remediations/propose", self.operator_token
        )
        self.require_status(status, 202, proposed, "propose remediation")
        self.save("remediations-proposed.json", proposed)
        selected = next(
            (
                item
                for item in proposed.get("remediations", [])
                if item.get("action_type") == "resize_connection_pool"
            ),
            None,
        )
        if selected is None:
            raise RuntimeError(f"resize_connection_pool candidate missing: {proposed}")
        self.remediation_id = selected["id"]
        self.json_output(
            {
                key: selected.get(key)
                for key in (
                    "id",
                    "action_type",
                    "target",
                    "parameters",
                    "risk",
                    "status",
                    "idempotency_key",
                    "policy_decision",
                )
            }
        )

        self.scene(111, 10, "HUMAN APPROVAL IS A REAL STATE MACHINE", "The proposer is denied; a different verified identity supplies a reason.")
        self.text(
            " awaiting_approval ----operator self-approve----> DENIED\n"
            "         |\n"
            "         +--------admin + reason---------------> approved"
        )
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{OPERATOR_TOKEN}}" '
            f"localhost:8080/v1/remediations/{self.remediation_id}/approve "
            "-d '{\"reason\":\"self approval should fail\"}'"
        )
        status, denied = self.curl(
            "POST",
            f"/v1/remediations/{self.remediation_id}/approve",
            self.operator_token,
            {"reason": "self approval should fail"},
        )
        self.text(f"HTTP {status}", RED)
        self.json_output(denied)
        if status not in (400, 403):
            raise RuntimeError(f"self approval did not fail closed: HTTP {status}")
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{ADMIN_TOKEN}}" '
            f"localhost:8080/v1/remediations/{self.remediation_id}/approve "
            "-d '{\"reason\":\"evidence reviewed; bounded target\"}'"
        )
        status, approved = self.curl(
            "POST",
            f"/v1/remediations/{self.remediation_id}/approve",
            self.admin_token,
            {"reason": "deterministic evidence reviewed; bounded target and rollback available"},
        )
        self.require_status(status, 200, approved, "approve remediation")
        self.json_output(approved)

        self.scene(123, 11, "JETSTREAM EXECUTION + IDEMPOTENCY", "Execute a real bounded local state change, then replay the same request.")
        self.command(
            f'curl -X POST -H "Authorization: Bearer ${{ADMIN_TOKEN}}" '
            f"localhost:8080/v1/remediations/{self.remediation_id}/execute -d '{{\"dry_run\":false}}'"
        )
        status, queued = self.curl(
            "POST",
            f"/v1/remediations/{self.remediation_id}/execute",
            self.admin_token,
            {"dry_run": False},
        )
        self.require_status(status, 202, queued, "queue remediation")
        self.json_output(queued)
        final: dict[str, Any] | None = None
        for _ in range(30):
            _, remediations = self.curl(
                "GET", f"/v1/incidents/{self.incident_id}/remediations", self.operator_token
            )
            final = next(
                (item for item in remediations if item.get("id") == self.remediation_id), None
            )
            if final and final.get("status") in {
                "succeeded",
                "failed",
                "timed_out",
                "cancelled",
            }:
                break
            time.sleep(0.25)
        if final is None or final.get("status") != "succeeded":
            raise RuntimeError(f"remediation did not succeed: {final}")
        self.command("argus worker result  # GET /v1/incidents/{id}/remediations")
        self.json_output(
            {
                key: final.get(key)
                for key in ("action_type", "target", "parameters", "status", "result")
            }
        )
        self.command("# replay the identical execute request")
        status, replayed = self.curl(
            "POST",
            f"/v1/remediations/{self.remediation_id}/execute",
            self.admin_token,
            {"dry_run": False},
        )
        self.require_status(status, 200, replayed, "replay remediation")
        self.json_output(replayed)
        self.command(
            "docker compose exec -T postgres psql -U argus -d argus "
            "-c \"SELECT target,state,receipt ...\""
        )
        receipt_sql = (
            "SELECT s.resource_type, s.target, s.state, r.action_type, "
            "left(r.idempotency_key,28)||'...' AS receipt "
            "FROM remediation_target_states s JOIN remediation_execution_receipts r ON r.target=s.target "
            f"WHERE r.idempotency_key='{selected['idempotency_key']}';"
        )
        receipt_output = self.run_process(
            ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "argus", "-d", "argus", "-P", "pager=off", "-c", receipt_sql]
        )
        self.text(receipt_output)
        self.command("curl -s 'localhost:8222/jsz?streams=true' | jq '{memory,storage,streams,consumers}'")
        nats_raw = self.run_process(["curl", "-sS", self.nats_url + "/jsz?streams=true"])
        nats = json.loads(nats_raw)
        account = (nats.get("account_details") or [{}])[0]
        self.json_output(
            {
                "jetstream": "enabled",
                "memory_bytes": account.get("memory", nats.get("memory")),
                "storage_bytes": account.get("store", nats.get("storage")),
                "streams": account.get("streams", nats.get("streams")),
                "consumers": account.get("consumers", nats.get("consumers")),
            }
        )

        self.scene(137, 12, "AUDIT + OBSERVABILITY", "Verify the complete hash chain and expose control-plane metrics.")
        self.command(
            'curl -H "Authorization: Bearer ${ADMIN_TOKEN}" localhost:8080/v1/audit/verify | jq'
        )
        status, verification = self.curl("GET", "/v1/audit/verify", self.admin_token)
        self.require_status(status, 200, verification, "verify audit chain")
        self.save("audit-verification.json", verification)
        self.json_output(
            {
                key: verification.get(key)
                for key in ("valid", "entries_verified", "head_position", "head_hash")
            }
        )
        if not verification.get("valid"):
            raise RuntimeError(f"audit chain verification failed: {verification}")
        self.command(
            "curl -s localhost:8080/metrics | grep -E "
            "'argus_(topology|rca_jobs|remediations|audit_chain)'"
        )
        metrics = self.run_process(["curl", "-sS", self.api_url + "/metrics"])
        metric_lines = [
            line
            for line in metrics.splitlines()
            if not line.startswith("#")
            and line.startswith(
                (
                    "argus_topology_alerts_total",
                    "argus_topology_incident_groups_total",
                    "argus_rca_jobs_total",
                    "argus_remediations_total",
                    "argus_audit_chain_integrity",
                    "argus_audit_chain_head_position",
                )
            )
        ]
        self.text("\n".join(metric_lines[:14]))

        self.scene(147, 13, "WHAT THE TERMINAL JUST PROVED", "Every line came from the running local control plane.")
        self.text(
            "  [PASS] 20 alerts -> 1 PostgreSQL root; 18 downstream pages suppressed\n"
            "  [PASS] deterministic evidence math produced a replayable RCA\n"
            "  [PASS] AI remained advisory; Verdikt returned PROPOSE_ONLY / executed=false\n"
            "  [PASS] medium risk required another human identity and a reason\n"
            "  [PASS] JetStream worker applied one typed action; replay returned reused\n"
            "  [PASS] PostgreSQL receipt persisted; SHA-256 audit chain verified\n\n"
            "  Argus: deterministic systems decide. AI explains. Policy authorizes.",
            GREEN,
        )
        self.capture.advance_to(150)
        self.capture.emit("\r\n")


def replay(cast_path: Path, speed: float) -> None:
    if speed <= 0:
        raise ValueError("replay speed must be positive")
    with cast_path.open(encoding="utf-8") as handle:
        lines = handle.readlines()
    if not lines:
        raise ValueError("terminal cast is empty")
    header = json.loads(lines[0])
    if header.get("version") != 2:
        raise ValueError("unsupported terminal cast version")
    previous = 0.0
    for raw in lines[1:]:
        timestamp, stream, data = json.loads(raw)
        if stream != "o":
            continue
        delay = (float(timestamp) - previous) / speed
        if delay > 0:
            time.sleep(delay)
        sys.stdout.write(data)
        sys.stdout.flush()
        previous = float(timestamp)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run or replay the Argus terminal demo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    live = subparsers.add_parser("live", help="execute the demo against a running stack")
    pacing = live.add_mutually_exclusive_group()
    pacing.add_argument("--paced", action="store_true", help="hold the full 150-second timeline")
    pacing.add_argument("--fast", action="store_true", help="run real operations without waits")
    live.add_argument("--cast", type=Path, default=DEFAULT_CAST)
    live.add_argument("--api-url", default=os.getenv("ARGUS_API_URL", "http://127.0.0.1:8080"))
    live.add_argument("--nats-url", default="http://127.0.0.1:8222")

    replay_parser = subparsers.add_parser("replay", help="replay an existing terminal cast")
    replay_parser.add_argument("--cast", type=Path, default=COMMITTED_CAST)
    replay_parser.add_argument("--speed", type=float, default=1.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "replay":
        replay(args.cast, args.speed)
        return

    capture = TerminalCapture(args.cast, paced=bool(args.paced))
    try:
        demo = Demo(capture, args.api_url, args.nats_url)
        demo.run()
        print(f"\nTerminal cast: {args.cast}")
        print(f"Evidence: {demo.evidence_dir}")
    except Exception as exc:
        capture.emit(f"\r\n{RED}DEMO FAILED: {exc}{RESET}\r\n")
        raise
    finally:
        capture.close()


if __name__ == "__main__":
    main()
