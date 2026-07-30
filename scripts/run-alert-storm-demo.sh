#!/usr/bin/env bash
set -euo pipefail

API_URL="${ARGUS_API_URL:-http://localhost:8080}"
EVIDENCE_DIR="${ARGUS_EVIDENCE_DIR:-artifacts/demo-evidence/topology-alert-storm}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKEN="${ARGUS_PROPOSER_TOKEN:-}"

if [[ -z "${TOKEN}" ]]; then
  TOKEN="$("${SCRIPT_DIR}/oidc-token.sh" operator)"
fi

mkdir -p "${EVIDENCE_DIR}"
PAYLOAD_FILE="${EVIDENCE_DIR}/alert-storm-request.json"

python3 - "${PAYLOAD_FILE}" <<'PY'
import datetime
import json
import sys

services = [
    "nginx", "checkout-api", "payments-api", "nginx", "checkout-api",
    "payments-api", "postgres", "nginx", "checkout-api", "payments-api",
    "nginx", "checkout-api", "payments-api", "postgres", "nginx",
    "checkout-api", "payments-api", "nginx", "checkout-api", "payments-api",
]
started_at = datetime.datetime.now(datetime.timezone.utc)
alerts = []
for index, service in enumerate(services):
    observed_at = started_at + datetime.timedelta(seconds=index)
    alerts.append({
        "status": "firing",
        "labels": {
            "alertname": "DependencyFailure",
            "service": service,
            "environment": "local",
            "severity": "sev2",
        },
        "annotations": {
            "summary": f"{service} is failing requests during the Postgres outage",
        },
        "startsAt": observed_at.isoformat().replace("+00:00", "Z"),
        "fingerprint": f"topology-storm-{index:02d}",
    })

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"status": "firing", "receiver": "topology-demo", "alerts": alerts}, handle, indent=2)
PY

curl -fsS -X POST "${API_URL}/v1/alerts/alertmanager" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  --data-binary "@${PAYLOAD_FILE}" >"${EVIDENCE_DIR}/correlation-response.json"

INCIDENT_ID="$(python3 - "${EVIDENCE_DIR}/correlation-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
incidents = payload.get("incidents", [])
stats = payload.get("correlation", {})
if len(incidents) != 1:
    raise SystemExit(f"expected one root incident, got {len(incidents)}")
if incidents[0].get("service") != "postgres":
    raise SystemExit(f"expected postgres root, got {incidents[0].get('service')}")
if stats.get("alert_count") != 20 or stats.get("suppressed_alert_count") != 18:
    raise SystemExit(f"unexpected correlation stats: {stats}")
print(incidents[0]["id"])
PY
)"

curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  "${API_URL}/v1/incidents/${INCIDENT_ID}/topology" >"${EVIDENCE_DIR}/incident-topology.json"
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  "${API_URL}/v1/incidents/${INCIDENT_ID}/signals" >"${EVIDENCE_DIR}/signals.json"
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  "${API_URL}/v1/incidents/${INCIDENT_ID}/timeline" >"${EVIDENCE_DIR}/timeline.json"
curl -fsS -X POST -H "Authorization: Bearer ${TOKEN}" \
  "${API_URL}/v1/incidents/${INCIDENT_ID}/rca/generate" >"${EVIDENCE_DIR}/rca-generate-response.json"
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  "${API_URL}/v1/incidents/${INCIDENT_ID}/rca" >"${EVIDENCE_DIR}/rca.json"
curl -fsS "${API_URL}/metrics" >"${EVIDENCE_DIR}/argus-metrics.prom"

python3 - "${EVIDENCE_DIR}/incident-topology.json" "${EVIDENCE_DIR}/signals.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    topology = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    signals = json.load(handle)
if topology.get("root_service") != "postgres":
    raise SystemExit(f"unexpected topology root: {topology}")
if topology.get("suppressed_alert_count") != 18:
    raise SystemExit(f"unexpected suppression count: {topology}")
if len(topology.get("affected_services", [])) != 4:
    raise SystemExit(f"unexpected blast radius: {topology}")
if len(signals) != 20:
    raise SystemExit(f"expected all 20 evidence signals, got {len(signals)}")
PY

cat >"${EVIDENCE_DIR}/summary.md" <<EOF
# Argus Topology Alert-Storm Evidence

- Input alerts: 20
- Root incidents: 1
- Root service: postgres
- Downstream alerts suppressed: 18
- Incident: ${INCIDENT_ID}
- Correlation response: ${EVIDENCE_DIR}/correlation-response.json
- Topology analysis: ${EVIDENCE_DIR}/incident-topology.json
- Deterministic RCA: ${EVIDENCE_DIR}/rca.json
- Preserved signals: ${EVIDENCE_DIR}/signals.json
- Timeline: ${EVIDENCE_DIR}/timeline.json
- Metrics: ${EVIDENCE_DIR}/argus-metrics.prom
EOF

echo "Topology demo completed: 20 alerts -> 1 root incident (${INCIDENT_ID}); 18 downstream alerts suppressed."
echo "Evidence directory: ${EVIDENCE_DIR}"
