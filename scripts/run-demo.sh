#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-postgres_connection_exhaustion}"
API_URL="${ARGUS_API_URL:-http://localhost:8080}"
PAYMENTS_URL="${ARGUS_PAYMENTS_URL:-http://localhost:9001}"
EVIDENCE_DIR="${ARGUS_EVIDENCE_DIR:-artifacts/demo-evidence/${SCENARIO}}"
API_TOKEN="${ARGUS_API_TOKEN:-local-admin-token}"

mkdir -p "${EVIDENCE_DIR}"

echo "Running Argus demo scenario: ${SCENARIO}"
echo "Writing evidence to ${EVIDENCE_DIR}"

if ! curl -sS -X POST "${PAYMENTS_URL}/admin/scenarios/activate" \
  -H 'Content-Type: application/json' \
  -d "{\"scenario\":\"${SCENARIO}\"}" >"${EVIDENCE_DIR}/scenario-activation.json"; then
  printf '{"status":"skipped","reason":"payments-api is not reachable"}\n' >"${EVIDENCE_DIR}/scenario-activation.json"
fi

curl -sS -X POST "${API_URL}/v1/signals/manual" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -d "{\"scenario\":\"${SCENARIO}\"}" >"${EVIDENCE_DIR}/manual-signal-response.json"

INCIDENT_ID="$(python3 - "${EVIDENCE_DIR}/manual-signal-response.json" <<'INNER_PY'
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    payload = json.load(handle)
incidents = payload.get('incidents', [])
print(incidents[0].get('id', '') if incidents else '')
INNER_PY
)"

if [[ -z "${INCIDENT_ID}" ]]; then
  echo "No incident id returned by Argus API. See ${EVIDENCE_DIR}/manual-signal-response.json"
  exit 1
fi

curl -sS -X POST "${API_URL}/v1/incidents/${INCIDENT_ID}/rca/generate" \
  -H "Authorization: Bearer ${API_TOKEN}" >"${EVIDENCE_DIR}/rca-generate-response.json"

curl -sS -X POST "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations/propose" \
  -H "Authorization: Bearer ${API_TOKEN}" >"${EVIDENCE_DIR}/remediation-propose-response.json"

curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}" >"${EVIDENCE_DIR}/incident.json"
curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/timeline" >"${EVIDENCE_DIR}/timeline.json"
curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/signals" >"${EVIDENCE_DIR}/signals.json"
curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/rca" >"${EVIDENCE_DIR}/rca.json"
curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations" >"${EVIDENCE_DIR}/remediations.json"
curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/audit" >"${EVIDENCE_DIR}/audit.json"

cat >"${EVIDENCE_DIR}/summary.md" <<EOF
# Argus Demo Evidence: ${SCENARIO}

- Incident: ${INCIDENT_ID}
- RCA: ${EVIDENCE_DIR}/rca.json
- Remediations: ${EVIDENCE_DIR}/remediations.json
- Timeline: ${EVIDENCE_DIR}/timeline.json
- Audit: ${EVIDENCE_DIR}/audit.json
EOF

cat <<EOF
Demo completed.
Incident: ${INCIDENT_ID}
Evidence directory: ${EVIDENCE_DIR}
EOF
