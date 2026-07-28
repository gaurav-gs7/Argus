#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-postgres_connection_exhaustion}"
API_URL="${ARGUS_API_URL:-http://localhost:8080}"
PAYMENTS_URL="${ARGUS_PAYMENTS_URL:-http://localhost:9001}"
EVIDENCE_DIR="${ARGUS_EVIDENCE_DIR:-artifacts/demo-evidence/${SCENARIO}}"
PROPOSER_TOKEN="${ARGUS_PROPOSER_TOKEN:-local-operator-token}"
APPROVER_TOKEN="${ARGUS_APPROVER_TOKEN:-local-admin-token}"
WORKER_TIMEOUT_SECONDS="${ARGUS_WORKER_TIMEOUT_SECONDS:-30}"

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
  -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
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
  -H "Authorization: Bearer ${PROPOSER_TOKEN}" >"${EVIDENCE_DIR}/rca-generate-response.json"

curl -sS -X POST "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations/propose" \
  -H "Authorization: Bearer ${PROPOSER_TOKEN}" >"${EVIDENCE_DIR}/remediation-propose-response.json"

curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}" >"${EVIDENCE_DIR}/incident.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/timeline" >"${EVIDENCE_DIR}/timeline.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/signals" >"${EVIDENCE_DIR}/signals.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/rca" >"${EVIDENCE_DIR}/rca.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations" >"${EVIDENCE_DIR}/remediations-before-approval.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/approval-requests?status=pending" >"${EVIDENCE_DIR}/approval-requests-before.json"

REMEDIATION_ID="$(python3 - "${EVIDENCE_DIR}/remediations-before-approval.json" <<'INNER_PY'
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    remediations = json.load(handle)
match = next((item for item in remediations if item.get('status') == 'awaiting_approval'), {})
print(match.get('id', ''))
INNER_PY
)"

if [[ -n "${REMEDIATION_ID}" ]]; then
  SELF_APPROVAL_CODE="$(curl -sS -o "${EVIDENCE_DIR}/self-approval-denied.json" -w '%{http_code}' \
    -X POST "${API_URL}/v1/remediations/${REMEDIATION_ID}/approve" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
    -d '{"reason":"Self approval must fail closed"}')"
  printf '{"http_status":%s}\n' "${SELF_APPROVAL_CODE}" >"${EVIDENCE_DIR}/self-approval-status.json"

  curl -sS -X POST "${API_URL}/v1/remediations/${REMEDIATION_ID}/approve" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    -d '{"reason":"Reviewed deterministic evidence; dry-run is bounded to the demo service"}' \
    >"${EVIDENCE_DIR}/approval-decision.json"

  curl -sS -X POST "${API_URL}/v1/remediations/${REMEDIATION_ID}/execute" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    -d '{"dry_run":true}' >"${EVIDENCE_DIR}/remediation-execute.json"

  REMEDIATION_STATUS=""
  for ((second = 0; second < WORKER_TIMEOUT_SECONDS; second++)); do
    curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
      "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations" \
      >"${EVIDENCE_DIR}/remediations-after-execution.json"
    REMEDIATION_STATUS="$(python3 - "${EVIDENCE_DIR}/remediations-after-execution.json" "${REMEDIATION_ID}" <<'INNER_PY'
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    remediations = json.load(handle)
match = next((item for item in remediations if item.get('id') == sys.argv[2]), {})
print(match.get('status', ''))
INNER_PY
)"
    case "${REMEDIATION_STATUS}" in
      succeeded | failed | timed_out | cancelled)
        break
        ;;
    esac
    sleep 1
  done

  if [[ "${REMEDIATION_STATUS}" != "succeeded" ]]; then
    echo "Remediation ${REMEDIATION_ID} did not succeed within ${WORKER_TIMEOUT_SECONDS}s (status=${REMEDIATION_STATUS:-unknown})."
    exit 1
  fi
fi

curl -sS -X POST "${PAYMENTS_URL}/admin/reset" >"${EVIDENCE_DIR}/scenario-reset.json"
curl -sS "${PAYMENTS_URL}/healthz" >"${EVIDENCE_DIR}/recovery-health.json"
curl -sS -X POST "${API_URL}/v1/incidents/${INCIDENT_ID}/resolve" \
  -H "Authorization: Bearer ${APPROVER_TOKEN}" >"${EVIDENCE_DIR}/incident-resolve.json"

curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}" >"${EVIDENCE_DIR}/incident.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations" >"${EVIDENCE_DIR}/remediations.json"
curl -sS -H "Authorization: Bearer ${PROPOSER_TOKEN}" "${API_URL}/v1/approval-requests" >"${EVIDENCE_DIR}/approval-requests-after.json"
curl -sS -H "Authorization: Bearer ${APPROVER_TOKEN}" "${API_URL}/v1/audit" >"${EVIDENCE_DIR}/audit.json"
curl -sS "${API_URL}/metrics" >"${EVIDENCE_DIR}/argus-metrics.prom"
curl -sS "${PAYMENTS_URL}/metrics" >"${EVIDENCE_DIR}/payments-metrics.prom"

cat >"${EVIDENCE_DIR}/summary.md" <<EOF
# Argus Demo Evidence: ${SCENARIO}

- Incident: ${INCIDENT_ID}
- RCA: ${EVIDENCE_DIR}/rca.json
- Remediations: ${EVIDENCE_DIR}/remediations.json
- Approval requests: ${EVIDENCE_DIR}/approval-requests-after.json
- Self-approval rejection: ${EVIDENCE_DIR}/self-approval-denied.json
- Approval decision: ${EVIDENCE_DIR}/approval-decision.json
- Worker result: ${EVIDENCE_DIR}/remediations-after-execution.json
- Recovery health: ${EVIDENCE_DIR}/recovery-health.json
- Incident resolution: ${EVIDENCE_DIR}/incident-resolve.json
- Timeline: ${EVIDENCE_DIR}/timeline.json
- Audit: ${EVIDENCE_DIR}/audit.json
- Metrics: ${EVIDENCE_DIR}/argus-metrics.prom
EOF

cat <<EOF
Demo completed.
Incident: ${INCIDENT_ID}
Evidence directory: ${EVIDENCE_DIR}
EOF
