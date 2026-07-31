#!/usr/bin/env bash
set -euo pipefail

API_URL="${ARGUS_API_URL:-http://localhost:8080}"
EVIDENCE_DIR="${ARGUS_EVIDENCE_DIR:-artifacts/demo-evidence/typed-remediation-handlers}"
WORKER_TIMEOUT_SECONDS="${ARGUS_WORKER_TIMEOUT_SECONDS:-30}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROPOSER_TOKEN="${ARGUS_PROPOSER_TOKEN:-$("${SCRIPT_DIR}/oidc-token.sh" operator)}"
APPROVER_TOKEN="${ARGUS_APPROVER_TOKEN:-$("${SCRIPT_DIR}/oidc-token.sh" admin)}"

mkdir -p "${EVIDENCE_DIR}"

run_action() {
  local scenario="$1"
  local action="$2"
  local prefix="${EVIDENCE_DIR}/${action}"

  curl -fsS -X POST "${API_URL}/v1/signals/manual" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
    -d "{\"scenario\":\"${scenario}\"}" >"${prefix}-incident.json"

  local incident_id
  incident_id="$(python3 - "${prefix}-incident.json" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(payload["incidents"][0]["id"])
PY
)"

  curl -fsS -X POST \
    -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
    "${API_URL}/v1/incidents/${incident_id}/remediations/propose" >"${prefix}-proposal.json"

  local remediation_id
  remediation_id="$(python3 - "${prefix}-proposal.json" "${action}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
match = next((item for item in payload["remediations"] if item["action_type"] == sys.argv[2]), None)
if match is None:
    raise SystemExit(f"missing typed remediation {sys.argv[2]}")
if match["status"] != "awaiting_approval":
    raise SystemExit(f"typed remediation did not require approval: {match}")
if not match.get("idempotency_key") or "parameters" not in match:
    raise SystemExit(f"typed remediation is missing safety identity: {match}")
print(match["id"])
PY
)"

  curl -fsS -X POST "${API_URL}/v1/remediations/${remediation_id}/approve" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    -d "{\"reason\":\"Validated bounded parameters for ${action}\"}" >"${prefix}-approval.json"

  curl -fsS -X POST "${API_URL}/v1/remediations/${remediation_id}/execute" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    -d '{"dry_run":false}' >"${prefix}-execute.json"

  local status=""
  for ((second = 0; second < WORKER_TIMEOUT_SECONDS; second++)); do
    curl -fsS -H "Authorization: Bearer ${PROPOSER_TOKEN}" \
      "${API_URL}/v1/incidents/${incident_id}/remediations" >"${prefix}-result.json"
    status="$(python3 - "${prefix}-result.json" "${remediation_id}" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
match = next((item for item in items if item["id"] == sys.argv[2]), {})
print(match.get("status", ""))
PY
)"
    [[ "${status}" == "succeeded" ]] && break
    [[ "${status}" == "failed" ]] && break
    sleep 1
  done
  [[ "${status}" == "succeeded" ]] || {
    echo "${action} finished with status ${status:-unknown}" >&2
    return 1
  }

  python3 - "${prefix}-result.json" "${remediation_id}" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
match = next(item for item in items if item["id"] == sys.argv[2])
result = match.get("result", {})
if result.get("backend") != "durable-local-control-state" or result.get("mode") != "execute":
    raise SystemExit(f"unexpected typed handler result: {result}")
PY

  local replay_code
  replay_code="$(curl -sS -o "${prefix}-replay.json" -w '%{http_code}' \
    -X POST "${API_URL}/v1/remediations/${remediation_id}/execute" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    -d '{"dry_run":false}')"
  [[ "${replay_code}" == "200" ]]
  grep -q '"status":"reused"' "${prefix}-replay.json"

  while IFS= read -r pending_id; do
    [[ -z "${pending_id}" ]] && continue
    curl -fsS -X POST \
      -H "Authorization: Bearer ${APPROVER_TOKEN}" \
      "${API_URL}/v1/remediations/${pending_id}/cancel" >/dev/null
  done < <(python3 - "${prefix}-result.json" "${remediation_id}" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
for item in items:
    if item["id"] != sys.argv[2] and item["status"] == "awaiting_approval":
        print(item["id"])
PY
)

  curl -fsS -X POST \
    -H "Authorization: Bearer ${APPROVER_TOKEN}" \
    "${API_URL}/v1/incidents/${incident_id}/resolve" >"${prefix}-resolve.json"
  echo "${action}: succeeded; replay reused"
}

run_action postgres_connection_exhaustion resize_connection_pool
run_action postgres_connection_exhaustion restart_pod
run_action redis_memory_pressure purge_cache
run_action dependency_latency toggle_feature_flag

curl -fsS -H "Authorization: Bearer ${APPROVER_TOKEN}" \
  "${API_URL}/v1/audit/verify" >"${EVIDENCE_DIR}/audit-verification.json"
python3 - "${EVIDENCE_DIR}/audit-verification.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if not report.get("valid"):
    raise SystemExit(f"audit chain verification failed: {report}")
print(f"Typed remediation demo complete; audit entries verified: {report['entries_verified']}")
PY

echo "Evidence directory: ${EVIDENCE_DIR}"
