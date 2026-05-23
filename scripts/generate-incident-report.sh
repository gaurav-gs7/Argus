#!/usr/bin/env bash
set -euo pipefail

INCIDENT_ID="${1:-}"
API_URL="${ARGUS_API_URL:-http://localhost:8080}"
AI_URL="${ARGUS_AI_URL:-http://localhost:8090}"
API_TOKEN="${ARGUS_API_TOKEN:-local-admin-token}"
if [[ -z "${INCIDENT_ID}" ]]; then
  echo "usage: $0 <incident_id>"
  exit 1
fi

INCIDENT="$(curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}")"
RCA="$(curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/rca")"
TIMELINE="$(curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/timeline")"
REMEDIATIONS="$(curl -sS -H "Authorization: Bearer ${API_TOKEN}" "${API_URL}/v1/incidents/${INCIDENT_ID}/remediations")"

curl -sS -X POST "${AI_URL}/v1/report/generate" \
  -H 'Content-Type: application/json' \
  -d "{
    \"incident\": ${INCIDENT},
    \"timeline\": ${TIMELINE},
    \"rca\": ${RCA},
    \"remediations\": ${REMEDIATIONS}
  }"
