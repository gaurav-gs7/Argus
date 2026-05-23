#!/usr/bin/env bash
set -euo pipefail

INCIDENT_ID="${1:-}"
if [[ -z "${INCIDENT_ID}" ]]; then
  echo "usage: $0 <incident_id>"
  exit 1
fi

INCIDENT="$(curl -sS "http://localhost:8080/v1/incidents/${INCIDENT_ID}")"
RCA="$(curl -sS "http://localhost:8080/v1/incidents/${INCIDENT_ID}/rca")"
TIMELINE="$(curl -sS "http://localhost:8080/v1/incidents/${INCIDENT_ID}/timeline")"
REMEDIATIONS="$(curl -sS "http://localhost:8080/v1/incidents/${INCIDENT_ID}/remediations")"

curl -sS -X POST http://localhost:8090/v1/report/generate \
  -H 'Content-Type: application/json' \
  -d "{
    \"incident\": ${INCIDENT},
    \"timeline\": ${TIMELINE},
    \"rca\": ${RCA},
    \"remediations\": ${REMEDIATIONS}
  }"
