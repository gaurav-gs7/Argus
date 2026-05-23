#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-postgres_connection_exhaustion}"

curl -sS -X POST http://localhost:9001/admin/scenarios/activate \
  -H 'Content-Type: application/json' \
  -d "{\"scenario\":\"${SCENARIO}\"}" >/dev/null || true

curl -sS -X POST http://localhost:8080/v1/signals/manual \
  -H 'Content-Type: application/json' \
  -H 'X-Argus-Actor: admin@local' \
  -d "{\"scenario\":\"${SCENARIO}\"}"
