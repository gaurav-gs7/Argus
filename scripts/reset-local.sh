#!/usr/bin/env bash
set -euo pipefail

docker compose down -v --remove-orphans || true
docker compose up --build -d
curl -sS -X POST http://localhost:9001/admin/reset >/dev/null || true
echo "Argus local environment reset."
