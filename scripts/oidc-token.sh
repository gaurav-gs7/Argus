#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"
TOKEN_URL="${ARGUS_OIDC_TOKEN_URL:-http://localhost:8082/realms/argus/protocol/openid-connect/token}"

case "${ROLE}" in
  admin)
    CLIENT_ID="${ARGUS_DEMO_ADMIN_CLIENT_ID:-argus-demo-admin}"
    CLIENT_SECRET="${ARGUS_DEMO_ADMIN_CLIENT_SECRET:-argus-local-admin-client-secret}"
    ;;
  operator)
    CLIENT_ID="${ARGUS_DEMO_OPERATOR_CLIENT_ID:-argus-demo-operator}"
    CLIENT_SECRET="${ARGUS_DEMO_OPERATOR_CLIENT_SECRET:-argus-local-operator-client-secret}"
    ;;
  viewer)
    CLIENT_ID="${ARGUS_DEMO_VIEWER_CLIENT_ID:-argus-demo-viewer}"
    CLIENT_SECRET="${ARGUS_DEMO_VIEWER_CLIENT_SECRET:-argus-local-viewer-client-secret}"
    ;;
  *)
    echo "usage: $0 <admin|operator|viewer>" >&2
    exit 2
    ;;
esac

RESPONSE="$(
  curl --fail-with-body --silent --show-error \
    --request POST "${TOKEN_URL}" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}"
)"

python3 -c '
import json
import sys

payload = json.load(sys.stdin)
token = payload.get("access_token", "")
if token.count(".") != 2:
    raise SystemExit("OIDC provider did not return a JWT access token")
print(token)
' <<<"${RESPONSE}"
