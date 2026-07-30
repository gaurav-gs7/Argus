#!/usr/bin/env bash
set -euo pipefail

API_URL="${ARGUS_API_URL:-http://localhost:8080}"
OIDC_ISSUER="${ARGUS_OIDC_ISSUER_URL:-http://localhost:8082/realms/argus}"
OIDC_AUDIENCE="${ARGUS_OIDC_AUDIENCE:-argus-api}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

wait_for_url() {
  local url="$1"
  for _ in {1..90}; do
    if curl --fail --silent --output /dev/null "${url}"; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for ${url}" >&2
  return 1
}

assert_code() {
  local label="$1"
  local want="$2"
  local got="$3"
  if [[ "${got}" != "${want}" ]]; then
    echo "${label}: got HTTP ${got}, want ${want}" >&2
    exit 1
  fi
}

wait_for_url "${ARGUS_OIDC_TOKEN_URL:-http://localhost:8082/realms/argus}/.well-known/openid-configuration"
wait_for_url "${API_URL}/readyz"

viewer="$("${SCRIPT_DIR}/oidc-token.sh" viewer)"
operator="$("${SCRIPT_DIR}/oidc-token.sh" operator)"
admin="$("${SCRIPT_DIR}/oidc-token.sh" admin)"

for role in viewer operator admin; do
  token_variable="${role}"
  token="${!token_variable}"
  ROLE="${role}" TOKEN="${token}" ISSUER="${OIDC_ISSUER}" AUDIENCE="${OIDC_AUDIENCE}" python3 - <<'PY'
import base64
import json
import os
import time

encoded = os.environ["TOKEN"].split(".")[1]
encoded += "=" * (-len(encoded) % 4)
claims = json.loads(base64.urlsafe_b64decode(encoded))
assert claims["iss"] == os.environ["ISSUER"]
assert claims["aud"] == os.environ["AUDIENCE"]
assert claims["exp"] - int(time.time()) <= 300
assert claims["exp"] > int(time.time())
assert claims["realm_access"]["roles"] == [f"argus-{os.environ['ROLE']}"]
assert claims["sub"]
PY

  principal="$(
    curl --fail --silent \
      --header "Authorization: Bearer ${token}" \
      "${API_URL}/v1/auth/me"
  )"
  ROLE="${role}" PRINCIPAL="${principal}" python3 - <<'PY'
import json
import os

principal = json.loads(os.environ["PRINCIPAL"])
assert principal["role"] == os.environ["ROLE"]
assert principal["id"] == principal["issuer"] + "#" + principal["subject"]
PY
done

unauth="$(
  curl --silent --output "${TMP_DIR}/unauth.json" --write-out '%{http_code}' \
    "${API_URL}/v1/incidents"
)"
viewer_read="$(
  curl --silent --output "${TMP_DIR}/viewer-read.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${viewer}" \
    "${API_URL}/v1/incidents"
)"
viewer_write="$(
  curl --silent --output "${TMP_DIR}/viewer-write.json" --write-out '%{http_code}' \
    --request POST \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer ${viewer}" \
    --data '{"name":"oidc-viewer-must-not-create"}' \
    "${API_URL}/v1/services"
)"
operator_action="$(
  curl --silent --output "${TMP_DIR}/operator-action.json" --write-out '%{http_code}' \
    --request POST \
    --header "Authorization: Bearer ${operator}" \
    "${API_URL}/v1/runbooks/reindex"
)"
admin_action="$(
  curl --silent --output "${TMP_DIR}/admin-action.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${admin}" \
    "${API_URL}/v1/audit"
)"
operator_audit_verify="$(
  curl --silent --output "${TMP_DIR}/operator-audit-verify.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${operator}" \
    "${API_URL}/v1/audit/verify"
)"
admin_audit_verify="$(
  curl --silent --output "${TMP_DIR}/admin-audit-verify.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${admin}" \
    "${API_URL}/v1/audit/verify"
)"

IFS='.' read -r token_header token_payload token_signature <<<"${viewer}"
replacement="A"
if [[ "${token_signature:0:1}" == "A" ]]; then
  replacement="B"
fi
tampered="${token_header}.${token_payload}.${replacement}${token_signature:1}"
tampered_code="$(
  curl --silent --output "${TMP_DIR}/tampered.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${tampered}" \
    "${API_URL}/v1/incidents"
)"

assert_code "missing token" 401 "${unauth}"
assert_code "viewer read" 200 "${viewer_read}"
assert_code "viewer mutation" 403 "${viewer_write}"
assert_code "operator action" 202 "${operator_action}"
assert_code "admin action" 200 "${admin_action}"
assert_code "operator audit verification" 403 "${operator_audit_verify}"
assert_code "admin audit verification" 200 "${admin_audit_verify}"
assert_code "tampered signature" 401 "${tampered_code}"

AUDIT_VERIFICATION="${TMP_DIR}/admin-audit-verify.json" python3 - <<'PY'
import json
import os

with open(os.environ["AUDIT_VERIFICATION"], encoding="utf-8") as handle:
    verification = json.load(handle)
assert verification["valid"] is True
assert verification["entries_verified"] == verification["head_position"]
assert len(verification["head_hash"]) == 64
PY

metrics="$(curl --fail --silent "${API_URL}/metrics")"
grep -q 'argus_authentication_failures_total{reason="invalid_token"}' <<<"${metrics}"
grep -q 'argus_authentication_failures_total{reason="missing_bearer_token"}' <<<"${metrics}"
grep -q 'argus_authorization_denials_total{permission="manage_service",role="viewer"}' <<<"${metrics}"
grep -q 'argus_authorization_denials_total{permission="view_audit",role="operator"}' <<<"${metrics}"
grep -q 'argus_audit_verifications_total{result="valid"}' <<<"${metrics}"
grep -q '^argus_audit_chain_integrity 1$' <<<"${metrics}"

printf 'OIDC E2E passed: unauth=%s viewer_read=%s viewer_write=%s operator=%s admin=%s audit_verify=%s tampered=%s\n' \
  "${unauth}" "${viewer_read}" "${viewer_write}" "${operator_action}" "${admin_action}" \
  "${admin_audit_verify}" "${tampered_code}"
