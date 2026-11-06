#!/usr/bin/env bash
set -euo pipefail

TOTAL_MINIMUM="${ARGUS_GO_TOTAL_COVERAGE_MIN:-25.0}"
CORE_MINIMUM="${ARGUS_GO_DECISION_CORE_COVERAGE_MIN:-50.0}"
OUTPUT_DIR="${ARGUS_COVERAGE_DIR:-}"

CORE_PACKAGES=(
  ./internal/actions
  ./internal/auth
  ./internal/config
  ./internal/correlation
  ./internal/policy
  ./internal/rca
  ./internal/remediation
  ./internal/topology
  ./internal/workers
)

if [[ -n "${OUTPUT_DIR}" ]]; then
  mkdir -p "${OUTPUT_DIR}"
  WORK_DIR="${OUTPUT_DIR}"
else
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/argus-coverage.XXXXXX")"
  trap 'rm -rf "${WORK_DIR}"' EXIT
fi

TOTAL_PROFILE="${WORK_DIR}/all.out"
CORE_PROFILE="${WORK_DIR}/decision-core.out"

coverage_total() {
  go tool cover -func="$1" | awk '/^total:/ { value=$3; sub(/%$/, "", value); print value }'
}

enforce_floor() {
  local label="$1"
  local actual="$2"
  local minimum="$3"

  if ! awk -v actual="${actual}" -v minimum="${minimum}" 'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
    printf 'Coverage gate failed: %s is %s%%; required minimum is %s%%.\n' "${label}" "${actual}" "${minimum}" >&2
    return 1
  fi

  printf 'Coverage gate passed: %s is %s%% (minimum %s%%).\n' "${label}" "${actual}" "${minimum}"
}

# With ARGUS_TEST_POSTGRES_DSN set (make integration-coverage), the database
# and JetStream tests run too, so the outbox, reconcilers and worker paths
# that only those tests can exercise count toward the gate. Those tests share
# one database, so packages run one at a time.
PARALLEL=()
if [[ -n "${ARGUS_TEST_POSTGRES_DSN:-}" ]]; then
  PARALLEL=(-p 1)
  echo "Integration services configured: coverage includes PostgreSQL/JetStream tests."
fi

echo "Running repository-wide Go coverage..."
go test -count=1 "${PARALLEL[@]}" -covermode=atomic -coverprofile="${TOTAL_PROFILE}" ./...
TOTAL_COVERAGE="$(coverage_total "${TOTAL_PROFILE}")"
enforce_floor "all Go statements" "${TOTAL_COVERAGE}" "${TOTAL_MINIMUM}"

echo "Running deterministic decision-core Go coverage..."
go test -count=1 "${PARALLEL[@]}" -covermode=atomic -coverprofile="${CORE_PROFILE}" "${CORE_PACKAGES[@]}"
CORE_COVERAGE="$(coverage_total "${CORE_PROFILE}")"
enforce_floor "decision-core statements" "${CORE_COVERAGE}" "${CORE_MINIMUM}"

if [[ -n "${OUTPUT_DIR}" ]]; then
  printf 'Coverage profiles written to %s.\n' "${OUTPUT_DIR}"
fi
