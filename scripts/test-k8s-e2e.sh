#!/usr/bin/env bash
# End-to-end test of the Helm chart on a kind cluster (CI job kubernetes-e2e).
#
# Proves, on a real cluster: the migrate init container applies the schema
# and the API and worker start in verify mode; the API serves and enforces
# authentication; a rolling upgrade and a helm rollback complete; pods of
# this release start against a newer *compatible* schema (what a rollback
# after a migration looks like) and refuse a newer *breaking* one.
#
# Expects: kind cluster in the current context, images argus-api:e2e and
# argus-worker:e2e loaded, deploy/kind/dependencies.yaml applied.
set -euo pipefail

NS=argus
RELEASE=argus
VALUES=deploy/helm/argus/ci/kind-values.yaml
PF_PID=""

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT
psql_q() { kubectl -n "$NS" exec deploy/postgres -- psql -U argus -d argus -Atc "$1"; }
rollout() { kubectl -n "$NS" rollout status "deploy/$1" --timeout=180s; }

echo "== dependencies"
rollout postgres
rollout nats

echo "== runtime secret"
kubectl -n "$NS" create secret generic argus-runtime \
  --from-literal=ARGUS_POSTGRES_DSN='postgres://argus:argus@postgres:5432/argus?sslmode=disable' \
  --from-literal=ARGUS_NATS_URL='nats://nats:4222' \
  --dry-run=client -o yaml | kubectl apply -f -

echo "== install"
helm install "$RELEASE" deploy/helm/argus -n "$NS" -f "$VALUES" --wait --timeout 6m
rollout argus-api
rollout argus-worker

echo "== migrations ran in the init container, not in the app containers"
migrate_log=$(kubectl -n "$NS" logs deploy/argus-api -c migrate)
grep -q '"applied schema migration"' <<<"$migrate_log" || grep -q '"schema is up to date"' <<<"$migrate_log" || fail "migrate init container log: $migrate_log"
[[ "$(kubectl -n "$NS" get configmap argus-control-plane -o jsonpath='{.data.ARGUS_MIGRATIONS}')" == "verify" ]] || fail "app containers are not in verify mode"
versions=$(psql_q "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations")
expected=$(ls migrations/*.sql | wc -l | tr -d ' ')
[[ "$(tr ',' '\n' <<<"$versions" | wc -l | tr -d ' ')" == "$expected" ]] || fail "schema_migrations=$versions, expected $expected versions"
echo "schema_migrations: $versions"

echo "== API serves and enforces authentication"
kubectl -n "$NS" port-forward svc/argus-api 18080:8080 >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break; sleep 1; done
[[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/readyz)" == "200" ]] || fail "/readyz"
[[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/v1/incidents)" == "401" ]] || fail "unauthenticated /v1/incidents was not 401"
kill "$PF_PID"; PF_PID=""

echo "== rolling upgrade and rollback"
helm upgrade "$RELEASE" deploy/helm/argus -n "$NS" -f "$VALUES" --set-string global.podAnnotations.e2e-revision=2 --wait --timeout 6m
rollout argus-api
helm rollback "$RELEASE" 1 -n "$NS" --wait --timeout 6m
rollout argus-api
rollout argus-worker

echo "== this release against a newer compatible schema (rollback after a migration)"
future=$((expected + 1))
psql_q "INSERT INTO schema_migrations (version, name, checksum, breaking) VALUES ($future, 'from_a_newer_release', repeat('0', 64), false)"
kubectl -n "$NS" rollout restart deploy/argus-api deploy/argus-worker
rollout argus-api
rollout argus-worker
kubectl -n "$NS" logs deploy/argus-worker | grep -q 'non-breaking migrations from a newer build' || fail "worker did not report the newer compatible schema"

echo "== this release against a newer breaking schema"
psql_q "UPDATE schema_migrations SET breaking = true WHERE version = $future"
kubectl -n "$NS" rollout restart deploy/argus-worker
refused=""
for _ in $(seq 1 60); do
  pod=$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=worker --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
  if kubectl -n "$NS" logs "$pod" 2>/dev/null | grep -q 'breaking migration newer than this build' \
     || kubectl -n "$NS" logs "$pod" --previous 2>/dev/null | grep -q 'breaking migration newer than this build'; then
    refused="$pod"; break
  fi
  sleep 2
done
[[ -n "$refused" ]] || fail "worker started against a breaking newer schema"
[[ "$(kubectl -n "$NS" get pod "$refused" -o jsonpath='{.status.containerStatuses[0].ready}')" != "true" ]] || fail "$refused is ready against a breaking schema"
echo "refused by $refused, as intended"

psql_q "DELETE FROM schema_migrations WHERE version = $future"
kubectl -n "$NS" rollout restart deploy/argus-worker
rollout argus-worker
echo "PASS"
