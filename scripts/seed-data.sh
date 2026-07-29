#!/usr/bin/env bash
set -euo pipefail

docker compose exec -T postgres psql -U argus -d argus <<'SQL'
INSERT INTO users (id, email, name, role)
VALUES
  ('http://localhost:8082/realms/argus#argus-demo-admin-subject', 'admin@argus.local', 'OIDC Demo Admin', 'admin'),
  ('http://localhost:8082/realms/argus#argus-demo-operator-subject', 'operator@argus.local', 'OIDC Demo Operator', 'operator'),
  ('http://localhost:8082/realms/argus#argus-demo-viewer-subject', 'viewer@argus.local', 'OIDC Demo Viewer', 'viewer')
ON CONFLICT (email) DO NOTHING;

INSERT INTO services (id, name, owner, tier, environment)
VALUES ('svc_payments', 'payments-api', 'payments-sre', 'tier0', 'local')
ON CONFLICT (name) DO NOTHING;

INSERT INTO runbooks (id, service_id, title, path, content, version)
VALUES (
  'rb_postgres',
  'svc_payments',
  'Postgres Connection Exhaustion',
  'demo/runbooks/postgres-connection-exhaustion.md',
  'Drain demo connections and restart the demo service if required.',
  1
)
ON CONFLICT (id) DO NOTHING;
SQL

curl -sS -X POST http://localhost:8090/v1/runbooks/index >/dev/null || true
echo "Seeded demo users, services, and runbooks."
