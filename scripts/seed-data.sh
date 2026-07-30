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
VALUES
  ('svc_payments', 'payments-api', 'payments-sre', 'tier0', 'local'),
  ('svc_checkout', 'checkout-api', 'checkout-sre', 'tier0', 'local'),
  ('svc_notification', 'notification-api', 'messaging-sre', 'tier1', 'local'),
  ('svc_postgres', 'postgres', 'database-sre', 'tier0', 'local'),
  ('svc_redis', 'redis', 'database-sre', 'tier1', 'local'),
  ('svc_nginx', 'nginx', 'edge-sre', 'tier0', 'local')
ON CONFLICT (name) DO NOTHING;

INSERT INTO service_dependencies (
  id, service_id, depends_on_service_id, dependency_type, criticality
)
SELECT edge.id, service.id, dependency.id, edge.dependency_type, edge.criticality
FROM (
  VALUES
    ('dep_payments_postgres', 'payments-api', 'postgres', 'datastore', 'critical'),
    ('dep_payments_redis', 'payments-api', 'redis', 'datastore', 'degraded'),
    ('dep_payments_notification', 'payments-api', 'notification-api', 'asynchronous', 'optional'),
    ('dep_checkout_payments', 'checkout-api', 'payments-api', 'synchronous', 'critical'),
    ('dep_nginx_payments', 'nginx', 'payments-api', 'edge', 'critical')
) AS edge(id, service_name, dependency_name, dependency_type, criticality)
JOIN services service ON service.name = edge.service_name
JOIN services dependency ON dependency.name = edge.dependency_name
ON CONFLICT (service_id, depends_on_service_id) DO UPDATE SET
  dependency_type = EXCLUDED.dependency_type,
  criticality = EXCLUDED.criticality;

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
echo "Seeded demo users, service topology, and runbooks."
