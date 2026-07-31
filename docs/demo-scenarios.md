# Demo Scenarios

Committed evidence snapshots live in [demo-evidence](demo-evidence/README.md). Live demo runs write fresh JSON snapshots under `artifacts/demo-evidence/<scenario>/`.

`make demo-typed-remediations` exercises pod restart, connection-pool resize, feature-flag toggle, and cache purge through real OIDC identities, approval, JetStream delivery, worker execution, replay, and audit-chain verification.

## Topology Alert Storm

- input: twenty alerts across Nginx, checkout, payments, and PostgreSQL
- topology: Nginx and checkout depend on payments; payments depends on PostgreSQL
- expected correlation: one observed PostgreSQL-root incident
- expected suppression: eighteen downstream alert deliveries stay as evidence without opening incidents
- run: `make demo-alert-storm`

## PostgreSQL Connection Exhaustion

- symptom: high API latency and 5xx
- evidence: connection timeouts and saturated pool
- expected actions: `drain_postgres_connections`, bounded `resize_connection_pool`, or `restart_pod`

## Redis Memory Pressure

- symptom: cache errors and latency
- expected action: bounded `purge_cache` for `demo:pressure:*`

## Nginx 5xx Spike

- symptom: edge 5xx with healthy upstream
- expected action: `rollback_config` and `reload_nginx`

## Dependency Latency

- symptom: traces show downstream span dominance
- expected action: `toggle_feature_flag` to the explicit disabled state

## Bad Config Rollout

- symptom: config event precedes parse or connection failures
- expected action: `rollback_config`, then `restart_pod`
