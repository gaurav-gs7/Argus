# Demo Scenarios

Committed evidence snapshots live in [demo-evidence](demo-evidence/README.md). Live demo runs write fresh JSON snapshots under `artifacts/demo-evidence/<scenario>/`.

## PostgreSQL Connection Exhaustion

- symptom: high API latency and 5xx
- evidence: connection timeouts and saturated pool
- expected action: `drain_postgres_connections`, then `restart_service`

## Redis Memory Pressure

- symptom: cache errors and latency
- expected action: `clear_redis_keyspace`

## Nginx 5xx Spike

- symptom: edge 5xx with healthy upstream
- expected action: `rollback_config` and `reload_nginx`

## Dependency Latency

- symptom: traces show downstream span dominance
- expected action: `revert_feature_flag`

## Bad Config Rollout

- symptom: config event precedes parse or connection failures
- expected action: `rollback_config`
