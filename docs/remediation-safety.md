# Remediation Safety

## Guardrails

- no arbitrary shell commands
- only registered handlers execute work
- every handler supports dry-run
- every state mutation is audited
- high-risk actions are denied
- medium-risk actions require approval
- repeated failures trigger policy denial
- idempotency keys prevent duplicate execution

## Approved V1 Actions

- `restart_service`
- `rollback_config`
- `reload_nginx`
- `clear_redis_keyspace`
- `drain_postgres_connections`
- `disable_bad_route`
- `revert_feature_flag`
