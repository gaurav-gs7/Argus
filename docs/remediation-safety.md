# Remediation Safety

## Guardrails

- no arbitrary shell commands
- only registered handlers execute work
- every handler supports dry-run
- every state mutation is audited
- high-risk actions are denied
- medium-risk actions require approval
- approval requests are durable and bound to one exact remediation
- approval and denial require an authenticated identity plus a reason
- proposer/approver separation is enforced by default
- decision, remediation transition, and audit records commit atomically
- pending requests escalate once and expire to `timed_out`
- webhook notifications are HTTPS-only outside loopback and can be HMAC-signed
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

## Approval State Machine

```text
awaiting_approval
  |-- approve by another operator/admin --> approved
  |-- deny by another operator/admin ----> rejected
  |-- operator cancellation -------------> cancelled
  `-- deadline reached ------------------> timed_out
```

Notification delivery never grants authority. Generic webhooks only carry the bounded request and authenticated decision endpoint. Slack decisions additionally require Slack's signing-secret HMAC, a fresh timestamp, an allow-listed Slack user mapped to an Argus identity, and a non-empty modal reason. PostgreSQL remains the source of truth if notification delivery is retried or unavailable.

Defaults are intentionally laptop-friendly: one goroutine sweeps every 15 seconds, no extra container is required, and an empty webhook URL leaves requests queryable through the API/CLI. For a generic webhook, set `ARGUS_APPROVAL_WEBHOOK_SECRET` so receivers can verify `X-Argus-Signature-256`. Slack uses a free incoming webhook plus a free Slack app for signed interactivity; it does not add a local service.
