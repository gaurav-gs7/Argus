# Remediation Safety

## Guardrails

- no arbitrary shell commands
- only registered handlers execute work
- every handler supports dry-run
- every state change commits in one transaction with its audit entry; event-only entries are appended separately and failures are counted
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
- action parameters are part of proposal deduplication and idempotency identity
- durable execution receipts make JetStream replay safe
- the job is written to a PostgreSQL outbox in the same transaction as the queue reservation, so a crash or JetStream outage cannot strand a queued remediation without its job
- each job is published once per reservation (`Nats-Msg-Id`), retried with backoff on infrastructure errors, bounded by `ARGUS_WORKER_MAX_DELIVER`, and dead-lettered to `ARGUS_DEAD_LETTER` when malformed or exhausted
- a queued remediation no worker ran, or a running one whose worker died, is re-sent by the reconciler up to `ARGUS_MAX_REDISPATCHES` times, then marked `timed_out` rather than running late; with no live worker for the action it waits instead
- with the Helios executor, a reconciler follows each workflow to its final state, cancels workflows that outlive `ARGUS_HELIOS_MAX_RUNTIME`, and adopts or resubmits submissions lost to an API crash
- admins list, replay, or discard dead letters (`argus deadletter ...`); replay only re-sends a still-queued remediation, and both actions are audited
- a job that exceeds `ARGUS_WORKER_JOB_TIMEOUT` is marked `timed_out` instead of retried, and a worker runs at most `ARGUS_WORKER_CONCURRENCY` jobs at once

## Approved V1 Actions

- `restart_service`
- `rollback_config`
- `reload_nginx`
- `clear_redis_keyspace`
- `drain_postgres_connections`
- `disable_bad_route`
- `revert_feature_flag`
- `restart_pod`
- `resize_connection_pool`
- `toggle_feature_flag`
- `purge_cache`

## Typed Handler Boundaries

| Handler | Target | Parameters | Local execution |
| --- | --- | --- | --- |
| `restart_pod` | `local/<pod>` or `demo/<pod>` | none | Sets a deterministic restart token in durable control state |
| `resize_connection_pool` | service DNS label | `size` from 2 to 50 | Sets an exact desired pool size |
| `toggle_feature_flag` | allow-listed `service/flag` | boolean `enabled` | Sets an exact desired flag state |
| `purge_cache` | scoped `demo:<segment>:*` | `max_keys` from 1 to 1000 | Records a bounded, replay-safe purge intent |

The default laptop profile intentionally uses PostgreSQL-backed control state rather than requiring Kubernetes or another configuration service. Production adapters can map the same typed desired state to Kubernetes patches, a dynamic-config API, or a cache control endpoint. They must retain the same validation and idempotency receipt contract. Arbitrary shell strings are never accepted.

Dry-run reads the current target state and returns the proposed state without writing either target state or an execution receipt. Execute takes advisory locks for both the idempotency key and target, applies the desired state, and stores the receipt in one transaction. Replayed JetStream messages return the original result with `reused: true`.

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

These controls bound what v1 can execute; they do not make external side effects atomic with PostgreSQL. See [Threat Model And Explicit Limitations](threat-model.md) for the crash-window and policy-coverage matrix.
