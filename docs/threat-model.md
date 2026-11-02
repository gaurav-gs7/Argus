# Threat Model And Explicit Limitations

## Status

This document describes the behavior implemented by Argus v1, not an aspirational production architecture. Argus demonstrates deterministic incident handling and bounded remediation on a single-laptop profile. It has not been certified for production, PCI DSS, SOC 2, or any other compliance regime.

The core safety claim is narrow: an LLM cannot invoke remediation, typed local handlers reject unbounded input, medium-risk actions require an identified second person, high-risk actions are denied, and replay of a completed local action reuses a durable receipt. Availability, exactly-once delivery across independent systems, and external-provider correctness remain separate concerns.

## Assets And Safety Goals

| Asset | Safety goal |
| --- | --- |
| Incident record and evidence | Preserve every accepted signal, correlate deterministically, and avoid silently converting advisory text into fact |
| Remediation authority | Permit only registered action types with bounded targets and parameters |
| Approval identity | Bind the decision, reason, and immutable OIDC `issuer#subject` to the exact proposal |
| Execution | Make retries safe and prevent duplicate local side effects |
| Audit ledger | Detect row mutation, deletion, reordering, and missing tails under the application database role |
| AI advice | Treat model output and retrieved operational text as untrusted proposals, never execution instructions |

## Trust Boundaries

| Boundary | Assumption | Failure or attacker considered |
| --- | --- | --- |
| Alertmanager, logs, traces, runbooks | Payload text is untrusted and may contain prompt injection or misleading evidence | Crafted alert annotations must not bypass candidate allow-lists, policy, approval, or typed handlers |
| OIDC provider | Issuer keys and mapped role claims are authoritative | Invalid issuer, audience, signature, expiry, or role must fail authentication; MFA and account lifecycle remain IdP responsibilities |
| Slack approval callback | Slack signing secret and timestamp validation establish callback authenticity | Replays, unsigned callbacks, unknown Slack users, self-approval, and empty reasons are denied |
| PostgreSQL | Application role cannot alter immutable audit rows outside approved functions | Outage, transaction rollback, and partial multi-transaction workflows are considered; a compromised database owner is not contained |
| NATS JetStream | Acknowledged file-backed stream persists messages on the local node; Argus owns two streams, `ARGUS_REMEDIATION` (7-day retention) and `ARGUS_DEAD_LETTER` (30 days) | Disconnects, duplicate publishes, worker redelivery, poison jobs, and retry exhaustion are considered; loss of the single node and cross-system atomicity are not solved |
| Worker adapters | Local PostgreSQL-backed adapters honor the receipt transaction | Real Kubernetes, Redis, Nginx, or database APIs must independently provide idempotency and scoped credentials |
| AI service, Ollama, Gemini, Verdikt | All model output is untrusted; Verdikt is a proposal-only policy boundary; every AI service route except `/healthz` and `/metrics` requires the shared `ARGUS_AI_SERVICE_TOKEN`, which has no default (the service refuses to start without one, and Argus refuses an AI service URL without one) | Unavailable or malformed advisory output fails closed and cannot block deterministic ingestion/RCA; an empty Verdikt token fails governance closed; the shared token is not per-caller identity |
| Helios | Accepts the same typed intent and idempotency key | The current integration is a safe simulated workflow, not a production remediation provider |

## Dependency And Crash Semantics

| Failure point | Current behavior | Residual risk |
| --- | --- | --- |
| PostgreSQL unavailable before incident write | Ingestion fails; no in-memory incident is treated as durable | Alertmanager must retry; Argus does not ship an ingress spool |
| PostgreSQL fails during incident ingestion | The whole delivery (incidents, signals, timeline, alert state, audit) rolls back as one transaction | Alertmanager must retry; ingestion is serialized by one advisory lock, which bounds throughput |
| PostgreSQL unavailable when execution is requested | Queue reservation fails and no message is intentionally published | Caller must retry after recovery |
| NATS unavailable during publish | Argus releases `queued -> approved` and records `remediation.dispatch_failed` in one transaction, then returns an error | A process crash can prevent that release |
| Publish ack lost and the publish is retried | The job carries `Nats-Msg-Id` = idempotency key + reservation time, so JetStream stores it once within its 10-minute duplicate window | A retry after the window, or for a new reservation, is a new message; worker claims and receipts still prevent a second execution |
| API crashes after queue reservation and before publish | PostgreSQL can retain `queued` while JetStream has no job | No transactional outbox or queued-job reconciler exists; an operator must repair the state |
| Worker disconnected or crashes before acknowledgement | The durable pull consumer `argus-remediation-workers` redelivers the message to any replica after its ack wait (job timeout + 30s); a running action is re-claimed and its receipt keeps local replay idempotent | After `ARGUS_WORKER_MAX_DELIVER` (default 5) deliveries JetStream stops redelivering and its max-deliveries advisory is captured in `ARGUS_DEAD_LETTER` |
| PostgreSQL unavailable when worker loads or completes a job | Worker naks with backoff (1s, doubling, capped at 60s); on the last delivery it dead-letters the job to `argus.dlq.remediation` with its reason, stream sequence, and delivery count | The remediation stays `queued`/`running` in PostgreSQL; dead letters are kept 30 days and are not replayed automatically |
| Malformed or unknown job | Undecodable payloads, a missing `remediation_id`, and remediations that do not exist are dead-lettered on first delivery and counted in `argus_remediation_dead_letters_total{reason}` | None beyond operator triage |
| Handler hangs | After `ARGUS_WORKER_JOB_TIMEOUT` (default 2m) the remediation is marked `timed_out` and the job is acked, not retried; at most `ARGUS_WORKER_CONCURRENCY` jobs run per worker, so other jobs keep flowing | A handler that ignores cancellation keeps its goroutine until it returns; its late result cannot overwrite `timed_out` |
| Local typed handler fails before commit | Desired state and receipt transaction roll back; worker retries within the action attempt budget | Repeated infrastructure errors eventually mark the action failed |
| Worker crashes after a completed local handler transaction | Receipt is durable; redelivery returns `reused: true` | This guarantee applies only to the local PostgreSQL adapter |
| External side effect succeeds before its receipt/status persists | Provider state may change while Argus still sees an incomplete action | Exactly-once cannot be claimed without a provider idempotency token and reconciliation read |
| Audit append fails during a state change | Proposal, execute reservation, dispatch release, cancellation, Helios outcomes, worker completion, manual incidents, incident ack/resolve, and dependency upserts write their audit entry in the same transaction, so the change rolls back (a worker retries it) | Event-only entries with no state change (idempotent reuse, skipped execution, retry scheduled, completion conflict) are written separately; a failure is logged and counted in `argus_audit_write_failures_total{action}` |
| Operator cancels a queued remediation | The worker's compare-and-swap claim fails, so the queued message is acked without executing | None for local execution; a cancel that loses the race to a worker claim returns `409` |
| Approval notification fails | Approval request remains durable and queryable; delivery failure is recorded | Initial notification is not guaranteed exactly once and HA sweepers may duplicate escalation delivery |
| Slow or oversized HTTP client | Read-header, read, write, and idle timeouts close the connection; bodies over 1 MiB (8 MiB for Alertmanager) return `413` | Limits are per connection; there is no per-client rate limit |
| Schema version mismatch | Migrations are versioned and checksummed in `schema_migrations`; a build older than the database's schema, or a modified applied migration, refuses to start | Rolling deploys need backward-compatible (expand, then contract) migrations because new and old replicas share one schema |
| AI service or Verdikt unavailable | Deterministic ingestion and RCA continue; governed AI proposal generation fails closed | Some advisory summaries or explanations may be unavailable until the failed dependency recovers |
| Helios accepts work but polling times out | Argus can leave the remediation in `running` | No final-state reconciliation controller currently closes the workflow |

## Correlation And RCA Limits

Exact deduplication uses `service + alert name + environment + fingerprint`. Each incident records its alerts as firing or resolved: it keeps absorbing an alert while that alert (or any other on the incident) is still firing, or within the grouping window of its last activity. A firing alert that is not re-sent for `ARGUS_ALERT_STALE_AFTER` (default 6h) stops holding the incident open, so an alert Alertmanager loses cannot pin an incident forever. Resolved notifications never open incidents. When a sender omits a fingerprint, Argus falls back to the alert name. Separate failures of the same alert can therefore collapse, while semantically equivalent alerts with different fingerprints can remain separate.

Topology correlation is deterministic, not omniscient. It trusts the current service catalog, uses cycle-safe graph traversal and stable tie-breaking, and stores suppressed alerts as evidence. A stale or incorrect edge can still group unrelated symptoms or infer the wrong upstream root. V1 has no edge freshness, runtime traffic verification, probabilistic causal model, or operator feedback loop.

RCA selects a failure mode only by exact alertname or an explicit `argus_failure_mode` label; annotation and log text cannot select one. Confidence comes only from probes Argus actually sent to Prometheus and Loki, capped by the number of independent sources, and the probe query, value, and status are persisted with every report. Untrusted service labels that could escape a PromQL/LogQL matcher are never substituted into a query. This is still not source attestation: an attacker who can write metrics or log lines with the right service label can corroborate a hypothesis, although that cannot authorize execution. Weights and thresholds are uncalibrated, probes use fixed lookback windows that can include an earlier unrelated burst, and there is no trace backend. See [Deterministic RCA Scoring](rca-scoring.md) for the exact formula, recorded live results, and limits.

## What Policy-Gated Means

The v1 Go policy engine currently checks:

| Enforced now | Not covered yet |
| --- | --- |
| Authenticated actor role is allowed to propose | Per-service and per-tenant authorization |
| Action type is registered | Dynamically distributed OPA bundles and policy version pinning |
| Target and parameters pass typed validation | Current infrastructure ownership and live target identity |
| High risk is denied | Multi-party or risk-dependent approval quorum |
| Medium risk requires approval | Maintenance windows, change freezes, and active change tickets |
| Same action is rate-limited and repeated failures trip a local circuit breaker | Fleet-wide failure budgets and cross-incident circuit breakers |
| The incident's environment (from its alert) must be enabled by `ARGUS_REMEDIATION_ENVIRONMENTS` | A trusted environment value derived from inventory rather than alert labels |
| Risk is the stricter of the action catalog's class and the proposal's | Risk that depends on target criticality or blast radius |

Policy is evaluated when a remediation is proposed. It is not re-evaluated immediately before execution, so an approval can outlive changed health, topology, ownership, or maintenance-window context. A missing actor role is denied by the policy package itself. Remediation cannot be dispatched for a resolved or cancelled incident. Low-risk means approval is not required; it does not give the LLM or AI service direct execution authority.

## Audit Limits

The chain detects modification under the normal application role: sequence positions, prior hashes, canonical entry hashes, and a persisted head are verified at startup, periodically, and on demand. PostgreSQL triggers reject updates, deletes, and truncation of ledger rows.

This does not defeat a database owner who can disable triggers and rewrite both the ledger and chain head. Argus also has no external signed checkpoint, WORM export, retention/archive policy, or independent verifier. The global chain-head lock serializes writers and has not been load-tested at production audit volume.

Every state change Argus makes (alert ingestion, approvals, proposals, execute reservations and releases, cancellation, Helios outcomes, worker completion, manual incidents, incident ack/resolve, and dependency upserts) commits in the same transaction as its audit entry: if the append fails, the change rolls back. Entries that record an event without changing state (idempotent reuse, skipped execution, retry scheduled, completion conflict) are appended separately, and a failed append is logged and counted in `argus_audit_write_failures_total` rather than failing the request. The worker's `queued -> running` claim is not separately audited; the completion entry records the outcome.

## Explicit Non-Goals In V1

- autonomous high-risk remediation
- arbitrary shell, SQL, Kubernetes manifest, or model-generated command execution
- multi-region or multi-cluster control-plane availability
- bundled PostgreSQL/NATS HA, backup, restore, or disaster-recovery automation
- live Kubernetes install, upgrade, rollback, and chaos certification
- compliance certification or replacement for an organization's change-management controls
- guarantees about third-party model retention, residency, or availability when Gemini is enabled

## Production Closure Plan

| Priority | Required closure | Verification evidence |
| --- | --- | --- |
| P0 | Add a PostgreSQL transactional outbox, idempotent publisher, and reconciler for stranded `queued` actions | Crash API between reservation/publish and prove eventual single delivery |
| P0 | Require provider idempotency tokens and postcondition reads for every real execution adapter | Kill workers at every side-effect/receipt boundary and prove convergence |
| P0 | Re-evaluate a versioned policy immediately before execution | Change policy/context after approval and prove execution is denied |
| P1 | Add operator tooling to inspect, replay, or discard dead-lettered jobs and reconcile their remediations | Dead-letter a job during an outage, replay it after recovery, and prove one execution |
| P1 | Add topology provenance, freshness, operator correction, and RCA calibration | Measure grouping precision, suppression recall, and hypothesis calibration on labeled incidents |
| P1 | Anchor signed audit heads outside PostgreSQL and test restore verification | Rewrite local ledger/head and prove the external checkpoint detects it |
| P1 | Run HA and dependency fault-injection tests for PostgreSQL, NATS, API replicas, and approval sweepers | Publish repeatable outage timelines and recovery objectives |

These gaps are intentionally visible so a reviewer can distinguish what the repository proves today from the controls a production deployment would still need.

## Implementation References

| Claim area | Verifiable implementation |
| --- | --- |
| Dedupe and topology ingestion | [`internal/incidents/service.go`](../internal/incidents/service.go), [`internal/incidents/store.go`](../internal/incidents/store.go) |
| Policy decision | [`internal/policy/engine.go`](../internal/policy/engine.go) |
| Queue reservation and publish | [`internal/remediation/service.go`](../internal/remediation/service.go), [`internal/remediation/executor.go`](../internal/remediation/executor.go) |
| JetStream configuration | [`internal/queue/nats.go`](../internal/queue/nats.go) |
| Worker retries and acknowledgement | [`internal/workers/runner.go`](../internal/workers/runner.go) |
| Durable local idempotency receipt | [`internal/workers/control_state.go`](../internal/workers/control_state.go) |
| Approval transaction and notifications | [`internal/approvals/store.go`](../internal/approvals/store.go), [`internal/approvals/service.go`](../internal/approvals/service.go) |
| Audit chain and verification | [`internal/audit/chain.go`](../internal/audit/chain.go), [`internal/audit/service.go`](../internal/audit/service.go) |
