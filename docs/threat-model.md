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
| NATS JetStream | Acknowledged file-backed stream persists messages on the local node | Disconnects and worker redelivery are considered; loss of the single node and cross-system atomicity are not solved |
| Worker adapters | Local PostgreSQL-backed adapters honor the receipt transaction | Real Kubernetes, Redis, Nginx, or database APIs must independently provide idempotency and scoped credentials |
| AI service, Ollama, Gemini, Verdikt | All model output is untrusted; Verdikt is a proposal-only policy boundary | Unavailable or malformed advisory output fails closed and cannot block deterministic ingestion/RCA |
| Helios | Accepts the same typed intent and idempotency key | The current integration is a safe simulated workflow, not a production remediation provider |

## Dependency And Crash Semantics

| Failure point | Current behavior | Residual risk |
| --- | --- | --- |
| PostgreSQL unavailable before incident write | Ingestion fails; no in-memory incident is treated as durable | Alertmanager must retry; Argus does not ship an ingress spool |
| PostgreSQL fails during incident ingestion | The failed statement rolls back | Incident, signal, timeline, and audit writes are not one transaction, so earlier writes can remain as partial context |
| PostgreSQL unavailable when execution is requested | Queue reservation fails and no message is intentionally published | Caller must retry after recovery |
| NATS unavailable during publish | Argus attempts `queued -> approved` rollback and returns an error | A process crash can prevent that rollback |
| API crashes after queue reservation and before publish | PostgreSQL can retain `queued` while JetStream has no job | No transactional outbox or queued-job reconciler exists; an operator must repair the state |
| Worker disconnected or crashes before acknowledgement | Durable consumer redelivers the message | Delivery settings have no dedicated dead-letter stream or poison-event quarantine |
| PostgreSQL unavailable when worker loads a job | Worker negatively acknowledges the message for redelivery | Queue lag grows until PostgreSQL recovers |
| Local typed handler fails before commit | Desired state and receipt transaction roll back; worker retries within the action attempt budget | Repeated infrastructure errors eventually mark the action failed |
| Worker crashes after a completed local handler transaction | Receipt is durable; redelivery returns `reused: true` | This guarantee applies only to the local PostgreSQL adapter |
| External side effect succeeds before its receipt/status persists | Provider state may change while Argus still sees an incomplete action | Exactly-once cannot be claimed without a provider idempotency token and reconciliation read |
| Completion persists but audit append fails | Remediation can finish without its expected non-approval audit row | Several API/worker audit calls are best effort and are not in the mutation transaction |
| Approval notification fails | Approval request remains durable and queryable; delivery failure is recorded | Initial notification is not guaranteed exactly once and HA sweepers may duplicate escalation delivery |
| AI service or Verdikt unavailable | Deterministic ingestion and RCA continue; governed AI proposal generation fails closed | Some advisory summaries or explanations may be unavailable until the failed dependency recovers |
| Helios accepts work but polling times out | Argus can leave the remediation in `running` | No final-state reconciliation controller currently closes the workflow |

## Correlation And RCA Limits

Exact deduplication uses `service + alert name + environment + fingerprint` within the grouping window. When a sender omits a fingerprint, Argus falls back to the alert name. Separate failures of the same alert can therefore collapse, while semantically equivalent alerts with different fingerprints can remain separate.

Topology correlation is deterministic, not omniscient. It trusts the current service catalog, uses cycle-safe graph traversal and stable tie-breaking, and stores suppressed alerts as evidence. A stale or incorrect edge can still group unrelated symptoms or infer the wrong upstream root. V1 has no edge freshness, runtime traffic verification, probabilistic causal model, or operator feedback loop.

RCA scoring is reproducible from normalized stored evidence, fixed rule weights, topology adjustments, and stable ordering. It is not source attestation. Attacker-controlled log or alert text can match an evidence category, although that match still cannot authorize execution. V1 does not model negative evidence, seasonality, metric baselines, score calibration, or counterfactual recovery. See [Deterministic RCA Scoring](rca-scoring.md) for the exact formula and evaluation harness.

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
| The proposal uses the local environment boundary | A trusted environment value derived from inventory rather than fixed v1 context |

Policy is evaluated when a remediation is proposed. It is not re-evaluated immediately before execution, so an approval can outlive changed health, topology, ownership, or maintenance-window context. The HTTP path supplies a role from verified OIDC claims, but the policy package itself currently defaults an empty role to `operator`; a future reusable policy boundary should deny missing roles rather than depend on its caller. Low-risk means approval is not required; it does not give the LLM or AI service direct execution authority.

## Audit Limits

The chain detects modification under the normal application role: sequence positions, prior hashes, canonical entry hashes, and a persisted head are verified at startup, periodically, and on demand. PostgreSQL triggers reject updates, deletes, and truncation of ledger rows.

This does not defeat a database owner who can disable triggers and rewrite both the ledger and chain head. Argus also has no external signed checkpoint, WORM export, retention/archive policy, or independent verifier. The global chain-head lock serializes writers and has not been load-tested at production audit volume.

Approval decisions are the strongest audited path because the approval state, remediation transition, and audit records commit in one transaction. Other incident, remediation, and worker paths frequently append audit records after their state update and some treat append errors as best effort. Until those writes are atomically coupled, the project should claim tamper evidence for records that exist, not complete non-repudiation for every state mutation.

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
| P0 | Couple every state mutation with its audit append or fail the mutation | Fault-inject audit writes across incident, remediation, and worker paths |
| P0 | Require provider idempotency tokens and postcondition reads for every real execution adapter | Kill workers at every side-effect/receipt boundary and prove convergence |
| P0 | Re-evaluate a versioned policy immediately before execution | Change policy/context after approval and prove execution is denied |
| P1 | Configure bounded JetStream delivery, backoff, dead-letter handling, and poison-event observability | Replay malformed and permanently failing jobs without infinite churn |
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
