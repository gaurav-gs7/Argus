# Architecture

Argus is split into deterministic control-plane logic and an advisory AI sidecar.

## Control Plane

- `argus-api`: REST API, Alertmanager ingress, incident lifecycle, RCA orchestration, remediation approval/execution
- `argus-worker`: durable remediation consumer using NATS JetStream
- `argus-cli`: operational CLI for incidents, remediations, runbooks, and demo scenarios
- `failure-injector`: local scenario helper for deterministic demos

## Optional Helios Backend

Argus can dispatch approved remediations to an external Helios control plane instead of the local Argus worker path.

- Argus remains authoritative for policy, approval, tamper-evident audit, and incident state
- OIDC verifies signed user identity; Argus maps trusted role claims into local permissions
- Helios becomes the execution backend for delegated remediation workflows
- The current integration uses Helios's trusted `persist_artifact` workflow path as a safe simulated execution backend
- Future Helios remediation-specific task types can replace this workflow mapping without changing Argus's control-plane contracts

## Deterministic Path

The correctness path does not depend on an LLM:

1. Receive signal
2. Normalize the complete alert batch
3. Walk the service dependency graph from symptoms toward shared upstream dependencies
4. Choose an observed root when present, otherwise mark the common root as inferred
5. Reuse or promote an open incident under a PostgreSQL advisory lock
6. Persist every alert as evidence while suppressing downstream incident creation
7. Build a deterministic timeline and topology snapshot
8. Generate rule-based RCA hypotheses
9. Propose typed remediations
10. Apply policy checks and require approval for medium-risk operations
11. Validate typed target and parameter bounds again in the worker
12. Execute through registered handlers using a durable idempotency receipt
13. Append every state change to the serialized SHA-256 audit hash chain

## Topology Correlation

`service_dependencies` stores directed `service -> depends_on` edges with dependency type and criticality. The correlator performs cycle-safe breadth-first graph walks and uses deterministic tie-breaking:

1. maximize the number of alerted services covered by a candidate root
2. minimize total dependency distance
3. prefer an alerted root over an inferred root
4. use lexical order as the final stable tie-break

This converts an alert storm into root incident groups without discarding evidence. A downstream alert is stored in `signals`, emitted as a `downstream_alert_suppressed` timeline event, and appended to the audit chain. Root inference never receives the confidence increase reserved for an observed root. Independent dependency failures remain separate incidents.

The ingestion lock is PostgreSQL-backed rather than process-local, so concurrent API replicas cannot race to create competing root incidents. It is deliberately coarse for the low-volume local profile; partitioned advisory locks are the natural scale-out path.

## Typed Remediation Runtime

`remediation_actions.parameters` carries deterministic desired state. The local worker exposes four concrete bounded handlers for pod restart, connection-pool resize, feature-flag toggle, and cache purge. Each handler implements validation, dry-run, and execute separately.

The M2-friendly adapter stores desired resource state in `remediation_target_states`. `remediation_execution_receipts` is keyed by the action's parameter-aware idempotency key. An execution transaction locks both the receipt and target, merges the desired state, and commits the result and receipt atomically. Replays return the receipt. This proves worker safety without adding Kubernetes to the default profile.

## Advisory AI Path

The AI service receives only structured evidence:

- incident metadata
- timeline events
- matched runbook snippets
- similar incidents
- dependency paths, affected services, and suppression counts

It can:

- summarize RCA
- explain remediation risk
- generate readable incident reports

It cannot:

- issue commands
- mutate state
- bypass policy
- approve actions

## Runtime Notes

The default profile keeps resource usage reasonable for 8 GB RAM by:

- using mock AI by default
- skipping vector DB
- using keyword retrieval over runbooks
- avoiding Tempo/Jaeger in the default Compose profile
