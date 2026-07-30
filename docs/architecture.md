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
2. Normalize and deduplicate
3. Persist incident and signal state
4. Build a deterministic timeline
5. Generate rule-based RCA hypotheses
6. Propose typed remediations
7. Apply policy checks
8. Require approval for medium-risk operations
9. Execute through registered handlers only
10. Append every state change to the serialized SHA-256 audit hash chain

## Advisory AI Path

The AI service receives only structured evidence:

- incident metadata
- timeline events
- matched runbook snippets
- similar incidents

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
