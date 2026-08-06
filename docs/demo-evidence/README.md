# Demo Evidence

This directory contains committed reviewer-friendly snapshots for the five Argus demo scenarios and the complete 150-second terminal recording. Live demo runs write fresh machine-local evidence under `artifacts/` so committed docs do not churn.

| Scenario | Evidence |
| --- | --- |
| PostgreSQL connection exhaustion | [postgres-connection-exhaustion.json](postgres-connection-exhaustion.json) |
| Redis memory pressure | [redis-memory-pressure.json](redis-memory-pressure.json) |
| Nginx 5xx spike | [nginx-5xx-spike.json](nginx-5xx-spike.json) |
| Dependency latency | [dependency-latency.json](dependency-latency.json) |
| Bad config rollout | [bad-config-rollout.json](bad-config-rollout.json) |
| AI governance with Verdikt | [ai-governance-verdikt.json](ai-governance-verdikt.json) |
| Human approval workflow | [human-approval-workflow.json](human-approval-workflow.json) |
| Topology alert storm | [topology-alert-storm.json](topology-alert-storm.json) |
| Live incident-to-remediation session | [argus-terminal-demo.cast](argus-terminal-demo.cast) |

Regenerate live evidence locally:

```bash
make up
make seed
make demo-alert-storm
make demo-postgres-exhaustion
```

The snapshots show the intended evidence shape: root incident metadata, topology and correlated timeline, deterministic RCA, policy-gated remediation proposal, identity-bound approval, and safety notes. Their RCA confidence values match the exact table-driven expectations in `internal/rca/service_test.go`; see the [scoring specification](../rca-scoring.md) for each multiplication and fallback bound.
