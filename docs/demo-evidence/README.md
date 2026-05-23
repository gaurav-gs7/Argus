# Demo Evidence

This directory contains committed reviewer-friendly snapshots for the five Argus demo scenarios. Live demo runs write fresh machine-local evidence under `artifacts/demo-evidence/<scenario>/` so committed docs do not churn.

| Scenario | Evidence |
| --- | --- |
| PostgreSQL connection exhaustion | [postgres-connection-exhaustion.json](postgres-connection-exhaustion.json) |
| Redis memory pressure | [redis-memory-pressure.json](redis-memory-pressure.json) |
| Nginx 5xx spike | [nginx-5xx-spike.json](nginx-5xx-spike.json) |
| Dependency latency | [dependency-latency.json](dependency-latency.json) |
| Bad config rollout | [bad-config-rollout.json](bad-config-rollout.json) |

Regenerate live evidence locally:

```bash
make up
make seed
make demo-postgres-exhaustion
```

The snapshots show the intended evidence shape: incident metadata, correlated timeline, deterministic RCA, policy-gated remediation proposal, and safety notes.
