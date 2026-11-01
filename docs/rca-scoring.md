# Deterministic RCA Scoring

Argus RCA is rule-based and evidence-driven. A hypothesis is selected only by structured alert identity, then corroborated or refuted by queries Argus actually sends to Prometheus and Loki. Confidence is bounded by how many independent sources agree. No LLM, sampling, or free-text classification is in this path.

"Deterministic" means: the same persisted signals plus the same probe results always produce the same hypothesis, arithmetic, and candidates. Probe results are persisted with every report (`evidence_items`), so any report can be replayed exactly.

## 1. Rule Selection

The compiled rule table (`internal/correlation/rules.go`) is reviewed in CI. A signal selects a rule only by:

1. an explicit `argus_failure_mode=<rule_id>` alert label, or
2. an exact `alertname` listed by the rule.

Annotations, summaries, descriptions, and service names never select a rule. An alert whose description says "maxmemory config" does not become a config rollout; a disk alert on `notification-api` does not become dependency latency.

| Rule | Alert names | Probes (backend: weight) |
| --- | --- | --- |
| `postgres_connection_exhaustion` | `PaymentsAPIPostgresConnectionExhaustion`, `PaymentsAPIPostgresPoolSaturation`, `PostgresConnectionPoolExhausted` | pool utilisation ≥ 0.9 (Prometheus: 0.20), 5xx ratio ≥ 5% (Prometheus: 0.10, *symptom*), acquisition-timeout log lines ≥ 1 (Loki: 0.20) |
| `redis_memory_pressure` | `PaymentsAPIRedisMemoryPressure`, `RedisMemoryPressure`, `RedisMemoryHigh` | memory used/max ≥ 0.9 (Prometheus: 0.20), operation errors increased (Prometheus: 0.15), memory-pressure log lines (Loki: 0.15) |
| `nginx_upstream_config` | `Nginx5xxSpike`, `NginxUpstreamErrors` | edge 5xx ratio ≥ 5% (Prometheus: 0.20, *symptom*), upstream error log lines (Loki: 0.15) |
| `dependency_latency` | `PaymentsAPIDependencyLatency`, `DownstreamDependencyLatency` | p95 latency ≥ 800 ms (Prometheus: 0.20, *symptom*), dependency-latency log lines (Loki: 0.15) |
| `bad_config_rollout` | `PaymentsAPIBadConfigRollout`, `ConfigRolloutFailed` | config parse error log lines (Loki: 0.25), 5xx ratio ≥ 5% (Prometheus: 0.10, *symptom*) |

**Symptom probes** measure impact (error ratio, latency) rather than the failure mode. Any outage produces them: with the PostgreSQL scenario live, the 5xx-ratio probe also "corroborated" a config-rollout alert and p95 latency a dependency-latency alert. Symptoms therefore add weight but never make their backend an independent source. Every rule must have at least one cause-specific probe.

Rule validation rejects duplicate IDs, an alert name claimed by two rules, probes without a `{{service}}` scope, probe weights above 0.5 per rule, unregistered remediation actions, and unknown risk levels.

## 2. Probes

Each matched rule runs its PromQL/LogQL instant queries, scoped to the alert's `service` label, against the configured backends (`ARGUS_PROMETHEUS_URL`, `ARGUS_LOKI_URL`). Every probe ends in exactly one state:

| Status | Meaning | Score effect |
| --- | --- | --- |
| `corroborated` | Backend returned a sample and the comparison held | `+weight`; backend counts as a source |
| `refuted` | Backend returned a sample and the comparison did not hold | `-0.5 × weight` |
| `no_data` | Backend answered with no matching series, or NaN | none |
| `unavailable` | Backend not configured, failed, timed out, or the service label was unsafe | none; reason recorded |

The service label comes from untrusted alert payloads. Only values matching `^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$` are substituted into queries. Anything else is recorded as `unavailable` and never reaches a backend. Probes run concurrently with `ARGUS_RCA_PROBE_TIMEOUT` (default 3s) each and a 4 MiB response cap.

## 3. Confidence

```text
raw        = 0.45 (alert match) + Σ corroborated weight − 0.5 × Σ refuted weight
sources    = {alertmanager} ∪ {backends with at least one corroborated cause-specific probe}
cap        = 0.55 for 1 source, 0.80 for 2, 0.95 for 3
confidence = clamp(raw, 0.35, cap)
```

| Situation | Confidence |
| --- | --- |
| One alert, no backend agrees (or none configured) | 0.45 |
| Alert + Prometheus pool and 5xx probes corroborate | min(0.75, 0.80) = 0.75 |
| Alert + all three PostgreSQL probes corroborate | min(0.95, 0.95) = 0.95 |
| Alert, pool probe corroborates, 5xx probe refutes | 0.45 + 0.20 − 0.05 = 0.60 |
| Config-rollout alert, only the 5xx symptom corroborates | min(0.55, 0.55) = 0.55, one source |
| Alert, both Prometheus probes refute | clamp(0.30) = 0.35, **contradicted** |

**Contradiction.** When refuted weight exceeds corroborated weight, the report says the evidence contradicts the alert and proposes only `collect_diagnostics`. Argus never proposes a remediation for a hypothesis its backends disagree with.

**Competing hypotheses.** Rank order is: non-contradicted before contradicted, then higher confidence, then more independent sources, then lexical hypothesis name. Evidence for losing hypotheses is kept in `evidence_items` for audit.

**Topology.** An observed topology root adds 0.03, never past the source cap. An inferred root adds nothing. When no rule matches but alerts share a dependency root, topology alone yields 0.72 (observed) or 0.58 (inferred) and permits diagnostics only.

**No match.** With no rule match and no topology root, Argus reports `0.35`, "Insufficient evidence", and `collect_diagnostics`.

## 4. Remediation Candidates

Rules carry candidate templates. The target always comes from the alert that matched, never from a constant:

| Rule | Candidate | Target source |
| --- | --- | --- |
| PostgreSQL | `drain_postgres_connections`, `resize_connection_pool` (size 20) | alert `service` |
| PostgreSQL, config rollout | `restart_pod` | `local/<pod label>`, falling back to `local/<service>` |
| Redis | `purge_cache` (max 500 keys) | `cache_key_pattern` label |
| Nginx | `rollback_config`, `reload_nginx` | alert `service` |
| Config rollout | `rollback_config` | alert `service` |
| Dependency latency | `toggle_feature_flag` (disable) | `degradable_feature_flag` label |

Every rendered target passes the action catalog's validation (DNS-label services, scoped cache prefixes, allow-listed flags). A candidate whose label is missing or whose target is rejected is dropped, the reason is added to the RCA factors, and if nothing survives Argus proposes diagnostics only. Policy, RBAC, approval, and typed handlers still decide whether any candidate runs.

## 5. Report Shape

```json
{
  "primary_hypothesis": "PostgreSQL connection pool exhaustion",
  "confidence": 0.95,
  "evidence": [
    "alertmanager: alert PaymentsAPIPostgresConnectionExhaustion fired for payments-api",
    "prometheus: connection pool utilisation is at or above 90% (observed 0.95 >= 0.9)"
  ],
  "evidence_items": [
    {"rule_id": "postgres_connection_exhaustion", "kind": "probe", "source": "prometheus",
     "reference": "postgres_pool_utilisation", "service": "payments-api",
     "query": "max(db_connection_pool_in_use{service=\"payments-api\"} / db_connection_pool_max{service=\"payments-api\"})",
     "status": "corroborated", "value": 0.95, "comparator": ">=", "threshold": 0.9, "weight": 0.2}
  ],
  "score": {"alert_match": 0.45, "corroborated": 0.5, "refuted": 0, "raw": 0.95,
            "sources": ["alertmanager", "loki", "prometheus"], "source_cap": 0.95, "final": 0.95}
}
```

Evidence lines from symptom probes are prefixed `prometheus (symptom):`. Corroborated and refuted probe values are also written to the incident timeline as `probe_corroborated` / `probe_refuted` events.

## 6. Verification

```bash
make rca-eval
```

runs the scoring and matching contract tests and `scripts/check-rca-evidence.py`, which independently recomputes every committed demo-evidence score from its `evidence_items`: probe statuses against values and thresholds, weights, cause-specific sources, cap, final confidence, and that every evidence line has a matching corroborated probe. `TestDemoEvidenceMatchesEngine` fails if a committed snapshot drifts from engine output. `TestGeneratePersistsQueriedEvidence` exercises the full path against PostgreSQL and HTTP servers speaking the Prometheus and Loki query APIs.

`TestLiveBackendsScenario` runs RCA against a real Prometheus and Loki while a demo scenario is active (see its doc comment); `ARGUS_E2E_ALERT` sends a different scenario's alert to check that the live backends do not corroborate it. The committed demo-evidence probe values were recorded from such runs against Prometheus 2.53 and Loki 3.0:

| Scenario | Confidence | Independent sources | Notes |
| --- | --- | --- | --- |
| PostgreSQL exhaustion | 0.95 | alertmanager, prometheus, loki | pool 0.95, 5xx ratio 1.0, 320 timeout log lines |
| Redis memory pressure | 0.75 | alertmanager, prometheus, loki | no redis_exporter in the demo, so memory utilisation has no data |
| Nginx 5xx spike | 0.45 | alertmanager | the demo has no nginx telemetry; alert-only bound |
| Dependency latency | 0.80 | alertmanager, loki | p95 latency 2.2s is a symptom |
| Bad config rollout | 0.80 | alertmanager, loki | 5xx ratio 0.91 is a symptom |

With the PostgreSQL scenario active, the other alerts score Redis 0.375 (contradicted, diagnostics only), config rollout 0.55, and dependency latency 0.55, each from the alert alone.

## 7. Limits

- Weights, thresholds, and caps are operational heuristics, not calibrated probabilities. Calibration needs labeled production incidents.
- Alertmanager alerts are often evaluated on the same Prometheus. The cap treats the alert and a Prometheus probe as separate sources because they test different conditions, but they share an upstream.
- Probes assume a `service` label on metrics and log streams. Deployments with other label conventions must adjust the rule queries.
- There is no trace backend. Dependency latency is corroborated by aggregate latency and logs, not span-level attribution.
- Probes are instant queries at RCA time over fixed lookback windows (5–10 minutes). A probe that runs after recovery can refute a hypothesis that was true during the incident, and a window can still contain an earlier, unrelated burst: a Redis alert sent a few minutes after the Redis scenario ended was still corroborated. Anchoring windows to the incident start would narrow this.
