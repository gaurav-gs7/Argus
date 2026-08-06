# Deterministic RCA Scoring

Argus uses a fixed, inspectable heuristic model for its correctness path. It is rule-based. The deterministic guarantee is narrower and testable: identical persisted signals and topology produce identical evidence, score arithmetic, hypothesis ordering, remediation candidates, and fallback behavior without an LLM, model temperature, or random state.

## Pipeline

1. Persisted signals are loaded in `observed_at, id` order.
2. The correlator lowercases `name + source + signal_type + JSON body` into one normalized text value.
3. Fixed predicates emit evidence carrying an explicit `rule_id`, type, source label, summary, confidence, weight, and occurrence time.
4. Evidence is deduplicated by `rule_id + type + source + summary`, so replaying the same alert cannot increase its hypothesis score.
5. Each evidence item is routed by `rule_id`, not by searching generated prose.
6. Hypotheses sort by descending score and then lexical hypothesis name, making ties stable across Go map iteration.
7. Topology applies only the bounded adjustments documented below.
8. The LLM receives the completed deterministic result afterward and may summarize it; it cannot change the stored evidence, score, or typed candidate parameters.

The implementation is in [`internal/correlation/correlator.go`](../internal/correlation/correlator.go) and [`internal/rca/service.go`](../internal/rca/service.go).

## Formula

For hypothesis `h`:

```text
raw_evidence_score(h) = sum(item.confidence * item.weight)
signal_confidence(h) = clamp(0.35 + raw_evidence_score(h), 0.35, 0.95)
```

The `0.35` baseline represents a classified but not statistically calibrated hypothesis. The `0.95` ceiling prevents heuristic matches from claiming certainty. RCA factors retain every multiplication, for example:

```text
metric_anomaly from prometheus (confidence 0.91 x weight 0.34 = 0.3094)
```

## Rule Coverage

| Rule ID | Predicate over normalized signal | Emitted evidence `(confidence x weight)` | Final confidence | Typed candidate set |
| --- | --- | --- | --- | --- |
| `postgres_connection_exhaustion` | contains `postgres` and `connection` | pool saturation `0.91x0.34`; acquisition timeout `0.87x0.29`; service impact `0.82x0.17` | `0.95` after cap | drain connections, resize pool, restart pod |
| `redis_memory_pressure` | contains `redis` and `memory` | memory threshold `0.86x0.31`; cache impact `0.82x0.22` | `0.7970` | bounded cache purge |
| `nginx_upstream_config` | contains `nginx` and `5xx` | edge 5xx `0.89x0.30`; nearby config `0.76x0.20` | `0.7690` | rollback config, reload Nginx |
| `dependency_latency` | contains `notification` or `latency` | dominant trace `0.84x0.30`; p95 sequence `0.77x0.18` | `0.7406` | disable optional notification path |
| `bad_config_rollout` | contains `config`, `parse`, or `rollout` | rollout order `0.93x0.35`; runtime error `0.85x0.24` | `0.8795` | rollback config, restart pod |

More than one rule may match a signal. Each emitted item remains attached to its own rule ID, so overlapping vocabulary cannot silently route an item to a different hypothesis.

## Topology Bounds

Topology does not invent a component-level failure mode.

| Condition | Behavior |
| --- | --- |
| Signal hypothesis plus observed root alert | add `0.03`, cap at `0.95`, attach blast radius and dependency paths |
| Signal hypothesis plus inferred root | add `0.00`; attach paths but do not inflate confidence |
| No signal hypothesis, observed shared root | name only the root failure domain at `0.72`; diagnostics only |
| No signal hypothesis, inferred shared root | name only the inferred failure domain at `0.58`; diagnostics only |
| No signal or usable topology match | return insufficient evidence at `0.35`; diagnostics only |

Root selection is separately deterministic: maximize alerted-service coverage, minimize total dependency distance, prefer an observed root, then break ties lexically. See [Topology Correlation](architecture.md#topology-correlation).

## Verification Matrix

| Claim | Executable check | Committed evidence |
| --- | --- | --- |
| Exact score for all five rules | `TestDeterministicRCAScenarioScores` | five JSON snapshots under [`docs/demo-evidence`](demo-evidence/README.md) |
| Duplicate alerts do not inflate evidence | `TestCorrelateDeduplicatesRepeatedEvidence` | topology alert-storm snapshot preserves all signals while suppressing incidents |
| Equal scores have a stable winner | `TestBestHypothesisBreaksEqualScoresLexically` | lexical tie rule in this specification |
| Unknown evidence fails safe | `TestBuildDeterministicRCAFallsBackToDiagnostics` | `0.35` plus diagnostics-only candidate |
| Observed topology has a bounded bonus | `TestEnrichWithObservedTopologyRaisesConfidenceAndExplainsBlastRadius` | [`topology-alert-storm.json`](demo-evidence/topology-alert-storm.json) |
| Inferred topology cannot inflate confidence | `TestEnrichWithInferredTopologyDoesNotInflateConfidence` | topology safety field `inferred_root_confidence_inflated: false` |
| Topology cannot invent a failure mode | `TestTopologyFallbackNamesFailureDomainWithoutInventingFailureMode` | topology summary names PostgreSQL only as the failure domain |

Run the focused checks with:

```bash
make rca-eval
```

## Trust Boundary And Limitations

- The confidence is an operational heuristic, not a Bayesian posterior, learned probability, or SLO-derived likelihood.
- Alert names, annotations, and log text can be attacker-influenced. A match can propose a hypothesis but cannot bypass typed handlers, policy, RBAC, dry-run, approval, idempotency, or auditing.
- The v1 classifier emits canonical evidence categories from normalized signal text for the local demo. It does not independently query or cryptographically attest Prometheus, Loki, or OTel provenance at scoring time.
- Current weights are hand-authored and regression-tested against five demo failure modes; they are not calibrated from a production incident corpus.
- Negative evidence, seasonality, baseline drift, and counterfactual causal analysis are not modeled.
- Production hardening should replace token predicates with typed source adapters, provenance metadata, anomaly extractors, and offline calibration while preserving the same inspectable scoring contract.

These constraints are intentional in v1: a low-confidence diagnostics fallback is safer than presenting an LLM-generated explanation as verified root cause.
