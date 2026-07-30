# ADR 0009: Topology-Aware Incident Correlation

## Status

Accepted

## Context

Exact alert deduplication prevents duplicate deliveries from opening duplicate incidents, but it does not address an alert storm where one dependency failure triggers distinct alerts across many downstream services. Treating every symptom as a separate incident increases on-call cognitive load and obscures the service closest to the root cause.

## Decision

Store a directed service dependency graph in PostgreSQL and correlate each normalized Alertmanager batch before incident creation. Choose roots deterministically by coverage, dependency distance, observed-root preference, and lexical tie-breaking. Persist every alert as evidence, but represent downstream symptoms as `downstream_alert_suppressed` timeline events under one root incident.

Serialize correlation with a PostgreSQL advisory lock so multiple API replicas cannot race. Mark roots inferred from topology separately from roots backed by an alert, and do not increase deterministic RCA confidence for inferred roots.

## Consequences

- Alert storms produce fewer, higher-value incidents without losing forensic evidence.
- Operators can inspect the blast radius and dependency paths through the API and RCA report.
- Incorrect or stale catalog edges can misgroup alerts, so inferred roots remain explicit and topology changes are audited.
- The coarse ingestion lock favors correctness and the 8 GB local profile over peak throughput. A partitioned lock by environment or graph component can replace it when scale requires.
