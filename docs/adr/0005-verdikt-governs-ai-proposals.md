# ADR 0005: Verdikt governs AI remediation proposals

## Status

Accepted.

## Context

Alert annotations and log lines are attacker-influenceable. An LLM must not convert those inputs into an executable operation, even when its output looks structurally valid.

## Decision

Argus gives the model only deterministic remediation candidates. The AI service strictly parses the response, rejects unknown fields and non-candidate targets, and sends each surviving typed proposal to Verdikt's authenticated policy-only endpoint. Verdikt audits the decision and always reports `executed: false`. It has no execution hop in this endpoint.

The governed output is advisory. Argus's Go policy engine, RBAC, approval state machine, idempotency controls, and typed worker registry remain the only correctness and execution path.

## Consequences

- Verdikt unavailability denies AI suggestions without affecting incident ingestion or deterministic RCA.
- Prompt-injection content is removed before an advisory call and counted in Prometheus.
- Running the complete local profile requires the Verdikt checkout beside Argus, adding a small container but no paid service.
