# LLM Design

The LLM is explicitly advisory only. Verdikt is the enforcement boundary around remediation suggestions.

## Inputs

- incident metadata and deterministic confidence
- deterministic timeline and bounded evidence list
- matched runbook chunks and similar incident summaries
- deterministic remediation candidates for suggestion ranking

Alert titles, annotations, and log lines are untrusted. Argus removes direct prompt-injection patterns and invisible Unicode controls before constructing prompts, then clearly delimits the remaining evidence as data.

## Governed suggestion path

1. Go RCA rules produce typed candidates.
2. The model may rank at most two candidates and add rationale.
3. Strict Pydantic models reject unknown actions, targets, and fields such as `execute` or `command`.
4. Verdikt evaluates the typed proposal through `/api/evaluate`.
5. Verdikt audits `PROPOSE_ONLY` and returns `executed: false` without invoking an upstream.
6. Durable remediation remains a separate operator-authenticated Go API path.

Verdikt failure, malformed model JSON, unknown fields, and protocol violations all fail closed for suggestions. They do not block incident ingestion or deterministic RCA.

## AI observability

Every advisory call exports operation/backend/model labels for call outcome, latency, input and output tokens, configured estimated cost, and deterministic confidence. Governance decisions and prompt-injection blocks are exported separately and appear in the Argus Grafana dashboard.

Cost rates default to zero for mock, Ollama, and Gemini free-tier usage. They can be configured per million tokens without changing code.
