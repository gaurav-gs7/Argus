# Argus

Argus is a production-style SRE control plane for incident detection, deterministic RCA, and safe policy-gated auto-remediation.

It is designed to feel like an internal reliability platform rather than a generic AI log chatbot:

- incidents are created from observability signals
- RCA is built from deterministic evidence first
- the LLM is advisory only and never in the correctness path
- Verdikt governs every AI remediation proposal in policy-only mode
- remediations are typed, idempotent, policy-gated, and auditable
- medium-risk actions enter a durable, identity-bound human approval workflow

## Why This Stack

This repository is intentionally optimized for local development on a MacBook Air M2 with 8 GB RAM:

- Go for the control plane, worker, CLI, and demo workloads
- Python FastAPI for the advisory AI service
- Verdikt as the non-executing governance gateway for AI proposals
- PostgreSQL for durable state
- NATS JetStream for durable event and remediation delivery
- Redis for lightweight cache and coordination
- Prometheus, Alertmanager, Loki, Grafana, and OTel Collector for observability
- Docker Compose instead of Kubernetes

The default local profile keeps the AI service lightweight and mock-friendly. Ollama and Gemini can be enabled explicitly.

## Optional Helios Integration

Argus can delegate approved remediation execution to an external Helios control plane.

- `ARGUS_REMEDIATION_EXECUTOR=local` keeps execution inside Argus
- `ARGUS_REMEDIATION_EXECUTOR=helios` submits an execution workflow to Helios
- `ARGUS_HELIOS_BASE_URL` points at the Helios API
- `ARGUS_HELIOS_ADMIN_TOKEN` authenticates workflow submission and status reads

In the current bridge, Argus submits a trusted Helios `persist_artifact` workflow that records the remediation intent and execution metadata using Helios's durable execution path. This is intentional: Helios is now integrated as a real execution backend, while action-specific Helios remediation handlers can be added later without changing Argus policy or incident logic.

## Architecture

```text
Observability signals -> Argus API -> Deterministic RCA -> AI advisory
                                      |                 |             |
                                      |                 |             v
                                      |                 |      Verdikt PROPOSE_ONLY
                                      |                 |             |
                                      v                 v             v
                                 PostgreSQL       Go Policy     Typed suggestions
                                      |                 |             |
                                      v                 v             |
                                  Audit Log      Durable approval <---+
                                                        |
                                             Slack / signed webhook
                                                        |
                                                        v
                                                NATS / Helios executor
```

## Quick Start

`make up` bootstraps Verdikt beside Argus when needed. Compose uses only a relative, overridable build context and has no machine-specific imports.

```bash
make up
make seed
export ARGUS_API_TOKEN=local-admin-token
curl http://localhost:8080/healthz
curl -H "Authorization: Bearer local-viewer-token" http://localhost:8080/v1/incidents
```

## One-Command Demo

```bash
make demo-postgres-exhaustion
```

That flow:

- injects a demo postgres exhaustion scenario
- posts an Alertmanager-style webhook
- creates or reuses an incident
- generates deterministic RCA
- proposes policy-gated remediation
- writes JSON evidence under `artifacts/demo-evidence/postgres_connection_exhaustion/`

## Local Profiles

Normal profile:

- postgres
- redis
- nats
- argus-api
- argus-worker
- argus-ai
- verdikt
- prometheus
- grafana
- loki
- otel-collector
- payments-api

Full profile:

- everything above
- alertmanager
- nginx
- notification-api
- failure-injector
- optional ollama

## Local RBAC

Argus uses simple local Bearer tokens for demo-safe RBAC:

- `local-admin-token`: admin, full access
- `local-operator-token`: operator, incident/RCA/remediation workflow access
- `local-viewer-token`: viewer, read-only access

Configure tokens with `ARGUS_AUTH_TOKENS` using `token:role:email` entries. Health, readiness, and metrics stay public for local probes; `/v1/*` APIs require `Authorization: Bearer <token>`.

## Governed AI Proposals

`POST /v1/incidents/{incident_id}/remediations/suggest` makes the authenticated Go control plane derive candidates and call the internal AI endpoint. The AI service accepts only Argus deterministic candidates. Model output is strict JSON, unknown fields fail closed, and each surviving proposal is sent to Verdikt's authenticated `/api/evaluate` endpoint. Verdikt returns `PROPOSE_ONLY` with `executed: false`; it never calls an upstream tool. Actual remediation still requires the independent Go policy, RBAC, approval, idempotency, and worker path.

Alert titles and log evidence are treated as untrusted data. Direct prompt-injection patterns and invisible Unicode controls are replaced with hashed placeholders before prompting, with block metrics exported to Prometheus.

A captured end-to-end governance run is committed at [docs/demo-evidence/ai-governance-verdikt.json](docs/demo-evidence/ai-governance-verdikt.json).

## Safety Model

- no arbitrary shell execution from the API
- remediations are registered typed handlers
- every remediation supports dry-run
- every remediation has an idempotency key
- medium-risk actions create a PostgreSQL-backed approval request
- Slack or signed generic webhooks notify the on-call approver
- approval and denial require an authenticated identity and a reason
- the proposer cannot approve their own action by default
- unanswered requests escalate and then expire the remediation
- high-risk actions are blocked
- every state-changing operation writes audit logs
- duplicate alerts are deduplicated
- duplicate remediation executions are ignored

## Human Approval

The policy flag is not treated as approval. When policy returns `requires_approval`, Argus creates an `approval_requests` row bound to the exact remediation ID, action, target, incident, and deadline. Configure `ARGUS_APPROVAL_WEBHOOK_URL` with `ARGUS_APPROVAL_WEBHOOK_MODE=slack` for Slack notifications, or `generic` for a signed JSON notification. Generic payloads carry `X-Argus-Signature-256` when `ARGUS_APPROVAL_WEBHOOK_SECRET` is set.

Slack can complete the decision inside Slack: Argus verifies Slack's HMAC signature and five-minute replay window, checks an explicit `SLACK_USER_ID=argus-identity` allow-list, opens a modal that requires the approver's reason, and records the mapped identity. This requires a free Slack app with interactivity pointed at `/v1/approval-callbacks/slack`, plus `ARGUS_SLACK_SIGNING_SECRET`, `ARGUS_SLACK_BOT_TOKEN`, and `ARGUS_SLACK_APPROVERS`.

Approvers use the notification's decision endpoint or the CLI:

```bash
argus remediation approve rem_123 \
  --token local-admin-token \
  --reason "Reviewed RCA evidence; dry-run is scoped to payments-api"
```

Identity comes from the authenticated bearer token, never the request body. The approval decision, remediation transition, and audit entries commit in one PostgreSQL transaction. A background controller escalates once at `ARGUS_APPROVAL_ESCALATE_AFTER` and moves unanswered requests and their remediations to `expired`/`timed_out` at `ARGUS_APPROVAL_TIMEOUT`.

## Current V1 Scope

This repository includes:

- Go API, worker, CLI, and failure injector
- deterministic incident ingestion and deduplication
- deterministic incident correlation and RCA scoring
- advisory AI service with `mock`, `ollama`, and `gemini` adapters
- local observability configuration
- Docker Compose profiles
- docs, ADRs, migrations, scripts, committed demo evidence, dashboards, alerts, and CI checks

See [docs/architecture.md](docs/architecture.md), [docs/local-dev.md](docs/local-dev.md), [docs/remediation-safety.md](docs/remediation-safety.md), and [docs/demo-evidence](docs/demo-evidence/README.md).

## License

This project is licensed under the Apache License 2.0. You may use, modify, and distribute the code, including for commercial purposes, as long as you preserve the license notice and include any required attribution. The software is provided without warranties or liability. See [LICENSE](LICENSE) for the full terms.
