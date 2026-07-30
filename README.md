# Argus

Argus is a production-style SRE control plane for incident detection, deterministic RCA, and safe policy-gated auto-remediation.

It is designed to feel like an internal reliability platform rather than a generic AI log chatbot:

- incidents are created from observability signals
- RCA is built from deterministic evidence first
- the LLM is advisory only and never in the correctness path
- Verdikt governs every AI remediation proposal in policy-only mode
- remediations are typed, idempotent, policy-gated, and recorded in a tamper-evident audit ledger
- medium-risk actions enter a durable, identity-bound human approval workflow

## Why This Stack

This repository is intentionally optimized for local development on a MacBook Air M2 with 8 GB RAM:

- Go for the control plane, worker, CLI, and demo workloads
- Python FastAPI for the advisory AI service
- Verdikt as the non-executing governance gateway for AI proposals
- PostgreSQL for durable state
- NATS JetStream for durable event and remediation delivery
- Redis for lightweight cache and coordination
- OIDC/JWT authentication with a resource-capped local Keycloak realm
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
OIDC/JWKS ---------------->+
Observability signals -> Argus API -> Deterministic RCA -> AI advisory
                                      |                 |             |
                                      |                 |             v
                                      |                 |      Verdikt PROPOSE_ONLY
                                      |                 |             |
                                      v                 v             v
                                 PostgreSQL       Go Policy     Typed suggestions
                                      |                 |             |
                                      v                 v             |
                              Audit Hash Chain   Durable approval <---+
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
export ARGUS_API_TOKEN="$(./scripts/oidc-token.sh viewer)"
curl http://localhost:8080/healthz
curl -H "Authorization: Bearer ${ARGUS_API_TOKEN}" http://localhost:8080/v1/incidents
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
- keycloak
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

## OIDC Authentication And RBAC

Argus accepts short-lived, asymmetrically signed OIDC JWT access tokens. It validates the signature through the provider's rotating JWKS, exact issuer, `argus-api` audience, expiry, and an RS256 allow-list before reading identity or role claims. Provider roles are explicitly mapped to `admin`, `operator`, or `viewer`; missing, unknown, or conflicting Argus roles fail closed.

The local Compose profile includes a 768 MiB-capped Keycloak instance and three separate service accounts for repeatable automation:

```bash
export ARGUS_API_TOKEN="$(./scripts/oidc-token.sh operator)"
```

Those clients exist only in the local realm. Production uses the organization's OIDC provider over HTTPS, provider-managed users/groups, and secrets outside the repository. Set `ARGUS_OIDC_ISSUER_URL`, `ARGUS_OIDC_AUDIENCE`, and `ARGUS_OIDC_ROLE_MAPPINGS`; normally leave `ARGUS_OIDC_JWKS_URL` empty so standards-based discovery supplies the rotating key set.

Health, readiness, metrics, and the independently HMAC-verified Slack callback stay public. Every other `/v1/*` route requires a verified OIDC token. Authorization uses the mapped role, while audit and four-eyes controls use the immutable `issuer#sub` identity rather than mutable email or caller-provided fields.

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
- every state-changing operation appends to a verifiable SHA-256 audit hash chain
- duplicate alerts are deduplicated
- duplicate remediation executions are ignored

## Tamper-Evident Audit Ledger

Audit records are append-only and ordered by a transactionally locked chain head. Each entry stores its chain position, prior hash, SHA-256 entry hash, and hash version. The hash covers canonical JSON for the actor, action, resource, request context, before/after state, metadata, timestamp, and chain metadata. Approval decisions append their audit records inside the same PostgreSQL transaction as the approval and remediation transitions.

PostgreSQL triggers reject `UPDATE`, `DELETE`, and `TRUNCATE` on `audit_logs`. Argus verifies the complete chain at startup, every minute, and on demand:

```bash
export ARGUS_API_TOKEN="$(./scripts/oidc-token.sh admin)"
argus audit verify
```

Prometheus exposes `argus_audit_chain_integrity`, `argus_audit_chain_head_position`, and verification counters. The persisted chain head detects missing tail entries as well as modified or reordered rows. For a threat model that includes a compromised PostgreSQL owner rewriting both the ledger and its head, export and sign the head hash in an external immutable store; that external anchoring is intentionally outside the local v1 profile.

## Human Approval

The policy flag is not treated as approval. When policy returns `requires_approval`, Argus creates an `approval_requests` row bound to the exact remediation ID, action, target, incident, and deadline. Configure `ARGUS_APPROVAL_WEBHOOK_URL` with `ARGUS_APPROVAL_WEBHOOK_MODE=slack` for Slack notifications, or `generic` for a signed JSON notification. Generic payloads carry `X-Argus-Signature-256` when `ARGUS_APPROVAL_WEBHOOK_SECRET` is set.

Slack can complete the decision inside Slack: Argus verifies Slack's HMAC signature and five-minute replay window, checks an explicit `SLACK_USER_ID=argus-identity` allow-list, opens a modal that requires the approver's reason, and records the mapped identity. This requires a free Slack app with interactivity pointed at `/v1/approval-callbacks/slack`, plus `ARGUS_SLACK_SIGNING_SECRET`, `ARGUS_SLACK_BOT_TOKEN`, and `ARGUS_SLACK_APPROVERS`.

Approvers use the notification's decision endpoint or the CLI:

```bash
argus remediation approve rem_123 \
  --token "$(./scripts/oidc-token.sh admin)" \
  --reason "Reviewed RCA evidence; dry-run is scoped to payments-api"
```

Identity comes from the verified OIDC issuer and subject, never the request body. The approval decision, remediation transition, and audit entries commit in one PostgreSQL transaction. A background controller escalates once at `ARGUS_APPROVAL_ESCALATE_AFTER` and moves unanswered requests and their remediations to `expired`/`timed_out` at `ARGUS_APPROVAL_TIMEOUT`.

## Current V1 Scope

This repository includes:

- Go API, worker, CLI, and failure injector
- deterministic incident ingestion and deduplication
- deterministic incident correlation and RCA scoring
- advisory AI service with `mock`, `ollama`, and `gemini` adapters
- local observability configuration
- Docker Compose profiles
- docs, ADRs, migrations, scripts, committed demo evidence, dashboards, alerts, and CI checks

See [docs/architecture.md](docs/architecture.md), [docs/audit-integrity.md](docs/audit-integrity.md), [docs/local-dev.md](docs/local-dev.md), [docs/remediation-safety.md](docs/remediation-safety.md), and [docs/demo-evidence](docs/demo-evidence/README.md).

## License

This project is licensed under the Apache License 2.0. You may use, modify, and distribute the code, including for commercial purposes, as long as you preserve the license notice and include any required attribution. The software is provided without warranties or liability. See [LICENSE](LICENSE) for the full terms.
