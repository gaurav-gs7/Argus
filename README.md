# Argus

Argus is a production-style SRE control plane for incident detection, deterministic RCA, and safe policy-gated auto-remediation.

It is designed to feel like an internal reliability platform rather than a generic AI log chatbot:

- incidents are created from observability signals
- RCA is built from deterministic evidence first
- the LLM is advisory only and never in the correctness path
- remediations are typed, idempotent, policy-gated, and auditable

## Why This Stack

This repository is intentionally optimized for local development on a MacBook Air M2 with 8 GB RAM:

- Go for the control plane, worker, CLI, and demo workloads
- Python FastAPI for the advisory AI service
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
Observability signals -> Argus API -> Incident Manager -> RCA Engine -> Policy Engine
                                                |                         |
                                                v                         v
                                           PostgreSQL                Remediation Proposals
                                                |                         |
                                                v                         v
                                           Audit Logs                NATS JetStream
                                                                          |
                                                                          v
                                                                  Argus Worker
                                                                          |
                                                                          v
                                                                Safe Typed Handlers
```

## Quick Start

```bash
cp .env.example .env
make up
make seed
curl http://localhost:8080/healthz
curl http://localhost:8080/v1/incidents
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

## Local Profiles

Normal profile:

- postgres
- redis
- nats
- argus-api
- argus-worker
- argus-ai
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

## Safety Model

- no arbitrary shell execution from the API
- remediations are registered typed handlers
- every remediation supports dry-run
- every remediation has an idempotency key
- medium-risk actions require approval
- high-risk actions are blocked
- every state-changing operation writes audit logs
- duplicate alerts are deduplicated
- duplicate remediation executions are ignored

## Current V1 Scope

This repository includes:

- Go API, worker, CLI, and failure injector
- deterministic incident ingestion and deduplication
- deterministic RCA scaffolding
- advisory AI service with `mock`, `ollama`, and `gemini` adapters
- local observability configuration
- Docker Compose profiles
- docs, ADRs, migrations, scripts, and baseline tests

See [docs/architecture.md](/Users/gauravgs7/Documents/Projects/Argus/docs/architecture.md), [docs/local-dev.md](/Users/gauravgs7/Documents/Projects/Argus/docs/local-dev.md), and [docs/remediation-safety.md](/Users/gauravgs7/Documents/Projects/Argus/docs/remediation-safety.md).
