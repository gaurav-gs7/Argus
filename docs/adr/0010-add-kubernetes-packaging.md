# ADR 0010: Add Kubernetes Packaging Without Replacing Compose

## Status

Accepted

## Context

Argus must remain comfortable on a MacBook Air M2 with 8 GB RAM, where a local Kubernetes cluster adds cost without improving the main incident-response demo. Compose alone, however, leaves the production deployment contract implicit.

## Decision

Docker Compose remains the supported local runtime. Argus also ships:

- a configurable Helm chart for API, worker, and AI workloads
- a readable Kustomize base with local and production overlays
- static lint and render checks in CI

The Kubernetes packaging does not install PostgreSQL, Redis, NATS, OIDC, Verdikt, ingress, TLS, or secret-management infrastructure. Those are platform dependencies in a real environment.

## Consequences

- local development stays within the existing resource envelope
- production concerns such as probes, security contexts, resource limits, disruption budgets, autoscaling, ingress, and network policy become reviewable
- operators can choose Helm values or Kustomize overlays
- the repository does not claim live-cluster production certification
- cluster install, upgrade, rollback, and failure testing remain required before production use
