# Kubernetes Packaging

Argus uses Docker Compose for supported local development. The Kubernetes packaging is a production-shaped stretch path that makes deployment assumptions explicit without adding a local cluster to the MacBook Air workflow.

## What Is Included

- Helm chart at `deploy/helm/argus`
- Kustomize base plus `local` and `production` overlays at `deploy/kustomize`
- API, worker, and optional AI deployments (worker replicas pull from one durable JetStream consumer, so `worker.replicas` above 1 splits remediation work)
- non-root pods, dropped Linux capabilities, read-only root filesystems, and disabled service-account token mounts
- CPU and memory requests/limits sized conservatively
- API and AI health probes
- ClusterIP services, optional ingress, network policies, PDBs, and API HPA
- Prometheus annotations in Kustomize and an optional `ServiceMonitor` in Helm
- CI linting and deterministic rendering, plus a kind-cluster job (`scripts/test-k8s-e2e.sh`) that installs the chart, checks the migrate init container and verify mode, upgrades and rolls back, and starts pods against a newer compatible schema and refuses a breaking one

## Schema Migrations

Both renderers run `argus-api migrate` as an init container on each API pod and start the API and worker with `ARGUS_MIGRATIONS=verify`. A pod therefore never serves traffic against a schema it does not know: the init container applies pending migrations under a PostgreSQL advisory lock (concurrent pods serialize), and verifying processes wait on the same lock and exit if a migration they need is still missing. Put a DDL-capable role in `ARGUS_MIGRATION_POSTGRES_DSN` in the runtime Secret to keep those privileges out of the long-running containers; without it, migrations use `ARGUS_POSTGRES_DSN`.

Migrations are backward compatible by default, so during a rolling update, and after `helm rollback`, the previous release keeps running against the newer schema and logs which migrations it does not know. A migration marked `-- argus:breaking` makes older pods refuse to start. Helm users can return to migrate-at-startup with `migrations.separateStep=false`.

## Deliberate Boundaries

The manifests do not install stateful or organization-owned dependencies. A target platform must provide:

- PostgreSQL with backups, TLS, connection limits, and an availability plan
- NATS JetStream with persistent storage and a disruption plan
- Redis, if coordination and cache features are enabled
- an HTTPS OIDC provider with mapped Argus roles
- Verdikt and any optional Gemini or Ollama backend
- ingress, DNS, TLS, a network-policy-capable CNI, and metrics-server for HPA
- a secret manager or external-secrets controller

The example `argus-runtime` Secret is not included by either renderer. Do not commit a populated copy.

## Helm

Validate both the conservative and production value sets:

```bash
make helm-check
```

Inspect the production render before applying it:

```bash
helm template argus deploy/helm/argus \
  --namespace argus \
  -f deploy/helm/argus/values-production.yaml
```

After publishing the three images and replacing all example values, install with:

```bash
kubectl create namespace argus
kubectl -n argus apply -f deploy/helm/argus/secret.example.yaml
helm upgrade --install argus deploy/helm/argus \
  --namespace argus \
  -f deploy/helm/argus/values-production.yaml
```

The Secret command above is for an isolated test only. Production should materialize `argus-runtime` from the platform secret manager.

## Kustomize

Render the lightweight example:

```bash
kubectl kustomize deploy/kustomize/overlays/local
```

Render the production example:

```bash
kubectl kustomize deploy/kustomize/overlays/production
```

Kustomize is useful when operators prefer transparent overlays. Helm is the primary configurable packaging path.

## MacBook Air Guidance

Do not run Kubernetes alongside the full Compose profile on an 8 GB machine. Use Compose for normal work and use `make k8s-check` only for static rendering. If a local cluster is needed for an interview demo, stop Compose first, use the mock AI backend, keep one replica per workload, and allocate no more than roughly 3 GB to the cluster.

## Production Readiness Gap

CI installs, upgrades and rolls back the chart on a single-node kind cluster with disposable PostgreSQL and NATS. That proves the chart works on Kubernetes, not operational readiness. Before production use, add:

1. multi-node and managed-cluster install tests with real ingress, TLS and network-policy enforcement
2. signed multi-architecture image publishing with SBOMs and provenance
3. external secret integration
4. backup/restore and JetStream recovery exercises
5. load, disruption, rollback, and network-policy tests
6. a policy for breaking migrations: compatible migrations (the default) let the previous release keep running during a rolling update or a rollback, but a migration marked `-- argus:breaking` stops older pods, so it needs a maintenance window or a two-release expand/contract

