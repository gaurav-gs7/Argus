# Kubernetes Packaging

Argus uses Docker Compose for supported local development. The Kubernetes packaging is a production-shaped stretch path that makes deployment assumptions explicit without adding a local cluster to the MacBook Air workflow.

## What Is Included

- Helm chart at `deploy/helm/argus`
- Kustomize base plus `local` and `production` overlays at `deploy/kustomize`
- API, worker, and optional AI deployments
- non-root pods, dropped Linux capabilities, read-only root filesystems, and disabled service-account token mounts
- CPU and memory requests/limits sized conservatively
- API and AI health probes
- ClusterIP services, optional ingress, network policies, PDBs, and API HPA
- Prometheus annotations in Kustomize and an optional `ServiceMonitor` in Helm
- CI linting and deterministic rendering

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

CI proves chart linting and deterministic manifest generation, not cluster compatibility or operational readiness. Before production use, add:

1. ephemeral-cluster install and upgrade tests
2. signed multi-architecture image publishing with SBOMs and provenance
3. external secret integration
4. backup/restore and JetStream recovery exercises
5. load, disruption, rollback, and network-policy tests
6. an explicit database migration job/versioning strategy for independently scaled releases

