# Local Development

## Prerequisites

- Docker Desktop
- Go 1.26.5+
- Python 3.11-3.13 if running the AI service outside Docker
- Verdikt cloned beside Argus (Compose uses `../Verdikt`, overridable with `VERDIKT_BUILD_CONTEXT`)

The normal Compose profile includes a resource-capped local Keycloak identity provider. It adds no paid dependency and keeps the complete stack practical on an 8 GB Apple Silicon laptop.

On the M2/8 GB validation profile, the complete normal stack used about 1.2 GiB after an authenticated incident demo; Keycloak accounted for roughly 550 MiB of that total. Its optimized image avoids repeating Quarkus augmentation on each container recreation.

## Boot

```bash
make up
make seed
```

## Useful Endpoints

- API: `http://localhost:8080`
- AI service: `http://localhost:8090`
- Verdikt governance: `http://localhost:8081`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Payments API: `http://localhost:9001`

## Recommended LLM Modes

- `mock`: safest default for low-memory laptops
- `ollama`: use `qwen2.5:1.5b` or `llama3.2:1b`
- `gemini`: optional free-tier fallback for advisory summaries

## Optional Helios Execution Backend

If Helios is already running on your laptop, Argus can delegate remediation execution to it:

```bash
export ARGUS_REMEDIATION_EXECUTOR=helios
export ARGUS_HELIOS_BASE_URL=http://host.docker.internal:8080
export ARGUS_HELIOS_ADMIN_TOKEN=change-me-admin-token
```

For Docker Compose on the same Mac, `host.docker.internal` is the simplest default if Helios is running outside the Argus Compose project.

## Suggested Flow

```bash
make demo-postgres-exhaustion
export ARGUS_API_TOKEN="$(./scripts/oidc-token.sh viewer)"
curl -H "Authorization: Bearer ${ARGUS_API_TOKEN}" http://localhost:8080/v1/incidents
```

The demo obtains separate short-lived operator and admin JWTs through the OIDC client-credentials flow, proves that self-approval is denied, records the immutable service-account subjects, executes a safe dry-run, and captures the resulting approval and audit evidence.

## Production OIDC

The bundled realm is only for local automation. For a deployed Argus instance:

```bash
export ARGUS_OIDC_ISSUER_URL=https://identity.example.com/realms/production
export ARGUS_OIDC_AUDIENCE=argus-api
export ARGUS_OIDC_JWKS_URL=
export ARGUS_OIDC_ROLE_CLAIM=realm_access.roles
export ARGUS_OIDC_ROLE_MAPPINGS=platform-admin=admin,oncall-sre=operator,incident-reader=viewer
export ARGUS_OIDC_SIGNING_ALGS=RS256
export ARGUS_ENV=production
```

Use Authorization Code with PKCE or your organization's existing login flow for humans. Do not deploy the bundled Keycloak HTTP/dev-file configuration or demo service-account secrets. Argus performs OIDC discovery at startup when `ARGUS_OIDC_JWKS_URL` is empty, caches the provider key set, and refreshes it on key rotation.

## Optional Approval Notifications

No paid service or extra local process is required. Approval requests remain durable and usable through the API/CLI when notification delivery is disabled.

Generic signed webhook:

```bash
export ARGUS_APPROVAL_WEBHOOK_URL=https://example.internal/argus-approvals
export ARGUS_APPROVAL_WEBHOOK_MODE=generic
export ARGUS_APPROVAL_WEBHOOK_SECRET=replace-with-a-long-random-secret
```

Slack incoming webhook:

```bash
export ARGUS_APPROVAL_WEBHOOK_URL=https://hooks.slack.com/services/...
export ARGUS_APPROVAL_WEBHOOK_MODE=slack
export ARGUS_SLACK_SIGNING_SECRET=...
export ARGUS_SLACK_BOT_TOKEN=xoxb-...
export ARGUS_SLACK_APPROVERS=U01234567=https://identity.example.com/realms/production#oidc-subject
```

Configure the Slack app's interactivity request URL as `https://<argus-host>/v1/approval-callbacks/slack` and grant the bot `chat:write`. Button clicks open a modal that requires a reason. Argus verifies Slack's request signature and timestamp, maps the Slack user ID to the same `issuer#sub` identity used by OIDC, and applies the same four-eyes and atomic audit transaction as the API path. Possession of a webhook URL is never approval authority.
