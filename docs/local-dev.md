# Local Development

## Prerequisites

- Docker Desktop
- Go 1.23+
- Python 3.11+ if running the AI service outside Docker

## Boot

```bash
cp .env.example .env
make up
make seed
```

## Useful Endpoints

- API: `http://localhost:8080`
- AI service: `http://localhost:8090`
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
curl http://localhost:8080/v1/incidents
```
