# Postgres Connection Exhaustion

## Symptoms

- API latency and 5xx increase together
- connection acquisition timeouts appear in application logs
- connection pool utilization exceeds 90%

## Safe Actions

1. Drain only demo application connections.
2. Restart the demo service if saturation persists.
