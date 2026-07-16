# Integration Tests

`make integration-test` starts disposable PostgreSQL and NATS JetStream
containers, then runs the integration cases colocated with the affected Go
packages:

- `internal/incidents`: migrations, Alertmanager ingestion, incident grouping,
  signals, timeline entries, and audit persistence.
- `internal/queue`: stream creation, event publication, and durable delivery.

Both cases are also run by the `integration` GitHub Actions job. They skip during
ordinary `go test ./...` runs unless `ARGUS_TEST_POSTGRES_DSN` and
`ARGUS_TEST_NATS_URL` are set.
