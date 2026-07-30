# ADR 0008: Use an append-only hash-chained audit ledger

## Status

Accepted

## Decision

Argus stores audit events in a globally ordered SHA-256 chain. A PostgreSQL chain-head row serializes append operations inside the caller's transaction. Database triggers reject updates, deletes, and truncation. Argus continuously verifies canonical entry hashes, chain links, positions, and the persisted head.

## Consequences

Concurrent API, worker, and approval transactions produce one verifiable history without adding another service. Legacy rows receive a deterministic one-time backfill, while partially migrated or headless chains fail migration. Audit storage is append-only, so tests and retention tooling must not delete individual records.

This provides tamper evidence within the PostgreSQL trust boundary, not non-repudiation against a database owner. Production environments requiring that stronger property must anchor signed head hashes outside the Argus database.
