# Audit Integrity

Argus treats auditability as a correctness property, not only a logging concern.

## Chain Format

Every `audit_logs` row contains:

- `chain_position`: contiguous position starting at one
- `previous_hash`: SHA-256 hash of the preceding entry, or the all-zero genesis hash
- `entry_hash`: SHA-256 of the canonical entry payload
- `hash_version`: format version, currently `1`

The canonical payload includes the chain metadata, immutable audit ID, OIDC-scoped actor identity, action, resource, request ID, IP address, before/after state, metadata, and UTC microsecond timestamp. JSON object keys are sorted and numbers retain their original decimal representation.

## Serialization

`audit_chain_state` stores the current position and head hash. Every append locks its single state row with `SELECT ... FOR UPDATE`, inserts the new ledger row, and advances the head in the same transaction. API, worker, and approval writers therefore cannot create chain forks. Approval audit entries remain atomic with their approval and remediation state transitions.

## Append-Only Enforcement

PostgreSQL triggers reject row updates, deletes, and table truncation. Required chain columns and unique indexes reject incomplete or duplicate direct inserts. The verifier checks:

1. contiguous positions
2. supported hash versions and valid hash encoding
3. each `previous_hash` link
4. recomputed canonical entry hashes
5. ledger length against the persisted head position
6. final entry hash against the persisted head hash

Argus verifies at startup, every minute, and through `GET /v1/audit/verify`. Integrity state is exported through Prometheus and a failed check raises `ArgusAuditChainIntegrityViolation`.

## Legacy Upgrade

The application migration detects a fully legacy, unchained table and backfills it once in deterministic `created_at, id` order. It refuses partially chained data or a chained ledger without its persisted head. Subsequent startups never recompute or repair hashes, because doing so would hide tampering.

## Trust Boundary

The local design detects accidental corruption, SQL mutation attempts, application compromise without schema-owner privileges, deleted tail rows, and privileged trigger bypass that does not also forge the head and full chain.

A PostgreSQL owner can ultimately drop controls and rewrite the ledger, chain, and head together. Regulated production deployments should periodically export and sign the head hash into an independently administered immutable store, transparency service, or WORM archive. External anchoring is excluded from the laptop-friendly v1 profile.
