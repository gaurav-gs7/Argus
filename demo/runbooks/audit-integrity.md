# Audit Chain Integrity Violation

## Trigger

`ArgusAuditChainIntegrityViolation` fires when `argus_audit_chain_integrity` is `0`.

## Immediate Actions

1. Freeze non-essential administrative changes and preserve PostgreSQL snapshots and Argus logs.
2. Run `argus audit verify` with an admin OIDC token and record the first invalid position, expected hash, actual hash, and persisted head.
3. Do not update, delete, truncate, or automatically re-hash audit rows.
4. Compare the current head with the latest externally retained head or incident evidence bundle, if available.
5. Restrict database-owner access and investigate migrations, manual SQL, compromised credentials, and storage corruption.

## Recovery

Restore from a known-good backup into an isolated database and verify the chain before resuming writes. Preserve the suspect database for forensics. A chain must never be silently repaired in place.
