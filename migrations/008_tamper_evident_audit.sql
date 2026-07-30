-- The Argus migration runner backfills legacy rows with canonical SHA-256 hashes
-- before applying the NOT NULL constraints below. Keep this migration paired
-- with audit.MigrateLedger; SQL alone cannot reproduce its canonical JSON hash.

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS chain_position BIGINT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash CHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash CHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version SMALLINT;

CREATE TABLE IF NOT EXISTS audit_chain_state (
    chain_id SMALLINT PRIMARY KEY CHECK (chain_id = 1),
    last_position BIGINT NOT NULL CHECK (last_position >= 0),
    last_hash CHAR(64) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_position ON audit_logs(chain_position);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_logs(entry_hash);

CREATE OR REPLACE FUNCTION reject_audit_log_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is forbidden', TG_OP
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_reject_mutation ON audit_logs;
CREATE TRIGGER audit_logs_reject_mutation
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation();

DROP TRIGGER IF EXISTS audit_logs_reject_truncate ON audit_logs;
CREATE TRIGGER audit_logs_reject_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_log_mutation();
