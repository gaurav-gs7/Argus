package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	HashVersion = 1
	GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Verification struct {
	Valid           bool      `json:"valid"`
	EntriesVerified int64     `json:"entries_verified"`
	HeadPosition    int64     `json:"head_position"`
	HeadHash        string    `json:"head_hash"`
	InvalidPosition int64     `json:"invalid_position,omitempty"`
	ExpectedHash    string    `json:"expected_hash,omitempty"`
	ActualHash      string    `json:"actual_hash,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	VerifiedAt      time.Time `json:"verified_at"`
}

type chainPayload struct {
	HashVersion   int             `json:"hash_version"`
	ChainPosition int64           `json:"chain_position"`
	PreviousHash  string          `json:"previous_hash"`
	ID            string          `json:"id"`
	ActorID       string          `json:"actor_id"`
	ActorType     string          `json:"actor_type"`
	Action        string          `json:"action"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	RequestID     string          `json:"request_id"`
	IPAddress     string          `json:"ip_address"`
	BeforeState   json.RawMessage `json:"before_state"`
	AfterState    json.RawMessage `json:"after_state"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     string          `json:"created_at"`
}

type preparedEntry struct {
	entry        Entry
	beforeJSON   []byte
	afterJSON    []byte
	metadataJSON []byte
}

func prepareEntry(entry Entry) (preparedEntry, error) {
	beforeJSON, err := canonicalJSON(entry.BeforeState)
	if err != nil {
		return preparedEntry{}, fmt.Errorf("canonicalize before state: %w", err)
	}
	afterJSON, err := canonicalJSON(entry.AfterState)
	if err != nil {
		return preparedEntry{}, fmt.Errorf("canonicalize after state: %w", err)
	}
	metadataJSON, err := canonicalJSON(entry.Metadata)
	if err != nil {
		return preparedEntry{}, fmt.Errorf("canonicalize metadata: %w", err)
	}
	return preparedEntry{
		entry:        entry,
		beforeJSON:   beforeJSON,
		afterJSON:    afterJSON,
		metadataJSON: metadataJSON,
	}, nil
}

func canonicalJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeRawJSON(raw)
}

func canonicalizeRawJSON(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null"), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func calculateHash(entry Entry, position int64, previousHash string, beforeJSON, afterJSON, metadataJSON []byte) (string, error) {
	beforeJSON, err := canonicalizeRawJSON(beforeJSON)
	if err != nil {
		return "", fmt.Errorf("canonicalize stored before state: %w", err)
	}
	afterJSON, err = canonicalizeRawJSON(afterJSON)
	if err != nil {
		return "", fmt.Errorf("canonicalize stored after state: %w", err)
	}
	metadataJSON, err = canonicalizeRawJSON(metadataJSON)
	if err != nil {
		return "", fmt.Errorf("canonicalize stored metadata: %w", err)
	}
	payload := chainPayload{
		HashVersion:   HashVersion,
		ChainPosition: position,
		PreviousHash:  previousHash,
		ID:            entry.ID,
		ActorID:       entry.ActorID,
		ActorType:     entry.ActorType,
		Action:        entry.Action,
		ResourceType:  entry.ResourceType,
		ResourceID:    entry.ResourceID,
		RequestID:     entry.RequestID,
		IPAddress:     entry.IPAddress,
		BeforeState:   beforeJSON,
		AfterState:    afterJSON,
		Metadata:      metadataJSON,
		CreatedAt:     entry.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal audit hash payload: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func MigrateLedger(ctx context.Context, database *sql.DB) error {
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin audit ledger migration: %w", err)
	}
	defer tx.Rollback()

	statements := []string{
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS chain_position BIGINT`,
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash CHAR(64)`,
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash CHAR(64)`,
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version SMALLINT`,
		`DROP TRIGGER IF EXISTS audit_logs_reject_mutation ON audit_logs`,
		`DROP TRIGGER IF EXISTS audit_logs_reject_truncate ON audit_logs`,
		`CREATE TABLE IF NOT EXISTS audit_chain_state (
			chain_id SMALLINT PRIMARY KEY CHECK (chain_id = 1),
			last_position BIGINT NOT NULL CHECK (last_position >= 0),
			last_hash CHAR(64) NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("prepare audit ledger schema: %w", err)
		}
	}

	var total, unchained, stateRows int64
	if err := tx.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (
				WHERE chain_position IS NULL OR previous_hash IS NULL OR entry_hash IS NULL OR hash_version IS NULL
			)
		FROM audit_logs
	`).Scan(&total, &unchained); err != nil {
		return fmt.Errorf("inspect audit ledger migration state: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_chain_state WHERE chain_id = 1`).Scan(&stateRows); err != nil {
		return fmt.Errorf("inspect audit chain head: %w", err)
	}

	switch {
	case total == 0:
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_chain_state (chain_id, last_position, last_hash, updated_at)
			VALUES (1, 0, $1, now())
			ON CONFLICT (chain_id) DO NOTHING
		`, GenesisHash); err != nil {
			return fmt.Errorf("initialize empty audit chain: %w", err)
		}
	case unchained == total:
		if stateRows != 0 {
			return fmt.Errorf("legacy audit rows found with an existing chain head; refusing ambiguous backfill")
		}
		if err := backfillLegacyRows(ctx, tx); err != nil {
			return err
		}
	case unchained > 0:
		return fmt.Errorf("partially chained audit ledger detected; manual recovery is required")
	case stateRows != 1:
		return fmt.Errorf("chained audit ledger is missing its persisted head")
	}

	finalStatements := []string{
		`ALTER TABLE audit_logs ALTER COLUMN chain_position SET NOT NULL`,
		`ALTER TABLE audit_logs ALTER COLUMN previous_hash SET NOT NULL`,
		`ALTER TABLE audit_logs ALTER COLUMN entry_hash SET NOT NULL`,
		`ALTER TABLE audit_logs ALTER COLUMN hash_version SET NOT NULL`,
		`ALTER TABLE audit_logs ALTER COLUMN hash_version SET DEFAULT 1`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_position ON audit_logs(chain_position)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_logs(entry_hash)`,
		`CREATE OR REPLACE FUNCTION reject_audit_log_mutation() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'audit_logs is append-only; % is forbidden', TG_OP
				USING ERRCODE = '55000';
		END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER audit_logs_reject_mutation
			BEFORE UPDATE OR DELETE ON audit_logs
			FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation()`,
		`CREATE TRIGGER audit_logs_reject_truncate
			BEFORE TRUNCATE ON audit_logs
			FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_log_mutation()`,
	}
	for _, statement := range finalStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("finalize audit ledger schema: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit ledger migration: %w", err)
	}
	return nil
}

func backfillLegacyRows(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(actor_id, ''), actor_type, action, resource_type, COALESCE(resource_id, ''),
		       COALESCE(request_id, ''), COALESCE(ip_address, ''), COALESCE(before_state, 'null'::jsonb),
		       COALESCE(after_state, 'null'::jsonb), COALESCE(metadata, 'null'::jsonb), created_at
		FROM audit_logs
		ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return fmt.Errorf("read legacy audit rows: %w", err)
	}

	type legacyRow struct {
		entry        Entry
		beforeJSON   []byte
		afterJSON    []byte
		metadataJSON []byte
	}
	var legacyRows []legacyRow
	for rows.Next() {
		var row legacyRow
		if err := rows.Scan(
			&row.entry.ID, &row.entry.ActorID, &row.entry.ActorType, &row.entry.Action, &row.entry.ResourceType, &row.entry.ResourceID,
			&row.entry.RequestID, &row.entry.IPAddress, &row.beforeJSON, &row.afterJSON, &row.metadataJSON, &row.entry.CreatedAt,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy audit row: %w", err)
		}
		legacyRows = append(legacyRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate legacy audit rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy audit rows: %w", err)
	}

	previousHash := GenesisHash
	var position int64
	for _, row := range legacyRows {
		position++
		entryHash, err := calculateHash(row.entry, position, previousHash, row.beforeJSON, row.afterJSON, row.metadataJSON)
		if err != nil {
			return fmt.Errorf("hash legacy audit row %q: %w", row.entry.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE audit_logs
			SET chain_position = $2, previous_hash = $3, entry_hash = $4, hash_version = $5
			WHERE id = $1
		`, row.entry.ID, position, previousHash, entryHash, HashVersion); err != nil {
			return fmt.Errorf("backfill legacy audit row %q: %w", row.entry.ID, err)
		}
		previousHash = entryHash
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_chain_state (chain_id, last_position, last_hash, updated_at)
		VALUES (1, $1, $2, now())
	`, position, previousHash); err != nil {
		return fmt.Errorf("persist backfilled audit chain head: %w", err)
	}
	return nil
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
