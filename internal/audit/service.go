package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gauravgs7/argus/internal/common"
)

type Entry struct {
	ID            string         `json:"id"`
	ActorID       string         `json:"actor_id,omitempty"`
	ActorType     string         `json:"actor_type"`
	Action        string         `json:"action"`
	ResourceType  string         `json:"resource_type"`
	ResourceID    string         `json:"resource_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	IPAddress     string         `json:"ip_address,omitempty"`
	BeforeState   map[string]any `json:"before_state,omitempty"`
	AfterState    map[string]any `json:"after_state,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ChainPosition int64          `json:"chain_position"`
	PreviousHash  string         `json:"previous_hash"`
	EntryHash     string         `json:"entry_hash"`
	HashVersion   int            `json:"hash_version"`
}

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Write(ctx context.Context, entry Entry) error {
	if entry.ID == "" {
		entry.ID = common.NewID("aud")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit write: %w", err)
	}
	defer tx.Rollback()
	if err := WriteTx(ctx, tx, entry); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit write: %w", err)
	}
	return nil
}

func WriteTx(ctx context.Context, tx *sql.Tx, entry Entry) error {
	if entry.ID == "" {
		entry.ID = common.NewID("aud")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	entry.CreatedAt = entry.CreatedAt.UTC().Truncate(time.Microsecond)
	prepared, err := prepareEntry(entry)
	if err != nil {
		return fmt.Errorf("prepare audit log: %w", err)
	}

	var previousPosition int64
	var previousHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT last_position, last_hash
		FROM audit_chain_state
		WHERE chain_id = 1
		FOR UPDATE
	`).Scan(&previousPosition, &previousHash); err != nil {
		return fmt.Errorf("lock audit chain head: %w", err)
	}
	position := previousPosition + 1
	entryHash, err := calculateHash(entry, position, previousHash, prepared.beforeJSON, prepared.afterJSON, prepared.metadataJSON)
	if err != nil {
		return fmt.Errorf("hash audit log: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, actor_id, actor_type, action, resource_type, resource_id,
			request_id, ip_address, before_state, after_state, metadata, created_at,
			chain_position, previous_hash, entry_hash, hash_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`,
		entry.ID, entry.ActorID, entry.ActorType, entry.Action, entry.ResourceType, entry.ResourceID,
		entry.RequestID, entry.IPAddress, prepared.beforeJSON, prepared.afterJSON, prepared.metadataJSON, entry.CreatedAt,
		position, previousHash, entryHash, HashVersion,
	)
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE audit_chain_state
		SET last_position = $1, last_hash = $2, updated_at = now()
		WHERE chain_id = 1 AND last_position = $3 AND last_hash = $4
	`, position, entryHash, previousPosition, previousHash)
	if err != nil {
		return fmt.Errorf("advance audit chain head: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return fmt.Errorf("advance audit chain head: concurrent or missing chain state")
	}
	return nil
}

func (s *Service) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(actor_id, ''), actor_type, action, resource_type, COALESCE(resource_id, ''),
		       COALESCE(request_id, ''), COALESCE(ip_address, ''), before_state, after_state, metadata, created_at,
		       chain_position, previous_hash, entry_hash, hash_version
		FROM audit_logs
		ORDER BY chain_position DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var entry Entry
		var beforeJSON, afterJSON, metadataJSON []byte
		if err := rows.Scan(
			&entry.ID, &entry.ActorID, &entry.ActorType, &entry.Action, &entry.ResourceType, &entry.ResourceID,
			&entry.RequestID, &entry.IPAddress, &beforeJSON, &afterJSON, &metadataJSON, &entry.CreatedAt,
			&entry.ChainPosition, &entry.PreviousHash, &entry.EntryHash, &entry.HashVersion,
		); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}

		_ = json.Unmarshal(beforeJSON, &entry.BeforeState)
		_ = json.Unmarshal(afterJSON, &entry.AfterState)
		_ = json.Unmarshal(metadataJSON, &entry.Metadata)
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

func (s *Service) Verify(ctx context.Context) (Verification, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Verification{}, fmt.Errorf("begin audit verification: %w", err)
	}
	defer tx.Rollback()

	var statePosition int64
	var stateHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT last_position, last_hash FROM audit_chain_state WHERE chain_id = 1
	`).Scan(&statePosition, &stateHash); err != nil {
		return Verification{}, fmt.Errorf("read audit chain head: %w", err)
	}
	report := Verification{
		Valid:        true,
		HeadPosition: statePosition,
		HeadHash:     stateHash,
		VerifiedAt:   time.Now().UTC(),
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(actor_id, ''), actor_type, action, resource_type, COALESCE(resource_id, ''),
		       COALESCE(request_id, ''), COALESCE(ip_address, ''), COALESCE(before_state, 'null'::jsonb),
		       COALESCE(after_state, 'null'::jsonb), COALESCE(metadata, 'null'::jsonb), created_at,
		       chain_position, previous_hash, entry_hash, hash_version
		FROM audit_logs
		ORDER BY chain_position ASC
	`)
	if err != nil {
		return Verification{}, fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close()

	previousHash := GenesisHash
	var expectedPosition int64 = 1
	for rows.Next() {
		var entry Entry
		var beforeJSON, afterJSON, metadataJSON []byte
		if err := rows.Scan(
			&entry.ID, &entry.ActorID, &entry.ActorType, &entry.Action, &entry.ResourceType, &entry.ResourceID,
			&entry.RequestID, &entry.IPAddress, &beforeJSON, &afterJSON, &metadataJSON, &entry.CreatedAt,
			&entry.ChainPosition, &entry.PreviousHash, &entry.EntryHash, &entry.HashVersion,
		); err != nil {
			return Verification{}, fmt.Errorf("scan audit chain: %w", err)
		}
		report.EntriesVerified++
		if entry.ChainPosition != expectedPosition {
			return invalidReport(report, entry.ChainPosition, fmt.Sprintf("chain position gap: expected %d", expectedPosition), "", ""), nil
		}
		if entry.HashVersion != HashVersion {
			return invalidReport(report, entry.ChainPosition, fmt.Sprintf("unsupported hash version %d", entry.HashVersion), "", ""), nil
		}
		if !validHash(entry.PreviousHash) || !validHash(entry.EntryHash) {
			return invalidReport(report, entry.ChainPosition, "malformed chain hash", "", entry.EntryHash), nil
		}
		if entry.PreviousHash != previousHash {
			return invalidReport(report, entry.ChainPosition, "previous hash does not match prior entry", previousHash, entry.PreviousHash), nil
		}
		expectedHash, err := calculateHash(entry, entry.ChainPosition, entry.PreviousHash, beforeJSON, afterJSON, metadataJSON)
		if err != nil {
			return Verification{}, fmt.Errorf("recompute audit hash at position %d: %w", entry.ChainPosition, err)
		}
		if entry.EntryHash != expectedHash {
			return invalidReport(report, entry.ChainPosition, "entry hash mismatch", expectedHash, entry.EntryHash), nil
		}
		previousHash = entry.EntryHash
		expectedPosition++
	}
	if err := rows.Err(); err != nil {
		return Verification{}, fmt.Errorf("iterate audit chain: %w", err)
	}
	if report.EntriesVerified != statePosition {
		return invalidReport(report, report.EntriesVerified, "persisted head position does not match ledger length", fmt.Sprint(report.EntriesVerified), fmt.Sprint(statePosition)), nil
	}
	if previousHash != stateHash {
		return invalidReport(report, statePosition, "persisted head hash does not match ledger head", previousHash, stateHash), nil
	}
	if err := tx.Commit(); err != nil {
		return Verification{}, fmt.Errorf("complete audit verification: %w", err)
	}
	return report, nil
}

func invalidReport(report Verification, position int64, reason, expected, actual string) Verification {
	report.Valid = false
	report.InvalidPosition = position
	report.Reason = reason
	report.ExpectedHash = expected
	report.ActualHash = actual
	return report
}
