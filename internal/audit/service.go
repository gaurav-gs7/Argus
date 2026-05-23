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
	ID           string         `json:"id"`
	ActorID      string         `json:"actor_id,omitempty"`
	ActorType    string         `json:"actor_type"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	BeforeState  map[string]any `json:"before_state,omitempty"`
	AfterState   map[string]any `json:"after_state,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
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

	beforeJSON, _ := json.Marshal(entry.BeforeState)
	afterJSON, _ := json.Marshal(entry.AfterState)
	metadataJSON, _ := json.Marshal(entry.Metadata)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, actor_id, actor_type, action, resource_type, resource_id,
			request_id, ip_address, before_state, after_state, metadata, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`,
		entry.ID, entry.ActorID, entry.ActorType, entry.Action, entry.ResourceType, entry.ResourceID,
		entry.RequestID, entry.IPAddress, beforeJSON, afterJSON, metadataJSON, entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}

	return nil
}

func (s *Service) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor_id, actor_type, action, resource_type, resource_id, request_id, ip_address,
		       before_state, after_state, metadata, created_at
		FROM audit_logs
		ORDER BY created_at DESC
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
