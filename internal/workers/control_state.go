package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

type ControlStateStore interface {
	Preview(ctx context.Context, resourceType, target string, desired map[string]any) (map[string]any, error)
	ApplyOnce(ctx context.Context, idempotencyKey, actionType, resourceType, target string, desired map[string]any) (map[string]any, error)
}

type PostgresControlStateStore struct {
	db *sql.DB
}

func NewPostgresControlStateStore(db *sql.DB) *PostgresControlStateStore {
	return &PostgresControlStateStore{db: db}
}

func (s *PostgresControlStateStore) Preview(ctx context.Context, resourceType, target string, desired map[string]any) (map[string]any, error) {
	current, err := s.currentState(ctx, resourceType, target)
	if err != nil {
		return nil, err
	}
	return stateResult("dry-run", resourceType, target, current, mergeState(current, desired), false), nil
}

func (s *PostgresControlStateStore) ApplyOnce(
	ctx context.Context,
	idempotencyKey, actionType, resourceType, target string,
	desired map[string]any,
) (map[string]any, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin control-state transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, idempotencyKey); err != nil {
		return nil, fmt.Errorf("lock remediation receipt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, resourceType+"/"+target); err != nil {
		return nil, fmt.Errorf("lock remediation target: %w", err)
	}

	var receiptJSON []byte
	err = tx.QueryRowContext(ctx, `
		SELECT result
		FROM remediation_execution_receipts
		WHERE idempotency_key = $1
	`, idempotencyKey).Scan(&receiptJSON)
	if err == nil {
		var result map[string]any
		if err := json.Unmarshal(receiptJSON, &result); err != nil {
			return nil, fmt.Errorf("decode remediation receipt: %w", err)
		}
		result["reused"] = true
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit reused remediation receipt: %w", err)
		}
		return result, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("read remediation receipt: %w", err)
	}

	current, err := currentStateTx(ctx, tx, resourceType, target)
	if err != nil {
		return nil, err
	}
	after := mergeState(current, desired)
	afterJSON, _ := json.Marshal(after)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_target_states (resource_type, target, state, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (resource_type, target) DO UPDATE
		SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at
	`, resourceType, target, afterJSON); err != nil {
		return nil, fmt.Errorf("apply remediation target state: %w", err)
	}

	result := stateResult("execute", resourceType, target, current, after, false)
	result["idempotency_key"] = idempotencyKey
	resultJSON, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_execution_receipts (idempotency_key, action_type, target, result)
		VALUES ($1, $2, $3, $4)
	`, idempotencyKey, actionType, target, resultJSON); err != nil {
		return nil, fmt.Errorf("write remediation receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit control-state remediation: %w", err)
	}
	return result, nil
}

func (s *PostgresControlStateStore) currentState(ctx context.Context, resourceType, target string) (map[string]any, error) {
	var stateJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT state FROM remediation_target_states WHERE resource_type = $1 AND target = $2
	`, resourceType, target).Scan(&stateJSON)
	return decodeState(stateJSON, err)
}

func currentStateTx(ctx context.Context, tx *sql.Tx, resourceType, target string) (map[string]any, error) {
	var stateJSON []byte
	err := tx.QueryRowContext(ctx, `
		SELECT state
		FROM remediation_target_states
		WHERE resource_type = $1 AND target = $2
		FOR UPDATE
	`, resourceType, target).Scan(&stateJSON)
	return decodeState(stateJSON, err)
}

func decodeState(stateJSON []byte, err error) (map[string]any, error) {
	if err == sql.ErrNoRows {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read remediation target state: %w", err)
	}
	var state map[string]any
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return nil, fmt.Errorf("decode remediation target state: %w", err)
	}
	return state, nil
}

func mergeState(current, desired map[string]any) map[string]any {
	merged := make(map[string]any, len(current)+len(desired))
	for key, value := range current {
		merged[key] = value
	}
	for key, value := range desired {
		merged[key] = value
	}
	return merged
}

func stateResult(mode, resourceType, target string, before, after map[string]any, reused bool) map[string]any {
	return map[string]any{
		"mode":          mode,
		"backend":       "durable-local-control-state",
		"resource_type": resourceType,
		"target":        target,
		"before":        before,
		"after":         after,
		"reused":        reused,
	}
}
