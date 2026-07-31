package workers

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/db"
)

func TestPostgresControlStateApplyOnceIsConcurrentAndDurable(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	const key = "integration_resize_connection_pool"
	if _, err := database.ExecContext(ctx, `
		DELETE FROM remediation_execution_receipts WHERE idempotency_key = $1
	`, key); err != nil {
		t.Fatalf("reset execution receipt fixture: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		DELETE FROM remediation_target_states
		WHERE resource_type = 'connection_pool' AND target = 'integration-payments'
	`); err != nil {
		t.Fatalf("reset target-state fixture: %v", err)
	}

	store := NewPostgresControlStateStore(database)
	const callers = 20
	var wg sync.WaitGroup
	results := make(chan map[string]any, callers)
	errors := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.ApplyOnce(
				context.Background(), key, "resize_connection_pool",
				"connection_pool", "integration-payments", map[string]any{"max_connections": 20},
			)
			results <- result
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent ApplyOnce() error: %v", err)
		}
	}
	firstExecutions := 0
	for result := range results {
		if result["reused"] == false {
			firstExecutions++
		}
	}
	if firstExecutions != 1 {
		t.Fatalf("first executions=%d, want exactly 1", firstExecutions)
	}

	var receiptCount int
	if err := database.QueryRowContext(ctx, `
		SELECT count(*) FROM remediation_execution_receipts WHERE idempotency_key = $1
	`, key).Scan(&receiptCount); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receiptCount != 1 {
		t.Fatalf("receipt count=%d, want 1", receiptCount)
	}
	var stateJSON []byte
	if err := database.QueryRowContext(ctx, `
		SELECT state FROM remediation_target_states
		WHERE resource_type = 'connection_pool' AND target = 'integration-payments'
	`).Scan(&stateJSON); err != nil {
		t.Fatalf("read target state: %v", err)
	}
	var state map[string]any
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		t.Fatalf("decode target state: %v", err)
	}
	if state["max_connections"] != float64(20) {
		t.Fatalf("unexpected target state: %#v", state)
	}

	if _, err := store.Preview(ctx, "feature_flag", "payments-api/checkout-v2", map[string]any{"enabled": false}); err != nil {
		t.Fatalf("Preview() error: %v", err)
	}
	var previewWrites int
	if err := database.QueryRowContext(ctx, `
		SELECT count(*) FROM remediation_target_states
		WHERE resource_type = 'feature_flag' AND target = 'payments-api/checkout-v2'
	`).Scan(&previewWrites); err != nil {
		t.Fatalf("count preview writes: %v", err)
	}
	if previewWrites != 0 {
		t.Fatalf("dry-run wrote %d target states", previewWrites)
	}
}
