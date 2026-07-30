package audit_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
)

func TestAuditLedgerBackfillConcurrencyAppendOnlyAndTamperDetection(t *testing.T) {
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

	createLegacyAuditTable(t, database)
	if _, err := database.ExecContext(ctx, `
		ALTER TABLE audit_logs
			ADD COLUMN chain_position BIGINT,
			ADD COLUMN previous_hash CHAR(64),
			ADD COLUMN entry_hash CHAR(64),
			ADD COLUMN hash_version SMALLINT
	`); err != nil {
		t.Fatalf("add partial-chain columns: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE audit_logs
		SET chain_position = 1, previous_hash = $1, entry_hash = $1, hash_version = 1
		WHERE id = 'aud_legacy_1'
	`, audit.GenesisHash); err != nil {
		t.Fatalf("create partial-chain fixture: %v", err)
	}
	if err := db.Migrate(ctx, database); err == nil || !strings.Contains(err.Error(), "partially chained") {
		t.Fatalf("partial audit chain migration error=%v, want fail-closed partial-chain error", err)
	}
	if _, err := database.ExecContext(ctx, `DROP TABLE audit_logs`); err != nil {
		t.Fatalf("remove partial-chain fixture: %v", err)
	}

	createLegacyAuditTable(t, database)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate legacy audit ledger: %v", err)
	}
	service := audit.NewService(database)
	initial, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify backfilled ledger: %v", err)
	}
	if !initial.Valid || initial.EntriesVerified != 2 || initial.HeadPosition != 2 {
		t.Fatalf("unexpected backfilled ledger: %+v", initial)
	}
	var migrationWG sync.WaitGroup
	migrationErrors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		migrationWG.Add(1)
		go func() {
			defer migrationWG.Done()
			migrationErrors <- db.Migrate(context.Background(), database)
		}()
	}
	migrationWG.Wait()
	close(migrationErrors)
	for err := range migrationErrors {
		if err != nil {
			t.Fatalf("concurrent startup migration: %v", err)
		}
	}
	if err := service.Write(ctx, audit.Entry{
		ID:           "aud_submicrosecond_timestamp",
		ActorType:    "system",
		Action:       "test.timestamp_precision",
		ResourceType: "audit_test",
		CreatedAt:    time.Date(2026, 7, 30, 12, 0, 0, 123456789, time.UTC),
	}); err != nil {
		t.Fatalf("append sub-microsecond timestamp: %v", err)
	}

	const concurrentWrites = 40
	var wg sync.WaitGroup
	errs := make(chan error, concurrentWrites)
	for i := 0; i < concurrentWrites; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errs <- service.Write(context.Background(), audit.Entry{
				ID:           fmt.Sprintf("aud_concurrent_%02d", index),
				ActorID:      "issuer#concurrent-writer",
				ActorType:    "user",
				Action:       "test.concurrent_append",
				ResourceType: "audit_test",
				ResourceID:   fmt.Sprintf("resource_%02d", index),
				Metadata:     map[string]any{"index": index},
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent audit write: %v", err)
		}
	}

	afterWrites, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify concurrent ledger: %v", err)
	}
	if !afterWrites.Valid || afterWrites.EntriesVerified != 3+concurrentWrites {
		t.Fatalf("concurrent ledger verification: %+v", afterWrites)
	}

	beforeRollback := afterWrites.HeadPosition
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.WriteTx(ctx, tx, audit.Entry{
		ID: "aud_rolled_back", ActorType: "system", Action: "test.rollback", ResourceType: "audit_test",
	}); err != nil {
		t.Fatalf("append audit row in rollback transaction: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback audit transaction: %v", err)
	}
	afterRollback, err := service.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !afterRollback.Valid || afterRollback.HeadPosition != beforeRollback {
		t.Fatalf("rolled-back append changed ledger head: before=%d after=%+v", beforeRollback, afterRollback)
	}

	assertMutationRejected(t, database, `UPDATE audit_logs SET action = 'tampered' WHERE id = 'aud_concurrent_00'`)
	assertMutationRejected(t, database, `DELETE FROM audit_logs WHERE id = 'aud_concurrent_00'`)
	assertMutationRejected(t, database, `TRUNCATE audit_logs`)
	if _, err := database.ExecContext(ctx, `
		INSERT INTO audit_logs (id, actor_type, action, resource_type)
		VALUES ('aud_direct_insert', 'system', 'test.direct', 'audit_test')
	`); err == nil {
		t.Fatal("direct insert without chain metadata must be rejected")
	}

	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_reject_mutation`); err != nil {
		t.Fatalf("disable append-only trigger for tamper simulation: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE audit_logs SET after_state = '{"tampered":true}'::jsonb WHERE id = 'aud_concurrent_00'
	`); err != nil {
		t.Fatalf("simulate privileged tamper: %v", err)
	}
	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_reject_mutation`); err != nil {
		t.Fatalf("restore append-only trigger: %v", err)
	}
	tampered, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify tampered ledger: %v", err)
	}
	if tampered.Valid || tampered.Reason != "entry hash mismatch" || tampered.InvalidPosition == 0 {
		t.Fatalf("tamper was not detected: %+v", tampered)
	}

	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_reject_mutation`); err != nil {
		t.Fatalf("disable trigger to restore test fixture: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE audit_logs SET after_state = 'null'::jsonb WHERE id = 'aud_concurrent_00'
	`); err != nil {
		t.Fatalf("restore tampered test fixture: %v", err)
	}
	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_reject_mutation`); err != nil {
		t.Fatalf("re-enable append-only trigger: %v", err)
	}
	restored, err := service.Verify(ctx)
	if err != nil || !restored.Valid {
		t.Fatalf("restored ledger should verify: report=%+v err=%v", restored, err)
	}

	if _, err := database.ExecContext(ctx, `
		UPDATE audit_chain_state SET last_position = last_position + 1 WHERE chain_id = 1
	`); err != nil {
		t.Fatalf("simulate persisted head corruption: %v", err)
	}
	headTampered, err := service.Verify(ctx)
	if err != nil {
		t.Fatalf("verify corrupted chain head: %v", err)
	}
	if headTampered.Valid || headTampered.Reason != "persisted head position does not match ledger length" {
		t.Fatalf("persisted head corruption was not detected: %+v", headTampered)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE audit_chain_state SET last_position = last_position - 1 WHERE chain_id = 1
	`); err != nil {
		t.Fatalf("restore persisted chain head: %v", err)
	}
	if final, err := service.Verify(ctx); err != nil || !final.Valid {
		t.Fatalf("final restored ledger should verify: report=%+v err=%v", final, err)
	}
}

func createLegacyAuditTable(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY,
			actor_id TEXT,
			actor_type TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT,
			request_id TEXT,
			ip_address TEXT,
			before_state JSONB,
			after_state JSONB,
			metadata JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatalf("create legacy audit table: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, actor_id, actor_type, action, resource_type, resource_id,
			before_state, after_state, metadata, created_at
		) VALUES
			('aud_legacy_1', 'issuer#operator', 'user', 'incident.detected', 'incident', 'inc_1',
			 '{"status":"none"}', '{"status":"detected"}', '{"source":"alertmanager"}', '2026-01-01T00:00:00Z'),
			('aud_legacy_2', 'issuer#admin', 'user', 'incident.resolved', 'incident', 'inc_1',
			 '{"status":"detected"}', '{"status":"resolved"}', '{"reason":"recovered"}', '2026-01-01T00:01:00Z')
	`); err != nil {
		t.Fatalf("insert legacy audit rows: %v", err)
	}
}

func assertMutationRejected(t *testing.T, database *sql.DB, statement string) {
	t.Helper()
	_, err := database.ExecContext(context.Background(), statement)
	if err == nil {
		t.Fatalf("append-only ledger accepted mutation: %s", statement)
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("mutation failed for an unexpected reason: %v", err)
	}
}
