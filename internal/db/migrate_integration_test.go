package db_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/migrations"
)

// scratchDatabase creates an empty database next to the one in
// ARGUS_TEST_POSTGRES_DSN and drops it when the test ends.
func scratchDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("argus_migrate_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create scratch database: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	scratch, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		scratch.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	return scratch
}

func embedded(t *testing.T) []migrations.Migration {
	t.Helper()
	all, err := migrations.All()
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func withExtra(t *testing.T, extra ...string) []migrations.Migration {
	set := embedded(t)
	for i, body := range extra {
		version := len(set) + 1
		set = append(set, migrations.Migration{Version: version, Name: fmt.Sprintf("test_%d", i), SQL: body, Checksum: fmt.Sprintf("%064d", version)})
	}
	return set
}

func recorded(t *testing.T, database *sql.DB) []int {
	t.Helper()
	rows, err := database.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		_ = rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

func tableExists(t *testing.T, database *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	if err := database.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func TestMigrateFreshDatabase(t *testing.T) {
	ctx := context.Background()
	database := scratchDatabase(t)
	applied, err := db.Apply(ctx, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(embedded(t)) {
		t.Fatalf("applied %d migrations, want %d", len(applied), len(embedded(t)))
	}
	for _, table := range []string{"incidents", "incident_alerts", "rca_reports", "remediation_actions", "audit_logs", "audit_chain_state", "worker_heartbeats"} {
		if !tableExists(t, database, table) {
			t.Fatalf("table %s missing after migrating an empty database", table)
		}
	}
	var checksum string
	if err := database.QueryRow(`SELECT checksum FROM schema_migrations WHERE version = 1`).Scan(&checksum); err != nil || checksum != embedded(t)[0].Checksum {
		t.Fatalf("baseline checksum=%q err=%v", checksum, err)
	}
	again, err := db.Apply(ctx, database, nil)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run applied %d migrations, err=%v", len(again), err)
	}
}

// A database created by an Argus build that predates schema_migrations (the
// inline-DDL era, here an early incidents/rca_reports shape with data) is
// brought forward by the baseline without losing rows.
func TestMigrateAdoptsUntrackedLegacyDatabase(t *testing.T) {
	ctx := context.Background()
	database := scratchDatabase(t)
	legacy := []string{
		`CREATE TABLE incidents (
			id TEXT PRIMARY KEY, title TEXT NOT NULL, service_id TEXT,
			severity TEXT NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3', 'sev4')),
			status TEXT NOT NULL, dedupe_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL, detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			resolved_at TIMESTAMPTZ, summary TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE rca_reports (
			id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(id),
			deterministic_summary TEXT NOT NULL, llm_summary TEXT, primary_hypothesis TEXT,
			contributing_factors JSONB, evidence JSONB NOT NULL, confidence NUMERIC(4,3),
			model_backend TEXT, model_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`INSERT INTO incidents (id, title, severity, status, dedupe_key, fingerprint, started_at)
			VALUES ('inc_legacy', 'legacy', 'sev2', 'open', 'alertmanager:checkout:prod:HighErrorRate', 'fp', now())`,
		`INSERT INTO rca_reports (id, incident_id, deterministic_summary, evidence)
			VALUES ('rca_legacy', 'inc_legacy', 'old report', '[]')`,
	}
	for _, stmt := range legacy {
		if _, err := database.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build legacy schema: %v", err)
		}
	}
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	var environment, llmStatus, candidates string
	if err := database.QueryRow(`SELECT environment FROM incidents WHERE id = 'inc_legacy'`).Scan(&environment); err != nil || environment != "prod" {
		t.Fatalf("legacy incident environment=%q err=%v", environment, err)
	}
	if err := database.QueryRow(`SELECT llm_status, candidates::text FROM rca_reports WHERE id = 'rca_legacy'`).Scan(&llmStatus, &candidates); err != nil || llmStatus != "disabled" || candidates != "[]" {
		t.Fatalf("legacy report llm_status=%q candidates=%q err=%v", llmStatus, candidates, err)
	}
	if got := recorded(t, database); len(got) != len(embedded(t)) {
		t.Fatalf("schema_migrations=%v", got)
	}
}

// API and worker replicas start together; exactly one applies each
// migration and none fails.
func TestConcurrentMigrateAppliesOnce(t *testing.T) {
	database := scratchDatabase(t)
	database.SetMaxOpenConns(20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applied, err := db.Apply(context.Background(), database, nil)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			total += len(applied)
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent migrate: %v", err)
	}
	if total != len(embedded(t)) {
		t.Fatalf("migrations applied %d times in total, want %d", total, len(embedded(t)))
	}
}

// A migration file is several statements; when one fails, none of the file
// and no schema_migrations row is kept, and a corrected file applies later.
func TestFailedMigrationRollsBackWholeFile(t *testing.T) {
	ctx := context.Background()
	database := scratchDatabase(t)
	broken := withExtra(t, `CREATE TABLE migration_probe (id INTEGER); INSERT INTO migration_probe VALUES (1); SELECT 1/0;`)
	if _, err := db.Apply(ctx, database, broken); err == nil {
		t.Fatal("a failing migration was reported as applied")
	}
	if tableExists(t, database, "migration_probe") {
		t.Fatal("statements before the failure were committed")
	}
	if got := recorded(t, database); len(got) != len(embedded(t)) {
		t.Fatalf("schema_migrations=%v, want only the embedded set", got)
	}
	fixed := withExtra(t, `CREATE TABLE migration_probe (id INTEGER); INSERT INTO migration_probe VALUES (1), (2);`)
	applied, err := db.Apply(ctx, database, fixed)
	if err != nil || len(applied) != 1 || applied[0].Version != len(fixed) {
		t.Fatalf("corrected migration applied=%v err=%v", applied, err)
	}
	var rows int
	if err := database.QueryRow(`SELECT count(*) FROM migration_probe`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("multi-statement migration rows=%d err=%v", rows, err)
	}
}

func TestMigrateRefusesModifiedMigration(t *testing.T) {
	ctx := context.Background()
	database := scratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	edited := embedded(t)
	edited[0].SQL += "\nSELECT 1;"
	edited[0].Checksum = fmt.Sprintf("%064d", 7)
	edited = append(edited, migrations.Migration{Version: len(edited) + 1, Name: "after_edit", SQL: `CREATE TABLE after_edit (id INTEGER);`, Checksum: fmt.Sprintf("%064d", 8)})
	if _, err := db.Apply(ctx, database, edited); !errors.Is(err, db.ErrMigrationModified) {
		t.Fatalf("err=%v, want ErrMigrationModified", err)
	}
	if tableExists(t, database, "after_edit") {
		t.Fatal("pending migrations ran despite a modified applied migration")
	}
}

// Rolling back to an older build after a newer one migrated must fail loudly
// instead of running old code against a schema it does not know.
func TestMigrateRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	database := scratchDatabase(t)
	if _, err := db.Apply(ctx, database, withExtra(t, `CREATE TABLE from_newer_release (id INTEGER);`)); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, database); !errors.Is(err, db.ErrSchemaNewer) {
		t.Fatalf("err=%v, want ErrSchemaNewer", err)
	}
}
