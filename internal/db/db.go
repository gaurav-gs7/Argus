package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

// ErrSchemaNewer means the database has a migration this build does not
// contain and that migration is marked breaking (-- argus:breaking), so this
// build cannot safely run against it. Unknown migrations that are not marked
// breaking are tolerated, which is what makes rolling back a release safe.
var ErrSchemaNewer = errors.New("database schema has a breaking migration newer than this build")

// ErrSchemaBehind means verify mode found migrations this build needs that
// have not been applied yet.
var ErrSchemaBehind = errors.New("database schema is behind this build")

// ErrMigrationModified means an already-applied migration file changed.
var ErrMigrationModified = errors.New("applied migration was modified")

// Mode selects what a process does with the schema at startup.
type Mode string

const (
	// ModeApply applies pending migrations (the default; single-node and
	// Compose deployments rely on it).
	ModeApply Mode = "apply"
	// ModeVerify applies nothing and refuses to start unless every migration
	// this build needs is already applied. Use it for application pods when a
	// separate migration step (argus-api migrate) runs with DDL privileges.
	ModeVerify Mode = "verify"
)

// ParseMode validates a configured mode; empty means ModeApply.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case "", ModeApply:
		return ModeApply, nil
	case ModeVerify:
		return ModeVerify, nil
	}
	return "", fmt.Errorf("ARGUS_MIGRATIONS must be %q or %q, got %q", ModeApply, ModeVerify, value)
}

const migrationLock = `hashtext('argus_schema_migrate')`

var schemaMigrationsDDL = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	checksum CHAR(64) NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`,
	`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS breaking BOOLEAN NOT NULL DEFAULT false`,
}

// Report describes a migration run.
type Report struct {
	// Applied lists the migrations this run applied.
	Applied []migrations.Migration
	// Newer lists versions a newer build applied that this build does not
	// know but tolerates because none of them is marked breaking.
	Newer []int
}

// Migrate applies the embedded migrations in the migrations package.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := Run(ctx, db, ModeApply, nil)
	return err
}

// Apply runs Run in ModeApply and returns the migrations it applied.
func Apply(ctx context.Context, db *sql.DB, set []migrations.Migration) ([]migrations.Migration, error) {
	report, err := Run(ctx, db, ModeApply, set)
	return report.Applied, err
}

// Prepare runs the startup schema step for mode and logs what it did.
func Prepare(ctx context.Context, db *sql.DB, mode Mode, logger *slog.Logger) error {
	report, err := Run(ctx, db, mode, nil)
	if err != nil {
		return err
	}
	for _, m := range report.Applied {
		logger.Info("applied schema migration", "version", m.Version, "name", m.Name)
	}
	if len(report.Newer) > 0 {
		logger.Warn("database has non-breaking migrations from a newer build; continuing", "versions", report.Newer)
	}
	return nil
}

// Run brings the schema up to date (ModeApply) or checks it (ModeVerify).
// A nil set means the embedded migrations.
//
// In ModeApply the whole run holds a session advisory lock on one
// connection, so API and worker replicas starting together serialize and the
// second sees the first's work in schema_migrations. Each migration runs in
// its own transaction with its schema_migrations row, so a failure leaves the
// database at the previous version. ModeVerify takes the same lock in shared
// mode, so it waits for an in-progress migration instead of reading half of
// it.
//
// Before anything runs, applied migrations this build knows are verified by
// checksum. Applied migrations it does not know come from a newer build: they
// are tolerated unless one is marked breaking.
//
// After the SQL migrations, ModeApply checks the tamper-evident audit ledger
// and, for a legacy table, backfills it once (audit.MigrateLedger). That step
// needs Go to compute hashes, and it re-validates the chain head every run.
func Run(ctx context.Context, db *sql.DB, mode Mode, set []migrations.Migration) (Report, error) {
	var report Report
	if set == nil {
		all, err := migrations.All()
		if err != nil {
			return report, err
		}
		set = all
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return report, fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()
	lock, unlock := "pg_advisory_lock", "pg_advisory_unlock"
	if mode == ModeVerify {
		lock, unlock = "pg_advisory_lock_shared", "pg_advisory_unlock_shared"
	}
	if _, err := conn.ExecContext(ctx, "SELECT "+lock+"("+migrationLock+")"); err != nil {
		return report, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT "+unlock+"("+migrationLock+")")
	}()

	if mode == ModeApply {
		for _, stmt := range schemaMigrationsDDL {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return report, fmt.Errorf("prepare schema_migrations: %w", err)
			}
		}
	}
	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return report, err
	}
	known := make(map[int]migrations.Migration, len(set))
	for _, m := range set {
		known[m.Version] = m
	}
	versions := make([]int, 0, len(applied))
	for version := range applied {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	var breaking []string
	for _, version := range versions {
		row := applied[version]
		m, ok := known[version]
		if !ok {
			report.Newer = append(report.Newer, version)
			if row.Breaking {
				breaking = append(breaking, fmt.Sprintf("%04d_%s", version, row.Name))
			}
			continue
		}
		if row.Checksum != m.Checksum {
			return report, fmt.Errorf("%w: %04d_%s checksum %s, database recorded %s", ErrMigrationModified, m.Version, m.Name, m.Checksum, row.Checksum)
		}
	}
	if len(breaking) > 0 {
		return report, fmt.Errorf("%w: %v applied, this build knows up to %04d; deploy a build that includes them", ErrSchemaNewer, breaking, len(set))
	}

	var pending []migrations.Migration
	for _, m := range set {
		if _, done := applied[m.Version]; !done {
			pending = append(pending, m)
		}
	}
	if mode == ModeVerify {
		if len(pending) > 0 {
			return report, fmt.Errorf("%w: %d migration(s) pending, first %04d_%s; run `argus-api migrate`", ErrSchemaBehind, len(pending), pending[0].Version, pending[0].Name)
		}
		return report, nil
	}
	for _, m := range pending {
		if err := applyOne(ctx, conn, m); err != nil {
			return report, err
		}
		report.Applied = append(report.Applied, m)
	}

	if err := audit.MigrateLedger(ctx, db); err != nil {
		return report, fmt.Errorf("migrate tamper-evident audit ledger: %w", err)
	}
	return report, nil
}

type appliedMigration struct {
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
	Breaking bool   `json:"breaking"`
	Version  int    `json:"version"`
}

// appliedMigrations reads schema_migrations as JSON rows, so a table written
// by an older build (without the breaking column) reads the same way. A
// missing table means nothing is applied.
func appliedMigrations(ctx context.Context, conn *sql.Conn) (map[int]appliedMigration, error) {
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("inspect schema_migrations: %w", err)
	}
	applied := map[int]appliedMigration{}
	if !exists {
		return applied, nil
	}
	rows, err := conn.QueryContext(ctx, `SELECT to_jsonb(s)::text FROM schema_migrations s`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var row appliedMigration
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			return nil, fmt.Errorf("decode schema_migrations row: %w", err)
		}
		applied[row.Version] = row
	}
	return applied, rows.Err()
}

func applyOne(ctx context.Context, conn *sql.Conn, m migrations.Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %04d_%s: %w", m.Version, m.Name, err)
	}
	defer tx.Rollback()
	// No arguments: pgx sends this over the simple protocol, which accepts a
	// file of several statements.
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, checksum, breaking) VALUES ($1, $2, $3, $4)`, m.Version, m.Name, m.Checksum, m.Breaking); err != nil {
		return fmt.Errorf("record migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}
