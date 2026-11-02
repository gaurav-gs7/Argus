package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// ErrSchemaNewer means the database has migrations this build does not
// contain: it was migrated by a newer release. Running older code against a
// newer schema is refused rather than guessed at.
var ErrSchemaNewer = errors.New("database schema is newer than this build")

// ErrMigrationModified means an already-applied migration file changed.
var ErrMigrationModified = errors.New("applied migration was modified")

const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	checksum CHAR(64) NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Migrate applies the embedded migrations in the migrations package.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := Apply(ctx, db, nil)
	return err
}

// Apply brings the schema up to date and returns the migrations it applied.
// A nil set means the embedded migrations.
//
// The API and worker both migrate at startup, so the whole run holds a
// session advisory lock on one connection: concurrent starts serialize, and
// the second sees the first's work in schema_migrations. Each migration runs
// in its own transaction together with its schema_migrations row, so a
// failure leaves the database at the previous version. Applied migrations
// are verified by checksum before anything new runs.
//
// After the SQL migrations, the tamper-evident audit ledger is checked and,
// for a legacy table, backfilled once (audit.MigrateLedger). That step needs
// Go to compute hashes, and it re-validates the chain head on every start.
func Apply(ctx context.Context, db *sql.DB, set []migrations.Migration) ([]migrations.Migration, error) {
	if set == nil {
		all, err := migrations.All()
		if err != nil {
			return nil, err
		}
		set = all
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('argus_schema_migrate'))`); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext('argus_schema_migrate'))`)
	}()

	if _, err := conn.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := appliedChecksums(ctx, conn)
	if err != nil {
		return nil, err
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
	for _, version := range versions {
		m, ok := known[version]
		if !ok {
			return nil, fmt.Errorf("%w: migration %04d is applied but this build only knows up to %04d", ErrSchemaNewer, version, len(set))
		}
		if applied[version] != m.Checksum {
			return nil, fmt.Errorf("%w: %04d_%s checksum %s, database recorded %s", ErrMigrationModified, m.Version, m.Name, m.Checksum, applied[version])
		}
	}

	var ran []migrations.Migration
	for _, m := range set {
		if _, done := applied[m.Version]; done {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return ran, err
		}
		ran = append(ran, m)
	}

	if err := audit.MigrateLedger(ctx, db); err != nil {
		return ran, fmt.Errorf("migrate tamper-evident audit ledger: %w", err)
	}
	return ran, nil
}

func appliedChecksums(ctx context.Context, conn *sql.Conn) (map[int]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]string{}
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		applied[version] = checksum
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("record migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}
