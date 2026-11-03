package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// ScratchDatabase creates an empty database next to the one in
// ARGUS_TEST_POSTGRES_DSN and drops it when the test ends. Use it for tests
// whose subject is global (migrations, reconcilers) and would otherwise act
// on rows other tests left in the shared database.
func ScratchDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("argus_scratch_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create scratch database: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	scratch, err := sql.Open("pgx", u.String())
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
