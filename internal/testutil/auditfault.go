// Package testutil holds helpers shared by integration tests.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"testing"
)

// FailAuditAction makes PostgreSQL reject audit_logs inserts for one action
// until the returned function is called (also registered as test cleanup).
func FailAuditAction(t *testing.T, db *sql.DB, action string) func() {
	t.Helper()
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(action))
	name := fmt.Sprintf("argus_test_fail_audit_%08x", hash.Sum32())
	stmt := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION %[1]s() RETURNS trigger AS $$
		BEGIN
			IF NEW.action = %[2]s THEN RAISE EXCEPTION 'injected audit failure for %%', NEW.action; END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql;
		DROP TRIGGER IF EXISTS %[1]s ON audit_logs;
		CREATE TRIGGER %[1]s BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION %[1]s();
	`, name, quote(action))
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("install audit fault: %v", err)
	}
	removed := false
	remove := func() {
		if removed {
			return
		}
		removed = true
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %[1]s ON audit_logs; DROP FUNCTION IF EXISTS %[1]s();`, name))
	}
	t.Cleanup(remove)
	return remove
}

func quote(value string) string {
	out := "'"
	for _, r := range value {
		if r == '\'' {
			out += "''"
			continue
		}
		out += string(r)
	}
	return out + "'"
}

// AuditCount counts audit entries for a resource and action.
func AuditCount(t *testing.T, db *sql.DB, resourceID, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE resource_id = $1 AND action = $2`, resourceID, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
