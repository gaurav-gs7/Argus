package incidents_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
)

func ingestionTestManager(t *testing.T, ctx context.Context) (*incidents.ServiceManager, func() int) {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := database.ExecContext(ctx, `TRUNCATE incident_timeline_events, signals, incidents, services CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	count := func() int {
		var n int
		_ = database.QueryRowContext(context.Background(), `SELECT count(*) FROM incidents`).Scan(&n)
		return n
	}
	// Default grouping window from config.go.
	return incidents.NewServiceManager(incidents.NewStore(database), audit.NewService(database), 5*time.Minute), count
}

func alert(status string, startsAt time.Time, fingerprint string) incidents.AlertmanagerWebhook {
	return incidents.AlertmanagerWebhook{Status: status, Alerts: []incidents.AlertmanagerAlert{{
		Status: status, StartsAt: startsAt, Fingerprint: fingerprint,
		Labels:      map[string]string{"alertname": "PaymentsAPIHighErrorRate", "service": "payments-api", "environment": "test", "severity": "sev2"},
		Annotations: map[string]string{"summary": "High 5xx rate"},
	}}}
}

// During an alert storm Alertmanager sends many webhooks concurrently (one per
// alert group). Ingestion must not stall.
func TestConcurrentWebhooksDoNotStall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	manager, _ := ingestionTestManager(t, ctx)

	// db.Open caps the pool at 10. Measured: 9 senders finish in ~0.2s; 10 or
	// more deadlock until every request times out.
	const senders = 16
	var failed atomic.Int32
	var firstErr atomic.Value
	var wg sync.WaitGroup
	start := time.Now()
	for i := range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // Alertmanager's default webhook timeout
			defer cancel()
			payload := alert("firing", time.Now().UTC(), fmt.Sprintf("storm-%d", i))
			payload.Alerts[0].Labels["service"] = fmt.Sprintf("svc-%02d", i)
			if _, err := manager.IngestAlertmanager(reqCtx, payload, "test"); err != nil {
				failed.Add(1)
				firstErr.CompareAndSwap(nil, err.Error())
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Errorf("%d/%d concurrent webhooks failed after %s; first error: %v", n, senders, time.Since(start).Round(time.Millisecond), firstErr.Load())
	}
}

func openIngestionDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// A failure on the second alert group must roll back the first group's
// incident, signals, timeline and audit entries: no partial context.
func TestIngestionIsAtomic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	database := openIngestionDB(t, ctx)

	if _, err := database.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION argus_test_fail_signal() RETURNS trigger AS $$
		BEGIN
			IF NEW.name = 'ArgusTestPoisonAlert' THEN RAISE EXCEPTION 'injected signal failure'; END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql;
		DROP TRIGGER IF EXISTS argus_test_fail_signal ON signals;
		CREATE TRIGGER argus_test_fail_signal BEFORE INSERT ON signals FOR EACH ROW EXECUTE FUNCTION argus_test_fail_signal();
	`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS argus_test_fail_signal ON signals; DROP FUNCTION IF EXISTS argus_test_fail_signal();`)
	})

	var auditBefore int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	good := alert("firing", time.Now().UTC(), "atomic-good")
	good.Alerts[0].Labels["service"] = "svc-atomic-a"
	poison := alert("firing", time.Now().UTC().Add(time.Second), "atomic-poison")
	poison.Alerts[0].Labels["service"] = "svc-atomic-b"
	poison.Alerts[0].Labels["alertname"] = "ArgusTestPoisonAlert"
	payload := good
	payload.Alerts = append(payload.Alerts, poison.Alerts[0])

	if _, err := manager.IngestAlertmanager(ctx, payload, "test"); err == nil {
		t.Fatal("injected failure was swallowed")
	}
	var signals, auditAfter int
	_ = database.QueryRowContext(ctx, `SELECT count(*) FROM signals`).Scan(&signals)
	_ = database.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs`).Scan(&auditAfter)
	if n := count(); n != 0 || signals != 0 || auditAfter != auditBefore {
		t.Fatalf("partial ingestion persisted: incidents=%d signals=%d audit +%d", n, signals, auditAfter-auditBefore)
	}

	// The same delivery succeeds once the fault is gone (Alertmanager retry).
	if _, err := database.ExecContext(ctx, `DROP TRIGGER argus_test_fail_signal ON signals`); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IngestAlertmanager(ctx, payload, "test"); err != nil {
		t.Fatalf("retry after recovery failed: %v", err)
	}
	if n := count(); n != 2 {
		t.Fatalf("retry produced %d incidents, want 2", n)
	}
}

// Many concurrent deliveries of the same alert must converge on one incident.
func TestConcurrentDuplicateDeliveriesCreateOneIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	startedAt := time.Now().UTC()
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "dup-storm"), "test"); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 || count() != 1 {
		t.Fatalf("failed=%d incidents=%d, want 0 failures and 1 incident", failed.Load(), count())
	}
}
