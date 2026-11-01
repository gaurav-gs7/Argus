package incidents_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Alertmanager re-sends a still-firing alert every group_interval/repeat_interval
// with the same startsAt. An outage longer than the grouping window must stay
// one incident.
func TestRenotifiedLongRunningAlertReusesIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)

	startedAt := time.Now().UTC().Add(-10 * time.Minute)
	first, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "fp-long"), "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "fp-long"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ID != second[0].ID {
		t.Errorf("one ongoing outage became %d incidents (%s, %s)", count(), first[0].ID, second[0].ID)
	}
}

// A "resolved" notification ends an alert. It must not open a new incident.
func TestResolvedNotificationDoesNotOpenIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)

	startedAt := time.Now().UTC().Add(-10 * time.Minute)
	if _, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "fp-res"), "test"); err != nil {
		t.Fatal(err)
	}
	resolved, err := manager.IngestAlertmanager(ctx, alert("resolved", startedAt, "fp-res"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Errorf("resolved notification produced incident %s in status %q; %d incidents exist", resolved[0].ID, resolved[0].Status, n)
	}
}

func ageIncident(t *testing.T, database *sql.DB, incidentID string, incidentAge, alertAge time.Duration) {
	t.Helper()
	if _, err := database.Exec(`UPDATE incidents SET last_seen_at = now() - $2::interval WHERE id = $1`, incidentID, fmt.Sprintf("%d seconds", int(incidentAge.Seconds()))); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE incident_alerts SET last_seen_at = now() - $2::interval WHERE incident_id = $1`, incidentID, fmt.Sprintf("%d seconds", int(alertAge.Seconds()))); err != nil {
		t.Fatal(err)
	}
}

func timelineTypes(t *testing.T, store *incidents.Store, incidentID string) map[string]int {
	t.Helper()
	events, err := store.ListTimeline(context.Background(), incidentID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, event := range events {
		out[event.EventType]++
	}
	return out
}

func TestResolvedNotificationClearsAlertsButKeepsIncidentOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, _ := ingestionTestManager(t, ctx)
	store := incidents.NewStore(openIngestionDB(t, ctx))

	startedAt := time.Now().UTC().Add(-time.Minute)
	created, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "clear-1"), "test")
	if err != nil {
		t.Fatal(err)
	}
	resolved := alert("resolved", startedAt, "clear-1")
	resolved.Alerts[0].EndsAt = time.Now().UTC()
	result, err := manager.IngestAlertmanagerWithResult(ctx, resolved, "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.ResolvedAlerts != 1 || len(result.Incidents) != 0 {
		t.Fatalf("stats=%+v incidents=%d", result.Stats, len(result.Incidents))
	}
	incident, err := store.GetIncident(ctx, created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if incident.AlertsClearedAt == nil || incident.Status != incidents.StatusDetected || incident.ResolvedAt != nil {
		t.Fatalf("incident after resolution: status=%s cleared=%v resolved=%v", incident.Status, incident.AlertsClearedAt, incident.ResolvedAt)
	}
	types := timelineTypes(t, store, incident.ID)
	if types["alert_resolved"] != 1 || types["alerts_cleared"] != 1 {
		t.Fatalf("timeline=%v", types)
	}
	alerts, _ := store.ListIncidentAlerts(ctx, incident.ID)
	if len(alerts) != 1 || alerts[0].Status != "resolved" || alerts[0].ResolvedAt == nil {
		t.Fatalf("alert state=%+v", alerts)
	}
}

func TestUnmatchedResolvedNotificationIsIgnored(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	database := openIngestionDB(t, ctx)
	payload := alert("resolved", time.Now().UTC(), "never-fired")
	payload.Alerts[0].Labels["service"] = "svc-never-seen"
	result, err := manager.IngestAlertmanagerWithResult(ctx, payload, "test")
	if err != nil {
		t.Fatal(err)
	}
	var services int
	_ = database.QueryRow(`SELECT count(*) FROM services WHERE name = 'svc-never-seen'`).Scan(&services)
	if count() != 0 || services != 0 || result.Stats.UnmatchedResolvedAlerts != 1 {
		t.Fatalf("incidents=%d services=%d stats=%+v", count(), services, result.Stats)
	}
}

func TestPartialResolutionKeepsIncidentFiring(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, _ := ingestionTestManager(t, ctx)
	store := incidents.NewStore(openIngestionDB(t, ctx))
	startedAt := time.Now().UTC()
	first, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "pod-a"), "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "pod-b"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("same alert on two pods split into two incidents")
	}
	if _, err := manager.IngestAlertmanager(ctx, alert("resolved", startedAt, "pod-a"), "test"); err != nil {
		t.Fatal(err)
	}
	incident, _ := store.GetIncident(ctx, first[0].ID)
	if incident.AlertsClearedAt != nil {
		t.Fatal("incident cleared while pod-b is still firing")
	}
	if _, err := manager.IngestAlertmanager(ctx, alert("resolved", startedAt, "pod-b"), "test"); err != nil {
		t.Fatal(err)
	}
	incident, _ = store.GetIncident(ctx, first[0].ID)
	if incident.AlertsClearedAt == nil {
		t.Fatal("incident not cleared after its last alert resolved")
	}
}

func TestFlappingAlertWithinWindowReusesIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	store := incidents.NewStore(openIngestionDB(t, ctx))
	startedAt := time.Now().UTC()
	first, _ := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "flap"), "test")
	if _, err := manager.IngestAlertmanager(ctx, alert("resolved", startedAt, "flap"), "test"); err != nil {
		t.Fatal(err)
	}
	again, err := manager.IngestAlertmanager(ctx, alert("firing", startedAt.Add(time.Minute), "flap"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].ID != first[0].ID || count() != 1 {
		t.Fatalf("flap within the window opened a new incident (%d total)", count())
	}
	incident, _ := store.GetIncident(ctx, first[0].ID)
	if incident.AlertsClearedAt != nil || timelineTypes(t, store, incident.ID)["alerts_refired"] != 1 {
		t.Fatalf("re-fire not recorded: cleared=%v timeline=%v", incident.AlertsClearedAt, timelineTypes(t, store, incident.ID))
	}
}

func TestRecurrenceAfterWindowOpensNewIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	database := openIngestionDB(t, ctx)
	startedAt := time.Now().UTC()
	first, _ := manager.IngestAlertmanager(ctx, alert("firing", startedAt, "recur"), "test")
	if _, err := manager.IngestAlertmanager(ctx, alert("resolved", startedAt, "recur"), "test"); err != nil {
		t.Fatal(err)
	}
	ageIncident(t, database, first[0].ID, 10*time.Minute, 10*time.Minute)
	later, err := manager.IngestAlertmanager(ctx, alert("firing", time.Now().UTC(), "recur"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if later[0].ID == first[0].ID || count() != 2 {
		t.Fatalf("a recurrence after the window should open a new incident")
	}
}

func TestStaleFiringAlertStopsPinningIncident(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, _ := ingestionTestManager(t, ctx)
	database := openIngestionDB(t, ctx)
	store := incidents.NewStore(database)
	grouping := incidents.Grouping{Window: 5 * time.Minute, AlertStaleAfter: incidents.DefaultAlertStaleAfter}
	created, _ := manager.IngestAlertmanager(ctx, alert("firing", time.Now().UTC(), "stale"), "test")

	// Last notification an hour ago, alert still firing: a long outage.
	ageIncident(t, database, created[0].ID, time.Hour, time.Hour)
	if open, _ := store.ListOpenIncidents(ctx, grouping); len(open) != 1 {
		t.Fatalf("firing alert should keep a long-running incident open, got %d", len(open))
	}
	// Seven hours without a re-send: Alertmanager has lost the alert.
	ageIncident(t, database, created[0].ID, 7*time.Hour, 7*time.Hour)
	if open, _ := store.ListOpenIncidents(ctx, grouping); len(open) != 0 {
		t.Fatalf("stale alert still pins the incident open")
	}
}

func TestIncidentRecordsAlertEnvironment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, _ := ingestionTestManager(t, ctx)
	payload := alert("firing", time.Now().UTC(), "env")
	payload.Alerts[0].Labels["environment"] = "production"
	payload.Alerts[0].Labels["alertname"] = "Latency:p95:High"
	created, err := manager.IngestAlertmanager(ctx, payload, "test")
	if err != nil {
		t.Fatal(err)
	}
	if created[0].Environment != "production" {
		t.Fatalf("environment=%q", created[0].Environment)
	}
}

// End to end with payloads captured from a real Alertmanager v0.27.0.
func TestCapturedAlertmanagerPayloadsDriveLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager, count := ingestionTestManager(t, ctx)
	store := incidents.NewStore(openIngestionDB(t, ctx))
	decode := func(name string) incidents.AlertmanagerWebhook {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var payload incidents.AlertmanagerWebhook
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		// Keep the captured alert inside the grouping window.
		payload.Alerts[0].StartsAt = time.Now().UTC()
		return payload
	}
	created, err := manager.IngestAlertmanager(ctx, decode("alertmanager-0.27-firing.json"), "test")
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := manager.IngestAlertmanager(ctx, decode("alertmanager-0.27-firing.json"), "test")
	if err != nil || repeat[0].ID != created[0].ID {
		t.Fatalf("repeat notification: %v %+v", err, repeat)
	}
	result, err := manager.IngestAlertmanagerWithResult(ctx, decode("alertmanager-0.27-resolved.json"), "test")
	if err != nil || result.Stats.ResolvedAlerts != 1 {
		t.Fatalf("resolved: %v %+v", err, result.Stats)
	}
	incident, _ := store.GetIncident(ctx, created[0].ID)
	if count() != 1 || incident.AlertsClearedAt == nil {
		t.Fatalf("incidents=%d cleared=%v", count(), incident.AlertsClearedAt)
	}
}
