package incidents_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
)

func TestAlertIngestionPersistsAndGroupsIncident(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		TRUNCATE incident_timeline_events, signals, incidents, services CASCADE
	`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	manager := incidents.NewServiceManager(store, auditor, 30*time.Minute)
	if _, err := database.ExecContext(ctx, `
		INSERT INTO services (id, name, owner, tier, environment)
		VALUES ('svc_nullable_owner', 'nullable-owner-service', NULL, 'tier2', 'test')
	`); err != nil {
		t.Fatalf("insert service with nullable owner: %v", err)
	}
	services, err := store.ListServices(ctx)
	if err != nil {
		t.Fatalf("list service with nullable owner: %v", err)
	}
	if len(services) != 1 || services[0].Owner != "" {
		t.Fatalf("nullable service owner should be represented as an empty value: %#v", services)
	}
	if service, err := store.EnsureService(ctx, "nullable-owner-service"); err != nil || service.Owner != "" {
		t.Fatalf("read existing service with nullable owner: service=%#v err=%v", service, err)
	}

	startedAt := time.Now().UTC().Add(-time.Minute)
	payload := incidents.AlertmanagerWebhook{
		Status: "firing",
		Alerts: []incidents.AlertmanagerAlert{{
			Status:      "firing",
			StartsAt:    startedAt,
			Fingerprint: "payments-latency-1",
			Labels: map[string]string{
				"alertname":   "HighLatency",
				"service":     "payments-api",
				"environment": "test",
				"severity":    "sev2",
			},
			Annotations: map[string]string{"summary": "payments latency is above SLO"},
		}},
	}

	first, err := manager.IngestAlertmanager(ctx, payload, "integration-test")
	if err != nil {
		t.Fatalf("ingest first alert: %v", err)
	}
	second, err := manager.IngestAlertmanager(ctx, payload, "integration-test")
	if err != nil {
		t.Fatalf("ingest duplicate alert: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one incident per ingestion, got %d and %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("expected duplicate alert to group into %s, got %s", first[0].ID, second[0].ID)
	}

	storedIncidents, err := store.ListIncidents(ctx)
	if err != nil {
		t.Fatalf("list incidents: %v", err)
	}
	if len(storedIncidents) != 1 {
		t.Fatalf("expected one stored incident, got %d", len(storedIncidents))
	}
	signals, err := store.ListSignals(ctx, first[0].ID)
	if err != nil {
		t.Fatalf("list signals: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("expected both alert deliveries to remain as evidence, got %d signals", len(signals))
	}
	timeline, err := store.ListTimeline(ctx, first[0].ID)
	if err != nil {
		t.Fatalf("list timeline: %v", err)
	}
	if len(timeline) != 2 {
		t.Fatalf("expected two timeline entries, got %d", len(timeline))
	}
	auditEntries, err := auditor.List(ctx, 10)
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	foundAudit := false
	for _, entry := range auditEntries {
		if entry.Action == "incident.detected" && entry.ResourceID == first[0].ID {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("expected incident.detected audit entry for %s, got %#v", first[0].ID, auditEntries)
	}
}
