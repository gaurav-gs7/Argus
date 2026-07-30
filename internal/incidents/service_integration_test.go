package incidents_test

import (
	"context"
	"fmt"
	"os"
	"sync"
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

func TestTopologyAlertStormCollapsesToRootIncident(t *testing.T) {
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
		TRUNCATE incident_timeline_events, signals, incidents, service_dependencies, services CASCADE
	`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	manager := incidents.NewServiceManager(store, auditor, 30*time.Minute)
	for _, dependency := range []incidents.ServiceDependencyRequest{
		{Service: "payments-api", DependsOn: "postgres", DependencyType: "datastore", Criticality: "critical"},
		{Service: "checkout-api", DependsOn: "payments-api", DependencyType: "synchronous", Criticality: "critical"},
		{Service: "nginx", DependsOn: "payments-api", DependencyType: "edge", Criticality: "critical"},
	} {
		if _, err := store.UpsertServiceDependency(ctx, dependency); err != nil {
			t.Fatalf("seed dependency %+v: %v", dependency, err)
		}
	}

	startedAt := time.Now().UTC().Add(-time.Minute)
	services := []string{
		"nginx", "checkout-api", "payments-api", "nginx", "checkout-api",
		"payments-api", "postgres", "nginx", "checkout-api", "payments-api",
		"nginx", "checkout-api", "payments-api", "postgres", "nginx",
		"checkout-api", "payments-api", "nginx", "checkout-api", "payments-api",
	}
	alerts := make([]incidents.AlertmanagerAlert, 0, len(services))
	for i, service := range services {
		alerts = append(alerts, incidents.AlertmanagerAlert{
			Status:      "firing",
			StartsAt:    startedAt.Add(time.Duration(i) * time.Second),
			Fingerprint: fmt.Sprintf("storm-%02d", i),
			Labels: map[string]string{
				"alertname":   "DependencyFailure",
				"service":     service,
				"environment": "test",
				"severity":    "sev2",
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s is failing requests during dependency outage", service),
			},
		})
	}

	result, err := manager.IngestAlertmanagerWithResult(ctx, incidents.AlertmanagerWebhook{
		Status: "firing",
		Alerts: alerts,
	}, "integration-test")
	if err != nil {
		t.Fatalf("ingest topology storm: %v", err)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Service != "postgres" {
		t.Fatalf("expected one postgres root incident, got %#v", result.Incidents)
	}
	if result.Stats.AlertCount != 20 || result.Stats.IncidentGroups != 1 ||
		result.Stats.AffectedServiceCount != 4 ||
		result.Stats.ObservedRoots != 1 || result.Stats.InferredRoots != 0 ||
		result.Stats.SuppressedAlertCount != 18 {
		t.Fatalf("unexpected topology correlation stats: %#v", result.Stats)
	}

	analysis, err := store.GetIncidentTopology(ctx, result.Incidents[0].ID)
	if err != nil {
		t.Fatalf("get incident topology: %v", err)
	}
	if analysis.RootService != "postgres" || analysis.RootInferred ||
		analysis.AlertCount != 20 || analysis.SuppressedAlertCount != 18 ||
		len(analysis.AffectedServices) != 4 || len(analysis.Paths) != 3 {
		t.Fatalf("unexpected persisted topology analysis: %#v", analysis)
	}
	stored, err := store.ListIncidents(ctx)
	if err != nil {
		t.Fatalf("list incidents: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("alert storm created %d incidents, want 1", len(stored))
	}
	signals, err := store.ListSignals(ctx, result.Incidents[0].ID)
	if err != nil || len(signals) != 20 {
		t.Fatalf("all alert evidence must be retained: signals=%d err=%v", len(signals), err)
	}

	downstreamOnly := incidents.AlertmanagerWebhook{Status: "firing", Alerts: []incidents.AlertmanagerAlert{{
		Status:      "firing",
		StartsAt:    time.Now().UTC(),
		Fingerprint: "storm-follow-up",
		Labels: map[string]string{
			"alertname": "High5xx", "service": "nginx", "environment": "test", "severity": "sev2",
		},
		Annotations: map[string]string{"summary": "nginx continues to return 5xx"},
	}}}
	followUp, err := manager.IngestAlertmanagerWithResult(ctx, downstreamOnly, "integration-test")
	if err != nil {
		t.Fatalf("ingest downstream follow-up: %v", err)
	}
	if len(followUp.Incidents) != 1 || followUp.Incidents[0].ID != result.Incidents[0].ID ||
		followUp.Stats.SuppressedAlertCount != 1 {
		t.Fatalf("downstream follow-up should attach to existing root: %#v", followUp)
	}

	if _, err := database.ExecContext(ctx, `
		TRUNCATE incident_timeline_events, signals, incidents CASCADE
	`); err != nil {
		t.Fatalf("reset incidents for root promotion: %v", err)
	}
	paymentsPayload := singleTopologyAlert("payments-api", "payments-first", startedAt)
	paymentsIncident, err := manager.IngestAlertmanager(ctx, paymentsPayload, "integration-test")
	if err != nil || len(paymentsIncident) != 1 {
		t.Fatalf("ingest downstream-first alert: incidents=%#v err=%v", paymentsIncident, err)
	}
	rootPayload := singleTopologyAlert("postgres", "postgres-late", startedAt.Add(time.Second))
	promoted, err := manager.IngestAlertmanager(ctx, rootPayload, "integration-test")
	if err != nil || len(promoted) != 1 {
		t.Fatalf("ingest late root alert: incidents=%#v err=%v", promoted, err)
	}
	if promoted[0].ID != paymentsIncident[0].ID || promoted[0].Service != "postgres" {
		t.Fatalf("late root should promote existing incident: before=%#v after=%#v", paymentsIncident[0], promoted[0])
	}
	promotedTopology, err := store.GetIncidentTopology(ctx, promoted[0].ID)
	if err != nil {
		t.Fatalf("get promoted topology: %v", err)
	}
	if promotedTopology.RootInferred || promotedTopology.SuppressedAlertCount != 1 ||
		len(promotedTopology.Paths) != 1 {
		t.Fatalf("promoted root topology is stale: %#v", promotedTopology)
	}

	if _, err := database.ExecContext(ctx, `
		TRUNCATE incident_timeline_events, signals, incidents CASCADE
	`); err != nil {
		t.Fatalf("reset incidents for concurrency check: %v", err)
	}
	concurrentPayload := singleTopologyAlert("payments-api", "concurrent-delivery", time.Now().UTC())
	managers := []*incidents.ServiceManager{
		incidents.NewServiceManager(store, auditor, 30*time.Minute),
		incidents.NewServiceManager(store, auditor, 30*time.Minute),
	}
	type ingestOutcome struct {
		items []incidents.Incident
		err   error
	}
	outcomes := make(chan ingestOutcome, len(managers))
	var wait sync.WaitGroup
	for _, concurrentManager := range managers {
		wait.Add(1)
		go func(manager *incidents.ServiceManager) {
			defer wait.Done()
			items, err := manager.IngestAlertmanager(ctx, concurrentPayload, "integration-test")
			outcomes <- ingestOutcome{items: items, err: err}
		}(concurrentManager)
	}
	wait.Wait()
	close(outcomes)

	var convergedID string
	for outcome := range outcomes {
		if outcome.err != nil || len(outcome.items) != 1 {
			t.Fatalf("concurrent ingestion failed: items=%#v err=%v", outcome.items, outcome.err)
		}
		if convergedID == "" {
			convergedID = outcome.items[0].ID
		}
		if outcome.items[0].ID != convergedID {
			t.Fatalf("concurrent managers created competing incidents: %s and %s", convergedID, outcome.items[0].ID)
		}
	}
	concurrentIncidents, err := store.ListIncidents(ctx)
	if err != nil || len(concurrentIncidents) != 1 {
		t.Fatalf("database should contain one concurrent incident: incidents=%#v err=%v", concurrentIncidents, err)
	}
}

func singleTopologyAlert(service, fingerprint string, startedAt time.Time) incidents.AlertmanagerWebhook {
	return incidents.AlertmanagerWebhook{Status: "firing", Alerts: []incidents.AlertmanagerAlert{{
		Status:      "firing",
		StartsAt:    startedAt,
		Fingerprint: fingerprint,
		Labels: map[string]string{
			"alertname": "DependencyFailure", "service": service, "environment": "test", "severity": "sev2",
		},
		Annotations: map[string]string{"summary": service + " dependency failure"},
	}}}
}
