package rca

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/evidence"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
)

var (
	metricsOnce   sync.Once
	sharedMetrics *telemetry.Metrics
)

// testMetrics registers Prometheus collectors once per test binary.
func testMetrics() *telemetry.Metrics {
	metricsOnce.Do(func() { sharedMetrics = telemetry.MustRegister() })
	return sharedMetrics
}

// promAPI serves the Prometheus/Loki instant-query envelope, answering by
// substring of the query.
func promAPI(t *testing.T, path string, answers map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query().Get("query")
		mu.Lock()
		asked = append(asked, query)
		mu.Unlock()
		for fragment, value := range answers {
			if strings.Contains(query, fragment) {
				fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d,%q]}]}}`, time.Now().Unix(), value)
				return
			}
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(server.Close)
	return server, &asked
}

func TestGeneratePersistsQueriedEvidence(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store := incidents.NewStore(database)
	manager := incidents.NewServiceManager(store, audit.NewService(database), 30*time.Minute)
	// Unique per run so topology grouping cannot reuse an earlier run's incident.
	fingerprint := fmt.Sprintf("rca-int-%d", time.Now().UnixNano())
	created, err := manager.IngestAlertmanager(ctx, incidents.AlertmanagerWebhook{Status: "firing", Alerts: []incidents.AlertmanagerAlert{{
		Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: fingerprint,
		Labels:      map[string]string{"alertname": "PaymentsAPIPostgresPoolSaturation", "service": "payments-api", "environment": fingerprint, "severity": "sev2"},
		Annotations: map[string]string{"summary": "pool saturated"},
	}}}, "integration-test")
	if err != nil || len(created) != 1 {
		t.Fatalf("ingest: %v %+v", err, created)
	}

	prom, promAsked := promAPI(t, "/api/v1/query", map[string]string{
		"db_connection_pool_in_use": "0.96",
		"http_requests_total":       "0.003", // error ratio well under 5%: refutes
	})
	loki, lokiAsked := promAPI(t, "/loki/api/v1/query", map[string]string{"connection acquisition timeout": "17"})
	collector := evidence.NewCollector(2*time.Second, map[evidence.Backend]evidence.Querier{
		evidence.Prometheus: evidence.NewPrometheus(prom.URL, "", prom.Client()),
		evidence.Loki:       evidence.NewLoki(loki.URL, "", loki.Client()),
	})
	svc := NewService(store, "", "", testMetrics(), collector)

	report, candidates, err := svc.Generate(ctx, created[0].ID)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(*promAsked) != 2 || len(*lokiAsked) != 1 {
		t.Fatalf("backends asked prometheus=%v loki=%v", *promAsked, *lokiAsked)
	}
	// 0.45 + 0.20 (pool) + 0.20 (logs) - 0.5*0.10 (error ratio refuted) = 0.80, three sources.
	if report.PrimaryHypothesis != "PostgreSQL connection pool exhaustion" || report.Confidence != 0.8 {
		t.Fatalf("report=%q %.4f score=%+v", report.PrimaryHypothesis, report.Confidence, report.Score)
	}
	if report.Score.Raw != 0.8 || report.Score.RefutationPenalty != 0.05 || len(report.Score.Sources) != 3 {
		t.Fatalf("persisted score=%+v", report.Score)
	}
	statuses := map[string]string{}
	for _, item := range report.EvidenceItems {
		statuses[item.Reference] = item.Status
	}
	want := map[string]string{
		"PaymentsAPIPostgresPoolSaturation": "matched",
		"postgres_pool_utilisation":         "corroborated",
		"postgres_service_error_ratio":      "refuted",
		"postgres_acquisition_timeout_logs": "corroborated",
	}
	for ref, status := range want {
		if statuses[ref] != status {
			t.Fatalf("persisted evidence items=%v, want %s=%s", statuses, ref, status)
		}
	}
	if len(candidates) == 0 || candidates[0].ActionType == "collect_diagnostics" {
		t.Fatalf("supported hypothesis lost its candidates: %+v", candidates)
	}

	timeline, err := store.ListTimeline(ctx, created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	probeEvents := 0
	for _, event := range timeline {
		if strings.HasPrefix(event.EventType, "probe_") {
			probeEvents++
			if event.Source != "prometheus" && event.Source != "loki" {
				t.Fatalf("probe event from unexpected source: %+v", event)
			}
		}
	}
	if probeEvents != 3 {
		t.Fatalf("expected 3 probe timeline events, got %d", probeEvents)
	}
}
