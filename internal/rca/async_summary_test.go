package rca

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
)

type rcaEnv struct {
	db      *sql.DB
	store   *incidents.Store
	manager *incidents.ServiceManager
}

func newRCAEnv(t *testing.T, ctx context.Context) rcaEnv {
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
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store := incidents.NewStore(database)
	return rcaEnv{db: database, store: store, manager: incidents.NewServiceManager(store, audit.NewService(database), 30*time.Minute)}
}

func (e rcaEnv) ingest(t *testing.T, ctx context.Context, fingerprint string) incidents.Incident {
	t.Helper()
	created, err := e.manager.IngestAlertmanager(ctx, incidents.AlertmanagerWebhook{Alerts: []incidents.AlertmanagerAlert{{
		Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: fingerprint,
		Labels: map[string]string{"alertname": "PaymentsAPIPostgresPoolSaturation", "service": "payments-api", "environment": fingerprint},
	}}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return created[0]
}

func (e rcaEnv) count(t *testing.T, query, incidentID string) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow(query, incidentID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// fakeAI answers /v1/rca/summarize after delay, or fails.
func fakeAI(t *testing.T, delay time.Duration, fail bool, calls *atomic.Int32, gotAuth *atomic.Value) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if gotAuth != nil {
			gotAuth.Store(r.Header.Get("Authorization"))
		}
		time.Sleep(delay)
		if fail {
			http.Error(w, "model unavailable", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"summary": "advisory summary", "backend": "mock", "model": "mock-1"})
	}))
	t.Cleanup(server.Close)
	return server
}

func waitForReport(t *testing.T, store *incidents.Store, incidentID, status string) incidents.RCAReport {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := store.GetLatestRCAReport(context.Background(), incidentID)
		if err == nil && report.LLMStatus == status {
			return report
		}
		if time.Now().After(deadline) {
			t.Fatalf("report never reached llm_status=%s (last %q, err %v)", status, report.LLMStatus, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The RCA endpoint used to answer 202 "queued" while running the whole LLM
// call inside the request. The deterministic report must now be complete
// without waiting on the model.
func TestGenerateDoesNotWaitForTheLLM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newRCAEnv(t, ctx)
	calls := &atomic.Int32{}
	auth := &atomic.Value{}
	ai := fakeAI(t, 2*time.Second, false, calls, auth)
	svc := NewService(env.store, ai.URL, "svc-token", testMetrics(), nil)
	incident := env.ingest(t, ctx, fmt.Sprintf("async-%d", time.Now().UnixNano()))

	start := time.Now()
	report, candidates, err := svc.Generate(ctx, incident.ID)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > time.Second {
		t.Fatalf("Generate waited %s for a 2s LLM call", elapsed)
	}
	if report.LLMStatus != incidents.LLMStatusPending || report.ID == "" || report.CreatedAt.IsZero() || len(candidates) == 0 {
		t.Fatalf("report=%+v candidates=%d", report, len(candidates))
	}
	stored, err := env.store.GetLatestRCAReport(ctx, incident.ID)
	if err != nil || stored.ID != report.ID || len(stored.Candidates) != len(candidates) {
		t.Fatalf("stored report=%+v err=%v", stored, err)
	}
	done := waitForReport(t, env.store, incident.ID, incidents.LLMStatusCompleted)
	if done.LLMSummary != "advisory summary" || done.ModelBackend != "mock" || done.ModelName != "mock-1" {
		t.Fatalf("summary not recorded: %+v", done)
	}
	if done.Confidence != report.Confidence || done.PrimaryHypothesis != report.PrimaryHypothesis {
		t.Fatal("the LLM summary changed deterministic fields")
	}
	if auth.Load() != "Bearer svc-token" {
		t.Fatalf("summarize call sent auth %q", auth.Load())
	}
	t.Logf("deterministic report returned in %s; LLM summary arrived later", elapsed.Round(time.Millisecond))
}

func TestLLMFailureAndDisabledStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newRCAEnv(t, ctx)
	calls := &atomic.Int32{}
	failing := NewService(env.store, fakeAI(t, 0, true, calls, nil).URL, "t", testMetrics(), nil)
	incident := env.ingest(t, ctx, fmt.Sprintf("llm-fail-%d", time.Now().UnixNano()))
	if _, _, err := failing.Generate(ctx, incident.ID); err != nil {
		t.Fatal(err)
	}
	failed := waitForReport(t, env.store, incident.ID, incidents.LLMStatusFailed)
	if failed.LLMSummary != "" || failed.ModelBackend != "deterministic" {
		t.Fatalf("failed summary left data behind: %+v", failed)
	}

	disabled := NewService(env.store, "", "", testMetrics(), nil)
	other := env.ingest(t, ctx, fmt.Sprintf("llm-off-%d", time.Now().UnixNano()))
	report, _, err := disabled.Generate(ctx, other.ID)
	if err != nil || report.LLMStatus != incidents.LLMStatusDisabled {
		t.Fatalf("disabled AI: status=%q err=%v", report.LLMStatus, err)
	}
}

func TestCloseWaitsForPendingSummaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newRCAEnv(t, ctx)
	calls := &atomic.Int32{}
	svc := NewService(env.store, fakeAI(t, 500*time.Millisecond, false, calls, nil).URL, "t", testMetrics(), nil)
	incident := env.ingest(t, ctx, fmt.Sprintf("close-%d", time.Now().UnixNano()))
	if _, _, err := svc.Generate(ctx, incident.ID); err != nil {
		t.Fatal(err)
	}
	svc.Close(5 * time.Second)
	if report, _ := env.store.GetLatestRCAReport(ctx, incident.ID); report.LLMStatus != incidents.LLMStatusCompleted {
		t.Fatalf("Close returned before the summary finished: %q", report.LLMStatus)
	}
}

// Every /propose call used to regenerate the RCA: new report, probes re-run,
// probe timeline events duplicated.
func TestProposalReusesCurrentReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newRCAEnv(t, ctx)
	svc := NewService(env.store, "", "", testMetrics(), nil)
	fingerprint := fmt.Sprintf("reuse-%d", time.Now().UnixNano())
	incident := env.ingest(t, ctx, fingerprint)

	first, firstCandidates, reused, err := svc.ReportForProposal(ctx, incident)
	if err != nil || reused || len(firstCandidates) == 0 {
		t.Fatalf("first proposal: reused=%v candidates=%d err=%v", reused, len(firstCandidates), err)
	}
	reportsQuery := `SELECT count(*) FROM rca_reports WHERE incident_id = $1`
	timelineQuery := `SELECT count(*) FROM incident_timeline_events WHERE incident_id = $1`
	reports, events := env.count(t, reportsQuery, incident.ID), env.count(t, timelineQuery, incident.ID)

	for range 3 {
		current, _ := env.store.GetIncident(ctx, incident.ID)
		again, candidates, reused, err := svc.ReportForProposal(ctx, current)
		if err != nil || !reused || again.ID != first.ID || len(candidates) != len(firstCandidates) {
			t.Fatalf("repeat proposal: reused=%v id=%s err=%v", reused, again.ID, err)
		}
	}
	if env.count(t, reportsQuery, incident.ID) != reports || env.count(t, timelineQuery, incident.ID) != events {
		t.Fatal("repeat proposals created reports or timeline events")
	}

	// A new alert delivery makes the report stale.
	time.Sleep(10 * time.Millisecond)
	refired := env.ingest(t, ctx, fingerprint)
	if refired.ID != incident.ID {
		t.Fatalf("re-notification opened a new incident")
	}
	current, _ := env.store.GetIncident(ctx, incident.ID)
	fresh, _, reused, err := svc.ReportForProposal(ctx, current)
	if err != nil || reused || fresh.ID == first.ID {
		t.Fatalf("new alert did not refresh the report: reused=%v err=%v", reused, err)
	}
}

func TestReindexRunbooksCallsTheAIService(t *testing.T) {
	var gotPath, gotAuth string
	ai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "indexed_chunks": 12})
	}))
	defer ai.Close()
	result, err := NewService(nil, ai.URL, "svc-token", nil, nil).ReindexRunbooks(context.Background())
	if err != nil || result["indexed_chunks"] != float64(12) || gotPath != "/v1/runbooks/index" || gotAuth != "Bearer svc-token" {
		t.Fatalf("result=%v err=%v path=%q auth=%q", result, err, gotPath, gotAuth)
	}
	if _, err := NewService(nil, "", "", nil, nil).ReindexRunbooks(context.Background()); err != ErrAIServiceDisabled {
		t.Fatalf("disabled AI: %v", err)
	}
}
