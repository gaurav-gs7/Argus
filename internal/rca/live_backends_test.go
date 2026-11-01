package rca

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/evidence"
	"github.com/gauravgs7/argus/internal/incidents"
)

// TestLiveBackendsScenario runs RCA against a real Prometheus and Loki while
// a demo scenario is active on payments-api. It is skipped unless the live
// stack is named explicitly:
//
//	ARGUS_E2E_PROMETHEUS_URL=http://localhost:9090 \
//	ARGUS_E2E_LOKI_URL=http://localhost:3100 \
//	ARGUS_E2E_SCENARIO=postgres_connection_exhaustion \
//	ARGUS_TEST_POSTGRES_DSN=... go test -run TestLiveBackendsScenario -v ./internal/rca
//
// Set ARGUS_E2E_ALERT to a different scenario to send that scenario's alert
// while ARGUS_E2E_SCENARIO is active; the backends must then fail to
// corroborate it.
func TestLiveBackendsScenario(t *testing.T) {
	promURL, lokiURL := os.Getenv("ARGUS_E2E_PROMETHEUS_URL"), os.Getenv("ARGUS_E2E_LOKI_URL")
	scenario, dsn := os.Getenv("ARGUS_E2E_SCENARIO"), os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if promURL == "" || lokiURL == "" || scenario == "" || dsn == "" {
		t.Skip("set ARGUS_E2E_PROMETHEUS_URL, ARGUS_E2E_LOKI_URL, ARGUS_E2E_SCENARIO and ARGUS_TEST_POSTGRES_DSN")
	}
	// Alert names and labels match what the demo injectors send.
	alerts := map[string]struct {
		alert  string
		rule   correlation.RuleID
		labels map[string]string
	}{
		"postgres_connection_exhaustion": {"PaymentsAPIPostgresConnectionExhaustion", correlation.RulePostgresConnectionExhaustion, nil},
		"redis_memory_pressure":          {"PaymentsAPIRedisMemoryPressure", correlation.RuleRedisMemoryPressure, map[string]string{"cache_key_pattern": "demo:pressure:*"}},
		"dependency_latency":             {"PaymentsAPIDependencyLatency", correlation.RuleDependencyLatency, map[string]string{"degradable_feature_flag": "payments-api/optional-notifications"}},
		"bad_config_rollout":             {"PaymentsAPIBadConfigRollout", correlation.RuleBadConfigRollout, nil},
	}
	alertScenario := os.Getenv("ARGUS_E2E_ALERT")
	if alertScenario == "" {
		alertScenario = scenario
	}
	want, ok := alerts[alertScenario]
	if _, active := alerts[scenario]; !ok || !active {
		t.Fatalf("unsupported scenario %q / alert %q", scenario, alertScenario)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store := incidents.NewStore(database)
	env := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	labels := map[string]string{"alertname": want.alert, "service": "payments-api", "environment": env, "severity": "sev2"}
	for key, value := range want.labels {
		labels[key] = value
	}
	created, err := incidents.NewServiceManager(store, audit.NewService(database), 30*time.Minute).IngestAlertmanager(ctx,
		incidents.AlertmanagerWebhook{Status: "firing", Alerts: []incidents.AlertmanagerAlert{{
			Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: env,
			Labels: labels,
		}}}, "e2e")
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	collector := evidence.NewCollector(5*time.Second, map[evidence.Backend]evidence.Querier{
		evidence.Prometheus: evidence.NewPrometheus(promURL, "", client),
		evidence.Loki:       evidence.NewLoki(lokiURL, "", client),
	})
	report, candidates, err := NewService(store, "", "", testMetrics(), collector).Generate(ctx, created[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("hypothesis=%q confidence=%.4f sources=%v", report.PrimaryHypothesis, report.Confidence, report.Score.Sources)
	for _, item := range report.EvidenceItems {
		value := "-"
		if item.Value != nil {
			value = formatValue(*item.Value)
		}
		t.Logf("  %-6s %-10s %-36s %-12s value=%s %s", item.Kind, item.Source, item.Reference, item.Status, value, item.Error)
	}
	for _, factor := range report.ContributingFactors {
		t.Logf("  factor: %s", factor)
	}
	for _, candidate := range candidates {
		t.Logf("  candidate: %s -> %s", candidate.ActionType, candidate.Target)
	}

	if report.Score.RuleID != string(want.rule) {
		t.Fatalf("rule=%s want %s", report.Score.RuleID, want.rule)
	}
	for _, item := range report.EvidenceItems {
		if item.Kind == "probe" && item.Status == string(evidence.StatusUnavailable) {
			t.Fatalf("live backend probe unavailable: %+v", item)
		}
	}
	if alertScenario != scenario {
		if report.Confidence > SourceCap(1) || len(report.Score.Sources) != 1 {
			t.Fatalf("alert for an inactive scenario was corroborated: %+v", report.Score)
		}
		if report.Score.Contradicted && (len(candidates) != 1 || candidates[0].ActionType != "collect_diagnostics") {
			t.Fatalf("contradicted alert proposed remediation: %+v", candidates)
		}
		return
	}
	if len(report.Score.Sources) < 2 {
		t.Fatalf("no live backend independently corroborated the active scenario: %+v", report.Score)
	}
	if len(candidates) == 0 || candidates[0].ActionType == "collect_diagnostics" {
		t.Fatalf("corroborated scenario lost its remediation candidates: %+v", candidates)
	}
}
