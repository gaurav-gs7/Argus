package rca

import (
	"context"
	"errors"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/evidence"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/topology"
)

var fixedNow = time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)

// answer is a recorded backend response for one probe.
type answer struct {
	value  float64
	noData bool
	err    error
}

// tableQuerier answers rendered queries from a fixed table and records what it
// was asked. Unknown queries return no data.
type tableQuerier struct {
	mu      sync.Mutex
	answers map[string]answer
	asked   []string
}

func (q *tableQuerier) Instant(_ context.Context, query string, _ time.Time) (float64, bool, error) {
	q.mu.Lock()
	q.asked = append(q.asked, query)
	q.mu.Unlock()
	a, ok := q.answers[query]
	if !ok || a.noData {
		return 0, false, a.err
	}
	return a.value, true, a.err
}

// backends builds Prometheus/Loki fakes whose answers are keyed by probe ID
// for the given service.
func backends(service string, byProbe map[string]answer) (map[evidence.Backend]evidence.Querier, map[evidence.Backend]*tableQuerier) {
	tables := map[evidence.Backend]*tableQuerier{
		evidence.Prometheus: {answers: map[string]answer{}},
		evidence.Loki:       {answers: map[string]answer{}},
	}
	for _, rule := range correlation.DefaultRules() {
		for _, probe := range rule.Probes {
			a, ok := byProbe[probe.ID]
			if !ok {
				continue
			}
			query, err := evidence.Render(probe.Query, service)
			if err != nil {
				panic(err)
			}
			tables[probe.Backend].answers[query] = a
		}
	}
	return map[evidence.Backend]evidence.Querier{evidence.Prometheus: tables[evidence.Prometheus], evidence.Loki: tables[evidence.Loki]}, tables
}

func newTestService(queriers map[evidence.Backend]evidence.Querier) *Service {
	svc := NewService(nil, "", "", nil, evidence.NewCollector(time.Second, queriers))
	svc.now = func() time.Time { return fixedNow }
	return svc
}

func alert(name, service string, extra map[string]string) incidents.Signal {
	labels := map[string]any{"alertname": name, "service": service}
	for k, v := range extra {
		labels[k] = v
	}
	return incidents.Signal{ID: "sig_" + name, Name: name, Source: "alertmanager", SignalType: "alert",
		Body: map[string]any{"labels": labels}, ObservedAt: fixedNow.Add(-time.Minute)}
}

func incidentFor(service string) incidents.Incident {
	return incidents.Incident{ID: "inc_test", Title: "test incident", Service: service, Severity: "sev2", StartedAt: fixedNow.Add(-2 * time.Minute)}
}

func run(svc *Service, incident incidents.Incident, signals ...incidents.Signal) analysis {
	return svc.analyze(context.Background(), incident, signals, incidents.IncidentTopology{})
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestAuthorizeAIRequestUsesServiceCredential(t *testing.T) {
	service := &Service{aiServiceToken: "service-secret"}
	req, err := http.NewRequest(http.MethodPost, "http://argus-ai/v1/remediation/suggest", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	service.authorizeAIRequest(req)
	if got := req.Header.Get("Authorization"); got != "Bearer service-secret" {
		t.Fatalf("unexpected authorization header %q", got)
	}
}

func TestValidateAdvisoryResponseFailsClosed(t *testing.T) {
	valid := map[string]any{"executed": false, "advisory_only": true}
	if err := validateAdvisoryResponse(valid); err != nil {
		t.Fatalf("valid advisory response rejected: %v", err)
	}
	for _, invalid := range []map[string]any{
		{"advisory_only": true},
		{"executed": false},
		{"executed": true, "advisory_only": true},
		{"executed": false, "advisory_only": false},
	} {
		if err := validateAdvisoryResponse(invalid); err == nil {
			t.Fatalf("unsafe response accepted: %#v", invalid)
		}
	}
}

func TestSourceCap(t *testing.T) {
	for sources, want := range map[int]float64{0: 0.55, 1: 0.55, 2: 0.80, 3: 0.95, 4: 0.95} {
		if got := SourceCap(sources); got != want {
			t.Fatalf("SourceCap(%d)=%v want %v", sources, got, want)
		}
	}
}

// corroborate answers every probe of a rule with a value that satisfies it.
func corroborate(rule correlation.RuleID, only ...evidence.Backend) map[string]answer {
	answers := map[string]answer{}
	for _, r := range correlation.DefaultRules() {
		if r.ID != rule {
			continue
		}
		for _, probe := range r.Probes {
			if len(only) > 0 && probe.Backend != only[0] {
				continue
			}
			answers[probe.ID] = answer{value: probe.Threshold + 1}
		}
	}
	return answers
}

func TestScenarioScores(t *testing.T) {
	cases := []struct {
		alert      string
		rule       correlation.RuleID
		hypothesis string
		full       float64 // every probe corroborated
		sources    int     // independent sources when every probe corroborates
		promOnly   float64 // only Prometheus probes corroborated
	}{
		{"PaymentsAPIPostgresConnectionExhaustion", correlation.RulePostgresConnectionExhaustion, "PostgreSQL connection pool exhaustion", 0.95, 3, 0.75},
		{"PaymentsAPIRedisMemoryPressure", correlation.RuleRedisMemoryPressure, "Redis memory pressure causing cache degradation", 0.95, 3, 0.80},
		// Nginx, latency and config have only symptom probes on Prometheus, so
		// Prometheus alone never lifts them past the single-source cap.
		{"Nginx5xxSpike", correlation.RuleNginxUpstreamConfig, "Nginx upstream misconfiguration or bad route rollout", 0.80, 2, 0.55},
		{"PaymentsAPIDependencyLatency", correlation.RuleDependencyLatency, "Downstream dependency latency dominates the request path", 0.80, 2, 0.55},
		{"PaymentsAPIBadConfigRollout", correlation.RuleBadConfigRollout, "Bad config rollout introduced an invalid runtime configuration", 0.80, 2, 0.55},
	}
	for _, tc := range cases {
		t.Run(string(tc.rule), func(t *testing.T) {
			queriers, _ := backends("payments-api", corroborate(tc.rule))
			full := run(newTestService(queriers), incidentFor("payments-api"), alert(tc.alert, "payments-api", nil))
			if full.Hypothesis != tc.hypothesis || !near(full.Confidence, tc.full) {
				t.Fatalf("full corroboration: %q %.4f, want %q %.4f", full.Hypothesis, full.Confidence, tc.hypothesis, tc.full)
			}
			if len(full.Score.Sources) != tc.sources || full.Score.Final != full.Confidence {
				t.Fatalf("full corroboration sources=%v score=%+v", full.Score.Sources, full.Score)
			}

			queriers, _ = backends("payments-api", corroborate(tc.rule, evidence.Prometheus))
			prom := run(newTestService(queriers), incidentFor("payments-api"), alert(tc.alert, "payments-api", nil))
			if !near(prom.Confidence, tc.promOnly) {
				t.Fatalf("prometheus only: %.4f want %.4f (%+v)", prom.Confidence, tc.promOnly, prom.Score)
			}

			alone := run(newTestService(nil), incidentFor("payments-api"), alert(tc.alert, "payments-api", nil))
			if !near(alone.Confidence, AlertMatchScore) || len(alone.Score.Sources) != 1 {
				t.Fatalf("alert only: %.4f sources=%v", alone.Confidence, alone.Score.Sources)
			}
			t.Logf("%s full=%.2f prometheus-only=%.2f alert-only=%.2f", tc.rule, full.Confidence, prom.Confidence, alone.Confidence)
		})
	}
}

func TestSingleAlertDoesNotClaimUnqueriedBackends(t *testing.T) {
	got := run(newTestService(nil), incidentFor("payments-api"), alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil))
	if got.Confidence >= 0.6 {
		t.Fatalf("one alert produced confidence %.2f", got.Confidence)
	}
	for _, line := range got.Evidence {
		if strings.HasPrefix(line, "prometheus") || strings.HasPrefix(line, "loki") {
			t.Fatalf("evidence cites a backend that never answered: %q", line)
		}
	}
	for _, item := range got.Items {
		if item.Kind == "probe" && (item.Status != string(evidence.StatusUnavailable) || item.Value != nil || !strings.Contains(item.Error, "not configured")) {
			t.Fatalf("unconfigured probe recorded as observed: %+v", item)
		}
	}
	if !reflect.DeepEqual(got.Score.Sources, []string{"alertmanager"}) {
		t.Fatalf("sources=%v", got.Score.Sources)
	}
}

func TestAnnotationKeywordsCannotSteerDiagnosis(t *testing.T) {
	svc := newTestService(nil)

	redis := alert("RedisMemoryHigh", "cache", nil)
	redis.Body["annotations"] = map[string]any{"description": "redis memory usage above 90% of maxmemory config"}
	if got := run(svc, incidentFor("cache"), redis); got.Hypothesis != "Redis memory pressure causing cache degradation" {
		t.Fatalf("config keyword steered a Redis alert: %q", got.Hypothesis)
	}

	disk := alert("NodeDiskAlmostFull", "notification-api", nil)
	disk.Body["annotations"] = map[string]any{"summary": "disk 95% full; latency; postgres connection; config rollout"}
	got := run(svc, incidentFor("notification-api"), disk)
	if got.Hypothesis != insufficientHypothesis || got.Confidence != BaselineConfidence {
		t.Fatalf("unknown alert was classified: %q %.2f", got.Hypothesis, got.Confidence)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].ActionType != "collect_diagnostics" || got.Candidates[0].Target != "notification-api" {
		t.Fatalf("unknown alert should only collect diagnostics on its service: %+v", got.Candidates)
	}
}

func TestRefutingEvidenceContradictsHypothesisAndBlocksRemediation(t *testing.T) {
	queriers, _ := backends("payments-api", map[string]answer{
		"postgres_pool_utilisation":         {value: 0.22},
		"postgres_service_error_ratio":      {value: 0.001},
		"postgres_acquisition_timeout_logs": {noData: true},
	})
	got := run(newTestService(queriers), incidentFor("payments-api"), alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil))
	if !got.Score.Contradicted || got.Confidence != BaselineConfidence {
		t.Fatalf("refuted hypothesis not contradicted: %+v", got.Score)
	}
	if !near(got.Score.Raw, 0.30) || !near(got.Score.RefutationPenalty, 0.15) {
		t.Fatalf("refutation arithmetic: %+v", got.Score)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].ActionType != "collect_diagnostics" {
		t.Fatalf("contradicted hypothesis proposed remediation: %+v", got.Candidates)
	}
	if !strings.Contains(got.Summary, "contradicts") {
		t.Fatalf("summary does not disclose the contradiction: %q", got.Summary)
	}
}

func TestPartialRefutationLowersConfidence(t *testing.T) {
	queriers, _ := backends("payments-api", map[string]answer{
		"postgres_pool_utilisation":    {value: 0.97},
		"postgres_service_error_ratio": {value: 0.01},
	})
	got := run(newTestService(queriers), incidentFor("payments-api"), alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil))
	// 0.45 + 0.20 - 0.5*0.10 = 0.60, two sources -> cap 0.80
	if got.Score.Contradicted || !near(got.Confidence, 0.60) || got.Score.SourceCap != 0.80 {
		t.Fatalf("partial refutation: %+v", got.Score)
	}
	if got.Candidates[0].ActionType == "collect_diagnostics" {
		t.Fatalf("supported hypothesis should keep its remediation candidates")
	}
	joined := strings.Join(got.Factors, "\n")
	for _, want := range []string{"corroborated: observed 0.97 >= 0.9 (+0.20)", "refuted: observed 0.01, expected >= 0.05 (-0.05)", "returned no matching series (not counted)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("factors missing %q:\n%s", want, joined)
		}
	}
}

func TestFailingBackendsAreNeverCounted(t *testing.T) {
	failing := map[string]answer{}
	for _, rule := range correlation.DefaultRules() {
		for _, probe := range rule.Probes {
			failing[probe.ID] = answer{err: errors.New("connection refused")}
		}
	}
	queriers, _ := backends("payments-api", failing)
	got := run(newTestService(queriers), incidentFor("payments-api"), alert("PaymentsAPIRedisMemoryPressure", "payments-api", nil))
	if !near(got.Confidence, AlertMatchScore) || got.Score.Corroborated != 0 || got.Score.Refuted != 0 {
		t.Fatalf("failing backends changed the score: %+v", got.Score)
	}
	probeFactors := 0
	for _, factor := range got.Factors {
		if !strings.Contains(factor, " probe ") {
			continue
		}
		probeFactors++
		if !strings.Contains(factor, "unavailable: connection refused (not counted)") {
			t.Fatalf("factor hides the failure: %q", factor)
		}
	}
	if probeFactors != 3 {
		t.Fatalf("expected 3 probe factors, got %d: %v", probeFactors, got.Factors)
	}
}

func TestFailureModeLabelSelectsRule(t *testing.T) {
	got := run(newTestService(nil), incidentFor("orders"),
		alert("OrdersDBSaturated", "orders", map[string]string{correlation.FailureModeLabel: "postgres_connection_exhaustion"}))
	if got.RuleID != correlation.RulePostgresConnectionExhaustion || !strings.Contains(got.Factors[0], "label argus_failure_mode=") {
		t.Fatalf("label override ignored: %q %v", got.RuleID, got.Factors)
	}
}

func TestProbesAreScopedToTheAlertedService(t *testing.T) {
	queriers, tables := backends("checkout-api", corroborate(correlation.RuleDependencyLatency))
	got := run(newTestService(queriers), incidentFor("payments-api"), alert("PaymentsAPIDependencyLatency", "checkout-api", nil))
	if !near(got.Confidence, 0.80) {
		t.Fatalf("probes not scoped to the alert's service: %+v", got.Score)
	}
	for _, query := range append(tables[evidence.Prometheus].asked, tables[evidence.Loki].asked...) {
		if !strings.Contains(query, `service="checkout-api"`) {
			t.Fatalf("probe queried another service: %s", query)
		}
	}
}

func TestUnsafeServiceLabelNeverReachesBackends(t *testing.T) {
	queriers, tables := backends("payments-api", corroborate(correlation.RulePostgresConnectionExhaustion))
	got := run(newTestService(queriers), incidentFor("payments-api"),
		alert("PaymentsAPIPostgresConnectionExhaustion", `payments-api"} or vector(1) #`, nil))
	if len(tables[evidence.Prometheus].asked)+len(tables[evidence.Loki].asked) != 0 {
		t.Fatalf("injected label value reached a backend")
	}
	if !near(got.Confidence, AlertMatchScore) {
		t.Fatalf("unsafe label should leave only the alert match: %+v", got.Score)
	}
}

func TestCompetingHypothesesAreRankedByEvidence(t *testing.T) {
	queriers, _ := backends("payments-api", corroborate(correlation.RuleBadConfigRollout))
	svc := newTestService(queriers)
	signals := []incidents.Signal{
		alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil),
		alert("PaymentsAPIBadConfigRollout", "payments-api", nil),
	}
	got := run(svc, incidentFor("payments-api"), signals...)
	if got.RuleID != correlation.RuleBadConfigRollout || !near(got.Confidence, 0.80) {
		t.Fatalf("corroborated hypothesis did not win: %s %.2f", got.RuleID, got.Confidence)
	}
	rules := map[string]int{}
	for _, item := range got.Items {
		rules[item.RuleID]++
	}
	if rules[string(correlation.RulePostgresConnectionExhaustion)] != 4 || rules[string(correlation.RuleBadConfigRollout)] != 3 {
		t.Fatalf("losing hypothesis evidence must be retained for audit: %v", rules)
	}
}

func TestEqualScoresBreakTiesLexically(t *testing.T) {
	svc := newTestService(nil)
	signals := []incidents.Signal{
		alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil),
		alert("PaymentsAPIBadConfigRollout", "payments-api", nil),
	}
	for i := 0; i < 50; i++ {
		got := run(svc, incidentFor("payments-api"), signals[i%2], signals[(i+1)%2])
		if got.RuleID != correlation.RuleBadConfigRollout {
			t.Fatalf("tie winner=%s, want lexical Bad config rollout", got.RuleID)
		}
	}
}

func TestReplayIsStable(t *testing.T) {
	queriers, _ := backends("payments-api", map[string]answer{
		"postgres_pool_utilisation":         {value: 0.95},
		"postgres_service_error_ratio":      {value: 0.02},
		"postgres_acquisition_timeout_logs": {value: 14},
	})
	svc := newTestService(queriers)
	signal := alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil)
	want := run(svc, incidentFor("payments-api"), signal)
	for i := 0; i < 100; i++ {
		if got := run(svc, incidentFor("payments-api"), signal); !reflect.DeepEqual(got, want) {
			t.Fatalf("replay %d changed output:\ngot:  %#v\nwant: %#v", i+1, got, want)
		}
	}
	t.Logf("100/100 replays identical; %s %.4f", want.Hypothesis, want.Confidence)
}

func TestEvidenceItemsRecordEveryObservation(t *testing.T) {
	queriers, _ := backends("payments-api", map[string]answer{
		"postgres_pool_utilisation":         {value: 0.95},
		"postgres_acquisition_timeout_logs": {value: 3},
	})
	got := run(newTestService(queriers), incidentFor("payments-api"), alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil))
	if len(got.Items) != 4 || got.Items[0].Kind != "alert" || got.Items[0].Source != "alertmanager" {
		t.Fatalf("items=%+v", got.Items)
	}
	pool := got.Items[1]
	if pool.Status != "corroborated" || *pool.Value != 0.95 || *pool.Threshold != 0.9 || pool.Source != "prometheus" ||
		!strings.Contains(pool.Query, `db_connection_pool_in_use{service="payments-api"}`) || !pool.ObservedAt.Equal(fixedNow) {
		t.Fatalf("pool probe item=%+v", pool)
	}
	if got.Items[2].Status != "no_data" || got.Items[2].Value != nil {
		t.Fatalf("no-data item=%+v", got.Items[2])
	}
	events := probeTimelineEvents("inc_test", got.Items)
	if len(events) != 2 || events[0].EventType != "probe_corroborated" || events[0].Source != "prometheus" {
		t.Fatalf("timeline events=%+v", events)
	}
	// 0.45 + 0.20 + 0.20 = 0.85 with three sources -> 0.85
	if !near(got.Confidence, 0.85) || !reflect.DeepEqual(got.Score.Sources, []string{"alertmanager", "loki", "prometheus"}) {
		t.Fatalf("score=%+v", got.Score)
	}
	if !strings.Contains(got.Summary, "min(max(0.45 alert match + 0.40 corroborated - 0.00 refutation penalty, 0.35), 0.95 cap for 3 independent source(s)") {
		t.Fatalf("summary arithmetic not inspectable: %q", got.Summary)
	}
}

func TestNoMatchFallsBackToDiagnostics(t *testing.T) {
	got := run(newTestService(nil), incidentFor("payments-api"), alert("UnknownAlert", "payments-api", nil))
	if got.Hypothesis != insufficientHypothesis || got.Confidence != BaselineConfidence || len(got.Items) != 0 {
		t.Fatalf("fallback=%+v", got)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].ActionType != "collect_diagnostics" || got.Candidates[0].Risk != "low" {
		t.Fatalf("expected low-risk diagnostics fallback, got %+v", got.Candidates)
	}
}

func observedTopology() incidents.IncidentTopology {
	return incidents.IncidentTopology{
		RootService:          "postgres",
		AffectedServices:     []string{"checkout-api", "nginx", "payments-api", "postgres"},
		AlertCount:           20,
		SuppressedAlertCount: 18,
		Paths:                []topology.Path{{From: "nginx", To: "postgres", Services: []string{"nginx", "payments-api", "postgres"}}},
	}
}

func TestObservedTopologyAdjustmentStaysUnderSourceCap(t *testing.T) {
	signal := alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil)
	alone := newTestService(nil).analyze(context.Background(), incidentFor("payments-api"), []incidents.Signal{signal}, observedTopology())
	if !near(alone.Confidence, 0.48) || !near(alone.Score.TopologyAdjustment, 0.03) {
		t.Fatalf("alert-only + observed root: %+v", alone.Score)
	}
	if !strings.Contains(alone.Summary, "observed root service postgres") || !strings.Contains(alone.Summary, "suppressed 18 downstream alerts") {
		t.Fatalf("topology summary missing context: %q", alone.Summary)
	}

	queriers, _ := backends("payments-api", corroborate(correlation.RulePostgresConnectionExhaustion))
	full := newTestService(queriers).analyze(context.Background(), incidentFor("payments-api"), []incidents.Signal{signal}, observedTopology())
	if full.Confidence != 0.95 || full.Score.TopologyAdjustment != 0 {
		t.Fatalf("topology pushed past the cap: %+v", full.Score)
	}
}

func TestInferredTopologyDoesNotInflateConfidence(t *testing.T) {
	topo := observedTopology()
	topo.RootInferred = true
	got := newTestService(nil).analyze(context.Background(), incidentFor("payments-api"),
		[]incidents.Signal{alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", nil)}, topo)
	if !near(got.Confidence, AlertMatchScore) || !strings.Contains(got.Summary, "inferred root service") {
		t.Fatalf("inferred root changed confidence: %+v", got.Score)
	}
}

func TestTopologyFallbackNamesFailureDomainWithoutInventingFailureMode(t *testing.T) {
	topo := observedTopology()
	got := newTestService(nil).analyze(context.Background(), incidents.Incident{Title: "Downstream request failures", Service: "postgres"},
		[]incidents.Signal{alert("DependencyFailure", "checkout-api", nil)}, topo)
	if got.Hypothesis != "Failure at root dependency postgres" || got.Confidence != 0.72 {
		t.Fatalf("unexpected topology fallback: %q %.2f", got.Hypothesis, got.Confidence)
	}
	if strings.Contains(strings.ToLower(got.Hypothesis+got.Summary), "connection pool") {
		t.Fatalf("topology fallback invented a failure mode")
	}
	if len(got.Candidates) != 1 || got.Candidates[0].ActionType != "collect_diagnostics" || got.Candidates[0].Target != "postgres" {
		t.Fatalf("topology-only evidence must produce diagnostics only: %+v", got.Candidates)
	}

	topo.RootInferred = true
	inferred := newTestService(nil).analyze(context.Background(), incidents.Incident{Service: "payments-api"},
		[]incidents.Signal{alert("DependencyFailure", "checkout-api", nil)}, topo)
	if inferred.Confidence != 0.58 {
		t.Fatalf("inferred topology confidence=%v, want 0.58", inferred.Confidence)
	}
}

func candidateTargets(candidates []Candidate) map[string]string {
	out := map[string]string{}
	for _, c := range candidates {
		out[c.ActionType] = c.Target
	}
	return out
}

func TestRemediationTargetsComeFromTheMatchedAlert(t *testing.T) {
	svc := newTestService(nil)
	cases := []struct {
		name   string
		signal incidents.Signal
		want   map[string]string
	}{
		{"postgres uses alert service and pod label", alert("PaymentsAPIPostgresConnectionExhaustion", "orders-api", map[string]string{"pod": "orders-api-7c9d"}),
			map[string]string{"drain_postgres_connections": "orders-api", "resize_connection_pool": "orders-api", "restart_pod": "local/orders-api-7c9d"}},
		{"pod falls back to service", alert("PaymentsAPIBadConfigRollout", "billing", nil),
			map[string]string{"rollback_config": "billing", "restart_pod": "local/billing"}},
		{"nginx targets the alerting edge service", alert("Nginx5xxSpike", "edge-proxy", nil),
			map[string]string{"rollback_config": "edge-proxy", "reload_nginx": "edge-proxy"}},
		{"redis uses the cache_key_pattern label", alert("PaymentsAPIRedisMemoryPressure", "payments-api", map[string]string{"cache_key_pattern": "demo:pressure:*"}),
			map[string]string{"purge_cache": "demo:pressure:*"}},
		{"latency uses the degradable_feature_flag label", alert("PaymentsAPIDependencyLatency", "checkout-api", map[string]string{"degradable_feature_flag": "checkout-api/async-confirmation"}),
			map[string]string{"toggle_feature_flag": "checkout-api/async-confirmation"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := run(svc, incidentFor("incident-root"), tc.signal)
			if targets := candidateTargets(got.Candidates); !reflect.DeepEqual(targets, tc.want) {
				t.Fatalf("targets=%v want %v", targets, tc.want)
			}
			for _, c := range got.Candidates {
				if c.Risk != "medium" || !c.RequiresApproval {
					t.Fatalf("candidate lost its approval requirement: %+v", c)
				}
			}
		})
	}
}

func TestMissingOrUnsafeTargetsFallBackToDiagnostics(t *testing.T) {
	svc := newTestService(nil)
	cases := []struct {
		name   string
		signal incidents.Signal
		reason string
	}{
		{"redis without key pattern", alert("PaymentsAPIRedisMemoryPressure", "payments-api", nil), "alert has no label cache_key_pattern"},
		{"latency without flag", alert("PaymentsAPIDependencyLatency", "notification-api", nil), "alert has no label degradable_feature_flag"},
		{"flag not allow-listed", alert("PaymentsAPIDependencyLatency", "payments-api", map[string]string{"degradable_feature_flag": "payments-api/delete-everything"}), "rejected by action catalog"},
		{"unscoped cache pattern", alert("PaymentsAPIRedisMemoryPressure", "payments-api", map[string]string{"cache_key_pattern": "*"}), "rejected by action catalog"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := run(svc, incidentFor("payments-api"), tc.signal)
			if len(got.Candidates) != 1 || got.Candidates[0].ActionType != "collect_diagnostics" || got.Candidates[0].RequiresApproval {
				t.Fatalf("candidates=%+v", got.Candidates)
			}
			if !strings.Contains(strings.Join(got.Factors, "\n"), tc.reason) {
				t.Fatalf("factors do not explain the dropped candidate (%q): %v", tc.reason, got.Factors)
			}
		})
	}
}

func TestPodLabelInjectionIsRejected(t *testing.T) {
	got := run(newTestService(nil), incidentFor("payments-api"),
		alert("PaymentsAPIPostgresConnectionExhaustion", "payments-api", map[string]string{"pod": "../../etc"}))
	targets := candidateTargets(got.Candidates)
	if _, ok := targets["restart_pod"]; ok {
		t.Fatalf("unsafe pod label produced a restart target: %v", targets)
	}
	if targets["drain_postgres_connections"] != "payments-api" {
		t.Fatalf("valid candidates should survive: %v", targets)
	}
}

func TestNoHardcodedDemoTargets(t *testing.T) {
	for _, rule := range correlation.DefaultRules() {
		for _, template := range rule.Remediations {
			for _, banned := range []string{"payments-api", "demo:", "nginx"} {
				if strings.Contains(template.TargetFormat, banned) {
					t.Fatalf("rule %s hardcodes target %q", rule.ID, template.TargetFormat)
				}
			}
		}
	}
}

// Recorded from a live run: with the PostgreSQL scenario active, a config
// rollout alert saw its 5xx-ratio probe corroborate (the outage does return
// 5xx) and a latency alert saw p95 >= 800ms. Impact symptoms must not count as
// independent evidence for the wrong failure mode.
func TestSymptomProbesDoNotCountAsIndependentSources(t *testing.T) {
	queriers, _ := backends("payments-api", map[string]answer{
		"config_service_error_ratio": {value: 1},
		"config_parse_error_logs":    {noData: true},
		"service_p95_latency":        {value: 0.99},
		"dependency_latency_logs":    {noData: true},
	})
	svc := newTestService(queriers)
	for _, name := range []string{"PaymentsAPIBadConfigRollout", "PaymentsAPIDependencyLatency"} {
		got := run(svc, incidentFor("payments-api"), alert(name, "payments-api", nil))
		if len(got.Score.Sources) != 1 || got.Confidence > SourceCap(1) {
			t.Fatalf("%s: symptom lifted confidence to %.2f from %v", name, got.Confidence, got.Score.Sources)
		}
		if got.Score.Corroborated == 0 {
			t.Fatalf("%s: symptom weight should still be recorded", name)
		}
		if !strings.Contains(strings.Join(got.Factors, "\n"), "(symptom) corroborated") {
			t.Fatalf("%s: factors do not label the symptom: %v", name, got.Factors)
		}
		for _, item := range got.Items {
			if item.Kind == "probe" && item.Status == "corroborated" && !item.Symptom {
				t.Fatalf("%s: corroborated item not marked as symptom: %+v", name, item)
			}
		}
	}
}
