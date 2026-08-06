package rca

import (
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/topology"
)

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

func TestBuildDeterministicRCAForPostgresExhaustion(t *testing.T) {
	incident := incidents.Incident{ID: "inc_123", Title: "High 5xx on payments-api", Service: "payments-api", Severity: "sev2", StartedAt: time.Now().UTC()}
	signals := []incidents.Signal{{
		Name: "PaymentsAPIPostgresConnectionExhaustion", Source: "alertmanager", SignalType: "alert",
		Body: map[string]any{"message": "postgres connection acquisition timeout"}, ObservedAt: incident.StartedAt,
	}}

	summary, hypothesis, confidence, evidence, factors, actions := buildDeterministicRCA(incident, signals)
	if hypothesis != "PostgreSQL connection pool exhaustion" {
		t.Fatalf("unexpected hypothesis: %q", hypothesis)
	}
	if confidence < 0.75 {
		t.Fatalf("expected confidence >= 0.75, got %f", confidence)
	}
	if len(evidence) < 2 || len(factors) == 0 || len(actions) == 0 || summary == "" {
		t.Fatalf("expected summary, evidence, factors, and actions to be populated")
	}
}

func TestDeterministicRCAScenarioScores(t *testing.T) {
	tests := []struct {
		name       string
		alertName  string
		message    string
		hypothesis string
		confidence float64
	}{
		{"postgres", "PaymentsAPIPostgresConnectionExhaustion", "postgres connection acquisition timeout", "PostgreSQL connection pool exhaustion", 0.95},
		{"redis", "PaymentsAPIRedisMemoryPressure", "redis memory pressure", "Redis memory pressure causing cache degradation", 0.797},
		{"nginx", "Nginx5xxSpike", "nginx elevated 5xx", "Nginx upstream misconfiguration or bad route rollout", 0.769},
		{"dependency", "PaymentsAPIDependencyLatency", "notification latency", "Downstream dependency latency dominates the request path", 0.7406},
		{"config", "PaymentsAPIBadConfigRollout", "bad config rollout", "Bad config rollout introduced an invalid runtime configuration", 0.8795},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incident := incidents.Incident{Title: tt.alertName, Service: "payments-api", StartedAt: time.Unix(0, 0).UTC()}
			signals := []incidents.Signal{{
				Name: tt.alertName, Source: "alertmanager", SignalType: "alert",
				Body: map[string]any{"message": tt.message}, ObservedAt: incident.StartedAt,
			}}

			summary, hypothesis, confidence, _, factors, _ := buildDeterministicRCA(incident, signals)
			if hypothesis != tt.hypothesis {
				t.Fatalf("hypothesis=%q, want %q", hypothesis, tt.hypothesis)
			}
			if math.Abs(confidence-tt.confidence) > 0.000001 {
				t.Fatalf("confidence=%v, want %v", confidence, tt.confidence)
			}
			if !strings.Contains(summary, "0.35 baseline") || len(factors) == 0 || !strings.Contains(factors[0], " x weight ") {
				t.Fatalf("score arithmetic is not inspectable: summary=%q factors=%#v", summary, factors)
			}
			t.Logf("hypothesis=%q confidence=%.4f", hypothesis, confidence)
		})
	}
}

func TestDeterministicRCAReplayStable(t *testing.T) {
	incident := incidents.Incident{
		ID: "inc_replay", Title: "PostgreSQL alert", Service: "payments-api",
		Severity: "sev2", StartedAt: time.Unix(0, 0).UTC(),
	}
	signals := []incidents.Signal{{
		Name: "PaymentsAPIPostgresConnectionExhaustion", Source: "alertmanager", SignalType: "alert",
		Body: map[string]any{"message": "postgres connection acquisition timeout"}, ObservedAt: incident.StartedAt,
	}}
	type output struct {
		Summary    string
		Hypothesis string
		Confidence float64
		Evidence   []string
		Factors    []string
		Candidates []Candidate
	}
	run := func() output {
		summary, hypothesis, confidence, evidence, factors, candidates := buildDeterministicRCA(incident, signals)
		return output{summary, hypothesis, confidence, evidence, factors, candidates}
	}

	want := run()
	for i := 0; i < 100; i++ {
		if got := run(); !reflect.DeepEqual(got, want) {
			t.Fatalf("replay %d changed deterministic output:\ngot:  %#v\nwant: %#v", i+1, got, want)
		}
	}
	t.Logf("100/100 replays identical; hypothesis=%q confidence=%.4f", want.Hypothesis, want.Confidence)
}

func TestBestHypothesisBreaksEqualScoresLexically(t *testing.T) {
	items := map[correlation.RuleID]*scoredHypothesis{
		"z_rule": {Name: "Zulu failure", Score: 0.4},
		"a_rule": {Name: "Alpha failure", Score: 0.4},
	}

	for i := 0; i < 100; i++ {
		if got := bestHypothesis(items); got == nil || got.Name != "Alpha failure" {
			t.Fatalf("equal-score winner=%#v, want lexical Alpha failure", got)
		}
	}
}

func TestBuildDeterministicRCAFallsBackToDiagnostics(t *testing.T) {
	incident := incidents.Incident{ID: "inc_123", Title: "Unknown issue", Service: "payments-api", Severity: "sev3", StartedAt: time.Now().UTC()}
	signals := []incidents.Signal{{Name: "UnknownAlert", Source: "manual", SignalType: "alert", Body: map[string]any{"message": "unknown"}, ObservedAt: incident.StartedAt}}

	_, hypothesis, confidence, _, _, actions := buildDeterministicRCA(incident, signals)
	if hypothesis != "Insufficient evidence for a high-confidence root cause" {
		t.Fatalf("unexpected fallback hypothesis: %q", hypothesis)
	}
	if confidence >= 0.6 {
		t.Fatalf("expected low confidence fallback, got %f", confidence)
	}
	if len(actions) != 1 || actions[0].ActionType != "collect_diagnostics" || actions[0].Risk != "low" {
		t.Fatalf("expected low-risk diagnostics fallback, got %+v", actions)
	}
}

func TestEnrichWithObservedTopologyRaisesConfidenceAndExplainsBlastRadius(t *testing.T) {
	summary, confidence, evidence, factors := enrichWithTopology(
		"Database evidence matched.",
		0.81,
		[]string{"connection pool saturated"},
		nil,
		incidents.IncidentTopology{
			RootService:          "postgres",
			AffectedServices:     []string{"checkout-api", "nginx", "payments-api", "postgres"},
			AlertCount:           20,
			SuppressedAlertCount: 18,
			Paths: []topology.Path{{
				From:     "nginx",
				To:       "postgres",
				Services: []string{"nginx", "payments-api", "postgres"},
			}},
		},
	)
	if math.Abs(confidence-0.84) > 0.000001 {
		t.Fatalf("confidence=%v, want 0.84", confidence)
	}
	if !strings.Contains(summary, "observed root service postgres") || !strings.Contains(summary, "suppressed 18 downstream alerts") {
		t.Fatalf("topology summary missing root or suppression context: %q", summary)
	}
	if len(evidence) != 3 || len(factors) != 1 {
		t.Fatalf("expected topology evidence and dependency path, got evidence=%#v factors=%#v", evidence, factors)
	}
}

func TestEnrichWithInferredTopologyDoesNotInflateConfidence(t *testing.T) {
	_, confidence, _, _ := enrichWithTopology(
		"Dependency evidence matched.",
		0.72,
		nil,
		nil,
		incidents.IncidentTopology{
			RootService:          "payments-api",
			RootInferred:         true,
			AffectedServices:     []string{"checkout-api", "nginx"},
			AlertCount:           2,
			SuppressedAlertCount: 2,
		},
	)
	if confidence != 0.72 {
		t.Fatalf("inferred root must not increase confidence: got %v", confidence)
	}
}

func TestTopologyFallbackNamesFailureDomainWithoutInventingFailureMode(t *testing.T) {
	incident := incidents.Incident{Title: "Downstream request failures"}
	analysis := incidents.IncidentTopology{
		RootService:          "postgres",
		AffectedServices:     []string{"checkout-api", "payments-api", "postgres"},
		AlertCount:           12,
		SuppressedAlertCount: 10,
	}
	summary, hypothesis, confidence, evidence, factors, candidates := applyTopologyFallback(
		incident,
		analysis,
		"insufficient",
		"Insufficient evidence for a high-confidence root cause",
		0.35,
		nil,
		nil,
		nil,
	)
	if hypothesis != "Failure at root dependency postgres" {
		t.Fatalf("unexpected topology hypothesis: %q", hypothesis)
	}
	if strings.Contains(strings.ToLower(hypothesis), "connection pool") || strings.Contains(strings.ToLower(summary), "connection pool") {
		t.Fatalf("topology fallback invented an unsupported failure mode: hypothesis=%q summary=%q", hypothesis, summary)
	}
	if confidence != 0.72 || len(evidence) != 2 || len(factors) != 1 {
		t.Fatalf("unexpected bounded topology score: confidence=%v evidence=%#v factors=%#v", confidence, evidence, factors)
	}
	if len(candidates) != 1 || candidates[0].ActionType != "collect_diagnostics" ||
		candidates[0].Target != "postgres" || candidates[0].Risk != "low" {
		t.Fatalf("topology-only evidence must produce diagnostics-only action: %#v", candidates)
	}
}

func TestInferredTopologyFallbackUsesLowerConfidence(t *testing.T) {
	_, _, confidence, _, _, _ := applyTopologyFallback(
		incidents.Incident{Title: "Sibling service failures"},
		incidents.IncidentTopology{
			RootService:          "payments-api",
			RootInferred:         true,
			AffectedServices:     []string{"checkout-api", "nginx"},
			AlertCount:           2,
			SuppressedAlertCount: 2,
		},
		"",
		"Insufficient evidence for a high-confidence root cause",
		0.35,
		nil,
		nil,
		nil,
	)
	if confidence != 0.58 {
		t.Fatalf("inferred topology confidence=%v, want 0.58", confidence)
	}
}
