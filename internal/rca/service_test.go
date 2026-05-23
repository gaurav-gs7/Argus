package rca

import (
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

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
