package correlation

import (
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

func TestCorrelatePostgresEvidence(t *testing.T) {
	incident := incidents.Incident{ID: "inc_1", Service: "payments-api", StartedAt: time.Now().UTC()}
	signals := []incidents.Signal{{
		Name:       "PaymentsAPIPostgresConnectionExhaustion",
		Source:     "alertmanager",
		SignalType: "alert",
		Body:       map[string]any{"message": "postgres connection acquisition timeout"},
		ObservedAt: incident.StartedAt,
	}}

	result := New().Correlate(incident, signals)
	if len(result.Events) < 2 {
		t.Fatalf("expected multiple correlated timeline events, got %d", len(result.Events))
	}
	if result.Evidence[0].Confidence <= 0 || result.Evidence[0].Weight <= 0 {
		t.Fatalf("expected scored evidence, got %+v", result.Evidence[0])
	}
	if result.Evidence[0].RuleID != RulePostgresConnectionExhaustion {
		t.Fatalf("rule id=%q, want %q", result.Evidence[0].RuleID, RulePostgresConnectionExhaustion)
	}
}

func TestCorrelateDeduplicatesRepeatedEvidence(t *testing.T) {
	incident := incidents.Incident{ID: "inc_1", Service: "payments-api", StartedAt: time.Now().UTC()}
	signal := incidents.Signal{
		Name: "PaymentsAPIRedisMemoryPressure", Source: "alertmanager", SignalType: "alert",
		Body: map[string]any{"message": "redis memory pressure"}, ObservedAt: incident.StartedAt,
	}

	result := New().Correlate(incident, []incidents.Signal{signal, signal})
	if len(result.Evidence) != 2 || len(result.Events) != 2 {
		t.Fatalf("duplicate signal inflated evidence: evidence=%d events=%d", len(result.Evidence), len(result.Events))
	}
}
