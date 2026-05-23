package rca

import (
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

func TestBuildDeterministicRCAForPostgresExhaustion(t *testing.T) {
	incident := incidents.Incident{
		ID:        "inc_123",
		Title:     "High 5xx on payments-api",
		Service:   "payments-api",
		Severity:  "sev2",
		StartedAt: time.Now().UTC(),
	}
	signals := []incidents.Signal{
		{
			Name:   "PaymentsAPIPostgresConnectionExhaustion",
			Source: "alertmanager",
			Body: map[string]any{
				"message": "postgres connection acquisition timeout",
			},
		},
	}

	summary, hypothesis, confidence, evidence, actions := buildDeterministicRCA(incident, signals)
	if hypothesis != "PostgreSQL connection pool exhaustion" {
		t.Fatalf("unexpected hypothesis: %q", hypothesis)
	}
	if confidence < 0.8 {
		t.Fatalf("expected confidence >= 0.8, got %f", confidence)
	}
	if len(evidence) == 0 || len(actions) == 0 || summary == "" {
		t.Fatalf("expected summary, evidence, and actions to be populated")
	}
}
