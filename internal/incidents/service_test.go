package incidents

import (
	"encoding/json"
	"testing"
)

func TestBuildDedupeKey(t *testing.T) {
	got := BuildDedupeKey("payments-api", "High5xx", "local", "abc123")
	want := "payments-api:High5xx:local:abc123"
	if got != want {
		t.Fatalf("BuildDedupeKey() = %q, want %q", got, want)
	}
}

func TestCanTransition(t *testing.T) {
	if !CanTransition(StatusDetected, StatusTriaged) {
		t.Fatalf("expected detected -> triaged to be allowed")
	}
	if CanTransition(StatusResolved, StatusDetected) {
		t.Fatalf("expected resolved -> detected to be disallowed")
	}
}

func TestAlertmanagerWebhookParsing(t *testing.T) {
	raw := []byte(`{
		"status": "firing",
		"receiver": "argus",
		"alerts": [
			{
				"status": "firing",
				"labels": {
					"alertname": "PaymentsAPIHighErrorRate",
					"service": "payments-api",
					"severity": "sev2"
				},
				"annotations": {
					"summary": "High 5xx rate on payments-api"
				},
				"startsAt": "2026-04-25T10:15:00Z",
				"fingerprint": "fp-123"
			}
		]
	}`)

	var payload AlertmanagerWebhook
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unexpected error parsing payload: %v", err)
	}
	if len(payload.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(payload.Alerts))
	}
	if payload.Alerts[0].Labels["service"] != "payments-api" {
		t.Fatalf("unexpected service label: %q", payload.Alerts[0].Labels["service"])
	}
}
