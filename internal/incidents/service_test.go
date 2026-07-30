package incidents

import (
	"encoding/json"
	"testing"

	"github.com/gauravgs7/argus/internal/topology"
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

func TestTopologyGroupingNeverCrossesEnvironments(t *testing.T) {
	graph := topology.New([]topology.Dependency{
		{Service: "payments-api", DependsOn: "postgres"},
	})
	alerts := []normalizedAlert{
		{service: "payments-api", environment: "production"},
		{service: "postgres", environment: "production"},
		{service: "payments-api", environment: "staging"},
		{service: "postgres", environment: "staging"},
	}

	groups := topologyGroupsByEnvironment(graph, alerts)
	if len(groups) != 2 {
		t.Fatalf("mixed environments produced %d groups, want 2", len(groups))
	}
	if groups[0].Environment != "production" || groups[1].Environment != "staging" {
		t.Fatalf("groups are not environment isolated and sorted: %#v", groups)
	}
	for _, group := range groups {
		items := alertsForGroup(alerts, group)
		if len(items) != 2 {
			t.Fatalf("group %s included %d alerts, want 2", group.Environment, len(items))
		}
		for _, item := range items {
			if item.environment != group.Environment {
				t.Fatalf("group %s leaked alert from %s", group.Environment, item.environment)
			}
		}
	}
}

func TestIncidentEnvironmentUsesDedupeKey(t *testing.T) {
	incident := Incident{DedupeKey: BuildDedupeKey("payments-api", "High5xx", "production", "fp")}
	if got := incidentEnvironment(incident); got != "production" {
		t.Fatalf("incident environment=%q, want production", got)
	}
}
