package incidents

import (
	"encoding/json"
	"strings"
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
	// Transitions the code performs must be allowed.
	for _, step := range [][2]string{
		{StatusDetected, StatusTriaged},                     // ack
		{StatusDetected, StatusRCAGenerated},                // RCA on a new incident
		{StatusTriaged, StatusRCAGenerated},                 // RCA after ack
		{StatusRCAGenerated, StatusRemediationProposed},     // proposal without approval
		{StatusRCAGenerated, StatusAwaitingApproval},        // proposal needing approval
		{StatusRemediationProposed, StatusAwaitingApproval}, // later proposal needs approval
		{StatusRCAGenerated, StatusResolved},                // operator resolve
		{StatusAwaitingApproval, StatusResolved},            // resolve after approved work ran
		{StatusRemediating, StatusResolved},
	} {
		if !CanTransition(step[0], step[1]) {
			t.Fatalf("%s -> %s must be allowed", step[0], step[1])
		}
	}
	for _, step := range [][2]string{
		{StatusResolved, StatusDetected},
		{StatusResolved, StatusRCAGenerated},
		{StatusCancelled, StatusTriaged},
		{StatusAwaitingApproval, StatusRCAGenerated},
		{StatusAwaitingApproval, StatusTriaged},
		{StatusRemediationProposed, StatusRCAGenerated},
		{StatusRCAGenerated, StatusTriaged},
	} {
		if CanTransition(step[0], step[1]) {
			t.Fatalf("%s -> %s must be denied", step[0], step[1])
		}
	}
	for _, terminal := range []string{StatusResolved, StatusCancelled} {
		if len(transitions[terminal]) != 0 {
			t.Fatalf("%s must be terminal", terminal)
		}
	}
	if got := AllowedFrom(StatusRCAGenerated); strings.Join(got, ",") != "detected,investigating,triaged" {
		t.Fatalf("AllowedFrom(rca_generated)=%v", got)
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

func TestRelatedOpenIncidentUsesStoredEnvironment(t *testing.T) {
	// The environment used to be parsed out of the dedupe key, which breaks
	// when an alert name contains ':'.
	open := []Incident{{
		ID: "inc_1", Service: "payments-api", Environment: "production",
		DedupeKey: BuildDedupeKey("payments-api", "Latency:p95:High", "production", "fp"),
	}}
	graph := topology.New(nil)
	if got, _ := relatedOpenIncident(graph, "payments-api", "production", open); got == nil || got.ID != "inc_1" {
		t.Fatalf("same-environment incident not matched: %+v", got)
	}
	if got, _ := relatedOpenIncident(graph, "payments-api", "p95", open); got != nil {
		t.Fatalf("matched an incident from another environment: %+v", got)
	}
}
