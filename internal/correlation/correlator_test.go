package correlation

import (
	"strings"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/evidence"
	"github.com/gauravgs7/argus/internal/incidents"
)

func alertSignal(name string, labels map[string]any, annotations map[string]any) incidents.Signal {
	body := map[string]any{"labels": labels}
	if annotations != nil {
		body["annotations"] = annotations
	}
	return incidents.Signal{ID: "sig_" + name, Name: name, Source: "alertmanager", SignalType: "alert", Body: body}
}

func TestDefaultRulesAreValid(t *testing.T) {
	if err := ValidateRules(DefaultRules()); err != nil {
		t.Fatalf("compiled rule table is invalid: %v", err)
	}
	for _, rule := range DefaultRules() {
		backends := map[evidence.Backend]bool{}
		for _, probe := range rule.Probes {
			backends[probe.Backend] = true
		}
		if !backends[evidence.Prometheus] && !backends[evidence.Loki] {
			t.Fatalf("rule %s has no backend probes", rule.ID)
		}
	}
}

func TestMatchUsesExactAlertName(t *testing.T) {
	incident := incidents.Incident{ID: "inc_1", Service: "payments-api", StartedAt: time.Unix(100, 0)}
	matches := New().Match(incident, []incidents.Signal{
		alertSignal("PaymentsAPIPostgresPoolSaturation", map[string]any{"service": "payments-api"}, nil),
	})
	if len(matches) != 1 || matches[0].RuleID != RulePostgresConnectionExhaustion {
		t.Fatalf("matches=%+v", matches)
	}
	if matches[0].Reason != "alertname PaymentsAPIPostgresPoolSaturation" || matches[0].Service != "payments-api" {
		t.Fatalf("unexpected match detail: %+v", matches[0])
	}
	if !matches[0].ObservedAt.Equal(incident.StartedAt) {
		t.Fatalf("zero observation time should fall back to incident start")
	}
}

func TestAnnotationTextNeverSelectsARule(t *testing.T) {
	incident := incidents.Incident{ID: "inc_1", Service: "notification-api"}
	traps := []incidents.Signal{
		alertSignal("NodeDiskAlmostFull", map[string]any{"service": "notification-api"},
			map[string]any{"summary": "postgres connection latency after config rollout; redis memory; nginx 5xx"}),
		alertSignal("PaymentsAPIHighErrorRate", map[string]any{"service": "payments-api", "component": "postgres"},
			map[string]any{"description": "connection pool"}),
		alertSignal("paymentsapipostgresconnectionexhaustion", map[string]any{}, nil),
	}
	if matches := New().Match(incident, traps); len(matches) != 0 {
		t.Fatalf("free text or near-miss names selected rules: %+v", matches)
	}
}

func TestFailureModeLabelOverridesAlertName(t *testing.T) {
	incident := incidents.Incident{Service: "orders"}
	matches := New().Match(incident, []incidents.Signal{
		alertSignal("OrdersDBSaturated", map[string]any{FailureModeLabel: "postgres_connection_exhaustion", "service": "orders"}, nil),
		alertSignal("PaymentsAPIRedisMemoryPressure", map[string]any{FailureModeLabel: "bad_config_rollout"}, nil),
		alertSignal("RedisMemoryHigh", map[string]any{FailureModeLabel: "not_a_rule"}, nil),
	})
	if len(matches) != 3 {
		t.Fatalf("matches=%+v", matches)
	}
	want := []RuleID{RulePostgresConnectionExhaustion, RuleBadConfigRollout, RuleRedisMemoryPressure}
	for i, id := range want {
		if matches[i].RuleID != id {
			t.Fatalf("match %d rule=%s want %s", i, matches[i].RuleID, id)
		}
	}
	if !strings.HasPrefix(matches[0].Reason, "label argus_failure_mode=") || matches[2].Reason != "alertname RedisMemoryHigh" {
		t.Fatalf("reasons=%q %q", matches[0].Reason, matches[2].Reason)
	}
}

func TestSignalServiceResolutionOrder(t *testing.T) {
	incident := incidents.Incident{Service: "incident-svc"}
	cases := []struct {
		signal incidents.Signal
		want   string
	}{
		{incidents.Signal{Body: map[string]any{"labels": map[string]string{"service": "label-svc"}, "topology": map[string]any{"observed_service": "topo-svc"}}}, "label-svc"},
		{incidents.Signal{Body: map[string]any{"labels": map[string]any{}, "topology": map[string]any{"observed_service": "topo-svc"}}}, "topo-svc"},
		{incidents.Signal{Body: map[string]any{}}, "incident-svc"},
	}
	for _, tc := range cases {
		if got := SignalService(incident, tc.signal, SignalLabels(tc.signal)); got != tc.want {
			t.Fatalf("service=%q want %q", got, tc.want)
		}
	}
}

func TestSignalLabelsIgnoresNonStringValues(t *testing.T) {
	labels := SignalLabels(incidents.Signal{Body: map[string]any{"labels": map[string]any{"a": "x", "b": 3, "c": nil}}})
	if len(labels) != 1 || labels["a"] != "x" {
		t.Fatalf("labels=%v", labels)
	}
	if len(SignalLabels(incidents.Signal{Body: map[string]any{"labels": "oops"}})) != 0 {
		t.Fatal("malformed labels should be ignored")
	}
}

func TestMatchesAreOrderedByObservationTime(t *testing.T) {
	early := alertSignal("Nginx5xxSpike", map[string]any{"service": "nginx"}, nil)
	early.ObservedAt = time.Unix(10, 0)
	late := alertSignal("PaymentsAPIBadConfigRollout", map[string]any{"service": "payments-api"}, nil)
	late.ObservedAt = time.Unix(20, 0)
	matches := New().Match(incidents.Incident{}, []incidents.Signal{late, early})
	if len(matches) != 2 || matches[0].RuleID != RuleNginxUpstreamConfig {
		t.Fatalf("matches not time ordered: %+v", matches)
	}
}

func TestValidateRulesRejectsBrokenTables(t *testing.T) {
	base := DefaultRules()
	cases := map[string]func([]Rule) []Rule{
		"duplicate id": func(r []Rule) []Rule { r[1].ID = r[0].ID; return r },
		"shared alert": func(r []Rule) []Rule { r[1].AlertNames = append(r[1].AlertNames, r[0].AlertNames[0]); return r },
		"no alerts":    func(r []Rule) []Rule { r[0].AlertNames = nil; return r },
		"no probes":    func(r []Rule) []Rule { r[0].Probes = nil; return r },
		"bad probe":    func(r []Rule) []Rule { r[0].Probes[0].Backend = "tempo"; return r },
		"dup probe":    func(r []Rule) []Rule { r[0].Probes[1].ID = r[0].Probes[0].ID; return r },
		"overweight": func(r []Rule) []Rule {
			r[0].Probes = append(r[0].Probes, r[0].Probes[0])
			r[0].Probes[len(r[0].Probes)-1].ID = "extra"
			return r
		},
		"no hypothesis": func(r []Rule) []Rule { r[0].Hypothesis = ""; return r },
		"symptoms only": func(r []Rule) []Rule {
			for i := range r[0].Probes {
				r[0].Probes[i].Symptom = true
			}
			return r
		},
		"unknown action": func(r []Rule) []Rule {
			r[0].Remediations = []CandidateTemplate{{ActionType: "rm_rf", Risk: "low"}}
			return r
		},
		"unknown risk": func(r []Rule) []Rule {
			r[0].Remediations = []CandidateTemplate{{ActionType: "rollback_config", Risk: "spicy"}}
			return r
		},
		"bad format": func(r []Rule) []Rule {
			r[0].Remediations = []CandidateTemplate{{ActionType: "restart_pod", TargetLabel: "pod", TargetFormat: "local/%s/%s", Risk: "medium"}}
			return r
		},
	}
	for name, mutate := range cases {
		rules := make([]Rule, len(base))
		for i, rule := range base {
			rule.AlertNames = append([]string(nil), rule.AlertNames...)
			rule.Probes = append([]evidence.Probe(nil), rule.Probes...)
			rules[i] = rule
		}
		if err := ValidateRules(mutate(rules)); err == nil {
			t.Fatalf("%s: broken rule table accepted", name)
		}
		if _, err := NewWithRules(mutate(rules)); err == nil {
			t.Fatalf("%s: NewWithRules accepted a broken table", name)
		}
	}
}

// A candidate's target comes from the alert, and is refused when the alert
// does not carry a safe one.
func TestCandidateTemplateRender(t *testing.T) {
	if len(New().Rules()) == 0 {
		t.Fatal("no rules")
	}
	pod := CandidateTemplate{ActionType: "restart_pod", TargetLabel: "pod", FallbackToService: true, TargetFormat: "local/%s"}
	if target, _, reason := pod.Render("payments-api", map[string]string{"pod": "payments-api-0"}); target != "local/payments-api-0" || reason != "" {
		t.Fatalf("pod label: %q %q", target, reason)
	}
	if target, _, reason := pod.Render("payments-api", nil); target != "local/payments-api" || reason != "" {
		t.Fatalf("service fallback: %q %q", target, reason)
	}
	strict := CandidateTemplate{ActionType: "purge_cache", TargetLabel: "cache_key_pattern", Parameters: map[string]any{"max_keys": 500}}
	if target, _, reason := strict.Render("payments-api", nil); target != "" || reason == "" {
		t.Fatalf("missing label must not derive a target: %q %q", target, reason)
	}
	if target, _, reason := strict.Render("payments-api", map[string]string{"cache_key_pattern": "*"}); target != "" || reason == "" {
		t.Fatalf("an unbounded cache pattern was accepted: %q %q", target, reason)
	}
	params := map[string]any{"max_keys": 500}
	target, got, reason := strict.Render("svc", map[string]string{"cache_key_pattern": "demo:pressure:*"})
	if reason != "" || target == "" || got["max_keys"] != params["max_keys"] {
		t.Fatalf("valid cache pattern: %q %v %q", target, got, reason)
	}
}
