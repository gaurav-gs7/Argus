package policy

import "testing"

func TestEvaluateMediumRiskRequiresApproval(t *testing.T) {
	engine := NewEngine()
	var input Input
	input.Actor.Role = "operator"
	input.Incident.Environment = "local"
	input.Remediation.Type = "restart_service"
	input.Remediation.Risk = "medium"

	decision := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("expected medium risk restart_service to be allowed")
	}
	if !decision.RequiresApproval {
		t.Fatalf("expected medium risk action to require approval")
	}
}

func TestEvaluateBlocksHighRisk(t *testing.T) {
	engine := NewEngine()
	var input Input
	input.Incident.Environment = "local"
	input.Remediation.Type = "terminate_all_connections"
	input.Remediation.Risk = "high"

	decision := engine.Evaluate(input)
	if decision.Allow {
		t.Fatalf("expected high risk action to be blocked")
	}
}

func TestEvaluateCircuitBreaker(t *testing.T) {
	engine := NewEngine()
	var input Input
	input.Actor.Role = "operator"
	input.Incident.Environment = "local"
	input.Remediation.Type = "restart_service"
	input.Remediation.Risk = "medium"
	input.History.FailedAttempts = 2

	decision := engine.Evaluate(input)
	if decision.Allow {
		t.Fatalf("expected repeated failures to trip circuit breaker")
	}
}

func TestEvaluateRestrictsRedisTarget(t *testing.T) {
	engine := NewEngine()
	var input Input
	input.Actor.Role = "operator"
	input.Incident.Environment = "local"
	input.Remediation.Type = "clear_redis_keyspace"
	input.Remediation.Risk = "medium"
	input.Remediation.Target = "*"

	decision := engine.Evaluate(input)
	if decision.Allow {
		t.Fatalf("expected broad redis keyspace target to be blocked")
	}
}

func TestEvaluateTypedActionBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		target     string
		parameters map[string]any
		allow      bool
	}{
		{"pod", "restart_pod", "local/payments-api", nil, true},
		{"production pod", "restart_pod", "production/payments-api", nil, false},
		{"pool", "resize_connection_pool", "payments-api", map[string]any{"size": 20}, true},
		{"oversized pool", "resize_connection_pool", "payments-api", map[string]any{"size": 51}, false},
		{"flag", "toggle_feature_flag", "payments-api/optional-notifications", map[string]any{"enabled": false}, true},
		{"unknown flag", "toggle_feature_flag", "payments-api/auth", map[string]any{"enabled": false}, false},
		{"cache", "purge_cache", "demo:pressure:*", map[string]any{"max_keys": 500}, true},
		{"broad cache", "purge_cache", "demo:*", map[string]any{"max_keys": 500}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := NewEngine()
			var input Input
			input.Actor.Role = "operator"
			input.Incident.Environment = "local"
			input.Remediation.Type = test.action
			input.Remediation.Target = test.target
			input.Remediation.Parameters = test.parameters
			input.Remediation.Risk = "medium"
			decision := engine.Evaluate(input)
			if decision.Allow != test.allow {
				t.Fatalf("Evaluate() allow=%t reason=%q, want %t", decision.Allow, decision.Reason, test.allow)
			}
			if decision.Allow && !decision.RequiresApproval {
				t.Fatal("medium-risk typed action did not require approval")
			}
		})
	}
}

func mediumRestart() Input {
	var input Input
	input.Actor.Role = "operator"
	input.Incident.Environment = "local"
	input.Remediation.Type = "restart_service"
	input.Remediation.Risk = "medium"
	return input
}

func TestEvaluateDeniesMissingRole(t *testing.T) {
	input := mediumRestart()
	input.Actor.Role = ""
	if decision := NewEngine().Evaluate(input); decision.Allow || decision.Reason != "Actor role is missing" {
		t.Fatalf("missing role was not denied: %+v", decision)
	}
}

func TestEvaluateUsesIncidentEnvironment(t *testing.T) {
	input := mediumRestart()
	input.Incident.Environment = "production"
	if decision := NewEngine().Evaluate(input); decision.Allow {
		t.Fatalf("production remediation allowed by the default engine: %+v", decision)
	}
	if decision := NewEngineForEnvironments([]string{" local", "production "}).Evaluate(input); !decision.Allow || !decision.RequiresApproval {
		t.Fatalf("explicitly enabled environment was denied: %+v", decision)
	}
	input.Incident.Environment = ""
	if decision := NewEngine().Evaluate(input); decision.Allow {
		t.Fatalf("empty environment allowed: %+v", decision)
	}
}

func TestEvaluateRiskComesFromCatalog(t *testing.T) {
	input := mediumRestart()
	input.Remediation.Type = "restart_pod"
	input.Remediation.Target = "local/payments-api"
	input.Remediation.Risk = "low" // proposal tries to skip approval
	decision := NewEngine().Evaluate(input)
	if !decision.Allow || !decision.RequiresApproval || decision.Risk != "medium" {
		t.Fatalf("catalog risk not enforced: %+v", decision)
	}

	input.Remediation.Risk = ""
	if decision := NewEngine().Evaluate(input); decision.Risk != "medium" || !decision.RequiresApproval {
		t.Fatalf("empty requested risk should use the catalog: %+v", decision)
	}
	input.Remediation.Risk = "high"
	if decision := NewEngine().Evaluate(input); decision.Allow {
		t.Fatalf("a proposal may raise risk to high and must then be blocked: %+v", decision)
	}
	input.Remediation.Risk = "spicy"
	if decision := NewEngine().Evaluate(input); decision.Allow {
		t.Fatalf("unknown risk allowed: %+v", decision)
	}
}
