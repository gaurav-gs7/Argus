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
