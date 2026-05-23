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
