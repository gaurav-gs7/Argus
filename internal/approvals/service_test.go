package approvals

import "testing"

func TestValidateDecisionFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		decision string
		reason   string
		actor    string
	}{
		{name: "unknown decision", decision: "execute", reason: "reviewed", actor: "admin@local"},
		{name: "missing reason", decision: DecisionApprove, actor: "admin@local"},
		{name: "missing identity", decision: DecisionDeny, reason: "unsafe"},
		{name: "system is not human", decision: DecisionApprove, reason: "reviewed", actor: "system"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateDecision(test.decision, test.reason, test.actor); err == nil {
				t.Fatal("expected decision to fail closed")
			}
		})
	}
}

func TestValidateSeparationEnforcesFourEyes(t *testing.T) {
	if err := validateSeparation("operator@local", "operator@local", false); err == nil {
		t.Fatal("expected self-approval to be denied")
	}
	if err := validateSeparation("operator@local", "admin@local", false); err != nil {
		t.Fatalf("different approver should pass: %v", err)
	}
	if err := validateSeparation("operator@local", "operator@local", true); err != nil {
		t.Fatalf("explicit local self-approval override should pass: %v", err)
	}
}
