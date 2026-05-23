package remediation

import "testing"

func TestRemediationStateMachine(t *testing.T) {
	if !CanTransition(StateAwaitingApproval, StateApproved) {
		t.Fatalf("expected awaiting_approval -> approved to be valid")
	}
	if CanTransition(StatePolicyBlocked, StateQueued) {
		t.Fatalf("policy_blocked must not transition to queued")
	}
	if !IsTerminalState(StateSucceeded) || !IsTerminalState(StatePolicyBlocked) {
		t.Fatalf("expected succeeded and policy_blocked to be terminal")
	}
}
