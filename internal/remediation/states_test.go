package remediation

import "testing"

func TestRemediationStateMachine(t *testing.T) {
	if !CanTransition(StateAwaitingApproval, StateApproved) {
		t.Fatalf("expected awaiting_approval -> approved to be valid")
	}
	if !CanTransition(StateAwaitingApproval, StateTimedOut) {
		t.Fatalf("expected awaiting_approval -> timed_out to be valid")
	}
	if CanTransition(StatePolicyBlocked, StateQueued) {
		t.Fatalf("policy_blocked must not transition to queued")
	}
	if !IsTerminalState(StateSucceeded) || !IsTerminalState(StatePolicyBlocked) {
		t.Fatalf("expected succeeded and policy_blocked to be terminal")
	}
}

func TestRequireTransitionRejectsInvalidMoves(t *testing.T) {
	for _, ok := range [][2]string{{StateApproved, StateQueued}, {StateQueued, StateRunning}, {StateRunning, StateTimedOut}, {StateQueued, StateQueued}} {
		if err := RequireTransition(ok[0], ok[1]); err != nil {
			t.Fatalf("%s -> %s: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range [][2]string{{StateSucceeded, StateQueued}, {StateCancelled, StateRunning}, {StateRunning, StateQueued}, {StateAwaitingApproval, StateQueued}} {
		if err := RequireTransition(bad[0], bad[1]); err == nil {
			t.Fatalf("%s -> %s was allowed", bad[0], bad[1])
		}
	}
}

func TestFirstNonEmptyRiskDefaultsToMedium(t *testing.T) {
	if firstNonEmptyRisk("", "high") != "high" || firstNonEmptyRisk("low", "high") != "low" || firstNonEmptyRisk("", "") != "medium" {
		t.Fatal("risk fallback order is wrong")
	}
	if requireApplied(false, nil) != ErrStateChanged || requireApplied(true, nil) != nil {
		t.Fatal("requireApplied")
	}
}
