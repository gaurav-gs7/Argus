package remediation

import "fmt"

const (
	StateProposed         = "proposed"
	StatePolicyBlocked    = "policy_blocked"
	StateAwaitingApproval = "awaiting_approval"
	StateApproved         = "approved"
	StateRejected         = "rejected"
	StateQueued           = "queued"
	StateRunning          = "running"
	StateSucceeded        = "succeeded"
	StateFailed           = "failed"
	StateTimedOut         = "timed_out"
	StateCancelled        = "cancelled"
)

func IsTerminalState(state string) bool {
	switch state {
	case StatePolicyBlocked, StateRejected, StateSucceeded, StateFailed, StateTimedOut, StateCancelled:
		return true
	default:
		return false
	}
}

func CanTransition(from, to string) bool {
	if from == to {
		return true
	}
	allowed := map[string]map[string]bool{
		StateProposed: {
			StatePolicyBlocked:    true,
			StateAwaitingApproval: true,
			StateApproved:         true,
			StateCancelled:        true,
		},
		StateAwaitingApproval: {
			StateApproved:  true,
			StateRejected:  true,
			StateCancelled: true,
		},
		StateApproved: {
			StateQueued:    true,
			StateCancelled: true,
		},
		StateQueued: {
			StateRunning:   true,
			StateSucceeded: true,
			StateFailed:    true,
			StateTimedOut:  true,
			StateCancelled: true,
		},
		StateRunning: {
			StateSucceeded: true,
			StateFailed:    true,
			StateTimedOut:  true,
		},
		StateFailed: {
			StateApproved: true,
		},
	}
	return allowed[from][to]
}

func RequireTransition(from, to string) error {
	if CanTransition(from, to) {
		return nil
	}
	return fmt.Errorf("invalid remediation transition %s -> %s", from, to)
}
