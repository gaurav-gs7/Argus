package workers

import (
	"context"
	"sync"
	"testing"

	"github.com/gauravgs7/argus/internal/actions"
	"github.com/gauravgs7/argus/internal/incidents"
)

func TestTypedHandlersDryRunExecuteAndReplay(t *testing.T) {
	state := newMemoryControlState()
	tests := []struct {
		name       string
		handler    Handler
		action     string
		target     string
		parameters map[string]any
	}{
		{"pod restart", NewPodRestartHandler(state), actions.RestartPod, "local/payments-api", nil},
		{"pool resize", NewConnectionPoolResizeHandler(state), actions.ResizeConnectionPool, "payments-api", map[string]any{"size": 20}},
		{"feature flag", NewFeatureFlagToggleHandler(state), actions.ToggleFeatureFlag, "payments-api/optional-notifications", map[string]any{"enabled": false}},
		{"cache purge", NewCachePurgeHandler(state), actions.PurgeCache, "demo:pressure:*", map[string]any{"max_keys": 500}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := incidents.RemediationAction{
				ActionType:     test.action,
				Target:         test.target,
				Parameters:     test.parameters,
				IdempotencyKey: "idem-" + test.action,
			}
			preview, err := test.handler.DryRun(context.Background(), req)
			if err != nil {
				t.Fatalf("DryRun() error: %v", err)
			}
			if preview["mode"] != "dry-run" || state.applyCount(req.IdempotencyKey) != 0 {
				t.Fatalf("dry-run mutated state: result=%#v applies=%d", preview, state.applyCount(req.IdempotencyKey))
			}

			first, err := test.handler.Execute(context.Background(), req)
			if err != nil {
				t.Fatalf("Execute() error: %v", err)
			}
			second, err := test.handler.Execute(context.Background(), req)
			if err != nil {
				t.Fatalf("replayed Execute() error: %v", err)
			}
			if first["reused"] != false || second["reused"] != true {
				t.Fatalf("unexpected idempotency results: first=%#v second=%#v", first, second)
			}
			if state.applyCount(req.IdempotencyKey) != 1 {
				t.Fatalf("side effect applied %d times, want 1", state.applyCount(req.IdempotencyKey))
			}
		})
	}
}

func TestTypedHandlersRejectUnsafeInputs(t *testing.T) {
	state := newMemoryControlState()
	tests := []struct {
		name    string
		handler Handler
		req     incidents.RemediationAction
	}{
		{"missing key", NewPodRestartHandler(state), incidents.RemediationAction{ActionType: actions.RestartPod, Target: "local/payments-api"}},
		{"wrong namespace", NewPodRestartHandler(state), incidents.RemediationAction{ActionType: actions.RestartPod, Target: "prod/payments-api", IdempotencyKey: "x"}},
		{"oversized pool", NewConnectionPoolResizeHandler(state), incidents.RemediationAction{ActionType: actions.ResizeConnectionPool, Target: "payments-api", Parameters: map[string]any{"size": 200}, IdempotencyKey: "x"}},
		{"unknown flag", NewFeatureFlagToggleHandler(state), incidents.RemediationAction{ActionType: actions.ToggleFeatureFlag, Target: "payments-api/disable-auth", Parameters: map[string]any{"enabled": false}, IdempotencyKey: "x"}},
		{"broad cache", NewCachePurgeHandler(state), incidents.RemediationAction{ActionType: actions.PurgeCache, Target: "demo:*", Parameters: map[string]any{"max_keys": 500}, IdempotencyKey: "x"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.handler.Execute(context.Background(), test.req); err == nil {
				t.Fatal("Execute() accepted unsafe input")
			}
		})
	}
}

type memoryControlState struct {
	mu       sync.Mutex
	states   map[string]map[string]any
	receipts map[string]map[string]any
	applies  map[string]int
}

func newMemoryControlState() *memoryControlState {
	return &memoryControlState{
		states:   map[string]map[string]any{},
		receipts: map[string]map[string]any{},
		applies:  map[string]int{},
	}
}

func (s *memoryControlState) Preview(_ context.Context, resourceType, target string, desired map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.states[resourceType+"/"+target]
	return stateResult("dry-run", resourceType, target, current, mergeState(current, desired), false), nil
}

func (s *memoryControlState) ApplyOnce(_ context.Context, key, _ string, resourceType, target string, desired map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, ok := s.receipts[key]; ok {
		result := mergeState(receipt, map[string]any{"reused": true})
		return result, nil
	}
	stateKey := resourceType + "/" + target
	current := s.states[stateKey]
	after := mergeState(current, desired)
	result := stateResult("execute", resourceType, target, current, after, false)
	s.states[stateKey] = after
	s.receipts[key] = result
	s.applies[key]++
	return result, nil
}

func (s *memoryControlState) applyCount(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applies[key]
}
