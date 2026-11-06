package remediation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
)

func TestDispatchBackoffDoublesAndCaps(t *testing.T) {
	want := map[int]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 5: 16 * time.Second, 6: 30 * time.Second, 40: 30 * time.Second}
	for attempts, expected := range want {
		if got := dispatchBackoff(attempts); got != expected {
			t.Fatalf("dispatchBackoff(%d)=%s want %s", attempts, got, expected)
		}
	}
}

func TestNewDispatcherFillsDefaults(t *testing.T) {
	d := NewDispatcher(nil, nil, nil, nil, nil, DispatcherConfig{MaxRedispatches: 7})
	def := DefaultDispatcherConfig()
	if d.cfg.MaxRedispatches != 7 || d.cfg.PollInterval != def.PollInterval || d.cfg.RedispatchAfter != def.RedispatchAfter ||
		d.cfg.BatchSize != def.BatchSize || d.cfg.PublishTimeout != def.PublishTimeout || d.cfg.ReconcileInterval != def.ReconcileInterval ||
		d.cfg.RunningStaleAfter != def.RunningStaleAfter || d.cfg.WorkerLiveWindow != def.WorkerLiveWindow || d.logger == nil {
		t.Fatalf("cfg=%+v", d.cfg)
	}
}

func TestJobCarriesTheWorkerContract(t *testing.T) {
	queuedAt := time.Unix(1700000000, 42)
	rem := incidents.RemediationAction{ID: "rem_1", IncidentID: "inc_1", IdempotencyKey: "key", DryRun: true, QueuedAt: &queuedAt}
	id := reservationEventID(rem)
	if id != "key@1700000000000000042" {
		t.Fatalf("reservation id=%s", id)
	}
	event := Job(rem, id)
	if event.EventID != id || event.EventType != queue.RemediationSubject || event.IdempotencyKey != "key" ||
		event.Payload["remediation_id"] != "rem_1" || event.Payload["incident_id"] != "inc_1" || event.Payload["dry_run"] != true {
		t.Fatalf("event=%+v", event)
	}
}

func TestOnlyTheLocalExecutorUsesTheOutbox(t *testing.T) {
	local := NewLocalExecutor()
	if !isQueued(local) || isQueued(NewHeliosExecutor("http://helios", "token", time.Second)) {
		t.Fatal("outbox routing is wrong")
	}
	if _, err := local.Execute(context.Background(), incidents.RemediationAction{}, incidents.Incident{}, false); err == nil {
		t.Fatal("the local executor must not be called directly")
	}
	s := NewService(nil, nil, nil, nil, nil, nil, nil)
	if s.Dispatcher() != nil {
		t.Fatal("a dispatcher without a queue client")
	}
	d := NewDispatcher(nil, nil, nil, nil, nil, DispatcherConfig{})
	s.UseDispatcher(d)
	if s.Dispatcher() != d {
		t.Fatal("UseDispatcher")
	}
}

// Run returns promptly when its context ends.
func TestDispatcherRunStops(t *testing.T) {
	d := NewDispatcher(nil, nil, nil, nil, nil, DispatcherConfig{PollInterval: time.Hour, ReconcileInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestOnlyQueuedAndRunningRemediationsAreDispatchable(t *testing.T) {
	for state, want := range map[string]bool{
		StateQueued: true, StateRunning: true, StateApproved: false, StateCancelled: false,
		StateSucceeded: false, StateFailed: false, StateTimedOut: false, StateAwaitingApproval: false,
	} {
		if Dispatchable(state) != want {
			t.Fatalf("Dispatchable(%s) != %v", state, want)
		}
	}
}

func TestHeliosReconcileConfigDefaults(t *testing.T) {
	got := HeliosReconcileConfig{MaxRuntime: time.Hour}.withDefaults()
	def := DefaultHeliosReconcileConfig()
	if got.MaxRuntime != time.Hour || got.Interval != def.Interval || got.SubmitLostAfter != def.SubmitLostAfter {
		t.Fatalf("cfg=%+v", got)
	}
}

// The reconciler finds a lost submission by its Argus labels among Helios's
// newest workflows, and cancels overdue ones; Helios errors surface.
func TestHeliosLookupAndCancel(t *testing.T) {
	var cancelled []string
	executor := NewHeliosExecutor("http://helios.local", "admin-token", time.Second)
	executor.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			return jsonResponse(http.StatusUnauthorized, map[string]string{"error": "unauthorized"}), nil
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workflows" && r.URL.Query().Get("limit") == "500":
			return jsonResponse(http.StatusOK, map[string]any{"workflows": []map[string]any{
				{"workflow_id": "wf_9", "state": "running", "labels": map[string]string{"source": "someone-else", "remediation_id": "rem_1"}},
				{"workflow_id": "wf_8", "state": "succeeded", "labels": map[string]string{"source": "argus", "remediation_id": "rem_1"}},
				{"workflow_id": "wf_7", "state": "failed", "labels": map[string]string{"source": "argus", "remediation_id": "rem_1"}},
			}}), nil
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/workflows/"), "/cancel")
			if id == "wf_missing" {
				return jsonResponse(http.StatusInternalServerError, map[string]string{"error": "no such workflow"}), nil
			}
			cancelled = append(cancelled, id)
			return jsonResponse(http.StatusAccepted, map[string]string{"status": "cancelled"}), nil
		}
		return nil, fmt.Errorf("unexpected %s %s", r.Method, r.URL)
	})}
	ctx := context.Background()
	found, err := executor.findWorkflow(ctx, "rem_1")
	if err != nil || found == nil || found.WorkflowID != "wf_8" || found.State != "succeeded" {
		t.Fatalf("found=%+v err=%v (want the newest Argus-labelled workflow)", found, err)
	}
	if none, err := executor.findWorkflow(ctx, "rem_2"); err != nil || none != nil {
		t.Fatalf("unknown remediation: %+v %v", none, err)
	}
	if err := executor.cancelWorkflow(ctx, "wf_8"); err != nil || len(cancelled) != 1 {
		t.Fatalf("cancel: %v %v", err, cancelled)
	}
	if err := executor.cancelWorkflow(ctx, "wf_missing"); err == nil {
		t.Fatal("a failed cancel was reported as success")
	}
	executor.adminToken = "wrong"
	if _, err := executor.findWorkflow(ctx, "rem_1"); err == nil {
		t.Fatal("an unauthorized list was reported as success")
	}
}

// Reconciling Helios is a no-op for other executors.
func TestReconcileHeliosIgnoresOtherExecutors(t *testing.T) {
	s := NewService(nil, nil, nil, nil, NewLocalExecutor(), nil, nil)
	if result, err := s.ReconcileHelios(context.Background(), HeliosReconcileConfig{}); err != nil || len(result.Errors) != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	s.RunHeliosReconciler(context.Background(), HeliosReconcileConfig{}, nil) // returns at once
}
