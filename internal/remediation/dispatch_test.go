package remediation

import (
	"context"
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
