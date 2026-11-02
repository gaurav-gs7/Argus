package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/nats-io/nats.go"
)

func TestRetryDelayBacksOffAndCaps(t *testing.T) {
	want := map[uint64]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 6: 32 * time.Second, 7: 60 * time.Second, 50: 60 * time.Second}
	for delivery, expected := range want {
		if got := RetryDelay(delivery); got != expected {
			t.Fatalf("RetryDelay(%d)=%s want %s", delivery, RetryDelay(delivery), expected)
		}
	}
}

func TestConfigureKeepsDefaultsForZeroFields(t *testing.T) {
	r := NewRunner(nil, nil, nil, nil)
	r.Configure(RunnerConfig{Concurrency: 8})
	def := DefaultRunnerConfig()
	if r.cfg.Concurrency != 8 || r.cfg.JobTimeout != def.JobTimeout || r.cfg.MaxDeliver != def.MaxDeliver {
		t.Fatalf("cfg=%+v", r.cfg)
	}
	cc := r.ConsumerConfig()
	if cc.AckWait <= r.cfg.JobTimeout || cc.MaxDeliver != def.MaxDeliver || cc.FilterSubject != queue.RemediationSubject || cc.AckPolicy != nats.AckExplicitPolicy {
		t.Fatalf("consumer config=%+v", cc)
	}
}

// slowHandler blocks until released or its context ends.
type slowHandler struct {
	name     string
	release  chan struct{}
	started  *atomic.Int32
	ignoreCx bool
}

func (h slowHandler) Name() string                               { return h.name }
func (h slowHandler) Validate(incidents.RemediationAction) error { return nil }
func (h slowHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	return h.Execute(ctx, req)
}
func (h slowHandler) Execute(ctx context.Context, _ incidents.RemediationAction) (map[string]any, error) {
	h.started.Add(1)
	if h.ignoreCx {
		<-h.release
		return map[string]any{"late": true}, nil
	}
	select {
	case <-h.release:
		return map[string]any{"ok": true}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// A handler that hangs past the job timeout is recorded as timed_out, not
// retried, and its eventual late completion cannot overwrite that.
func TestJobTimeoutMarksRemediationTimedOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	for _, ignore := range []bool{false, true} {
		release := make(chan struct{})
		started := &atomic.Int32{}
		runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, slowHandler{name: "test_slow", release: release, started: started, ignoreCx: ignore})
		runner.Configure(RunnerConfig{JobTimeout: 200 * time.Millisecond})
		rem := env.queuedRemediation(t, ctx, "test_slow")

		start := time.Now()
		err := runner.handleMessage(ctx, executeMessage(rem.ID))
		if err == nil || !strings.Contains(err.Error(), "job timeout") {
			t.Fatalf("ignoreCtx=%v: err=%v", ignore, err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("ignoreCtx=%v: timeout not enforced (%s)", ignore, elapsed)
		}
		after, _ := env.store.GetRemediation(ctx, rem.ID)
		if after.Status != remediationpkg.StateTimedOut {
			t.Fatalf("ignoreCtx=%v: status=%s", ignore, after.Status)
		}
		close(release) // the abandoned handler finishes late
		time.Sleep(100 * time.Millisecond)
		if ok, _ := env.store.CompleteRemediation(ctx, rem.ID, remediationpkg.StateSucceeded, nil, ""); ok {
			t.Fatalf("ignoreCtx=%v: a late completion overwrote timed_out", ignore)
		}
	}
}

func TestPoisonMessagesAreTerminated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)
	cases := map[string]*nats.Msg{
		"undecodable":    {Subject: queue.RemediationSubject, Data: []byte("not json")},
		"missing id":     {Subject: queue.RemediationSubject, Data: []byte(`{"payload":{}}`)},
		"unknown action": executeMessage("rem_does_not_exist"),
	}
	for name, msg := range cases {
		if err := runner.handleMessage(ctx, msg); err == nil {
			t.Fatalf("%s: poison message was accepted", name)
		}
	}
	if err := runner.handleMessage(ctx, executeMessage("rem_does_not_exist")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing remediation should be classified as not found, got %v", err)
	}
}

// End to end against JetStream: a database outage retries with backoff and
// then dead-letters instead of spinning; a poison message is dead-lettered
// at once; one hung job does not block the others.
func TestJetStreamFailureHandling(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)

	client, err := queue.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	js := client.JetStream()
	for _, stream := range []string{queue.RemediationStream, queue.DeadLetterStream} {
		if err := js.PurgeStream(stream); err != nil {
			t.Fatal(err)
		}
	}
	_ = js.DeleteConsumer(queue.RemediationStream, WorkerConsumer)
	dlq, err := js.PullSubscribe(queue.DeadLetterSubject, "", nats.BindStream(queue.DeadLetterStream))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dlq.Unsubscribe() }()

	// A store whose database is closed behaves like PostgreSQL being down.
	broken, err := sql.Open("pgx", os.Getenv("ARGUS_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	brokenStore := incidents.NewStore(broken)

	release := make(chan struct{})
	defer close(release)
	started := &atomic.Int32{}
	var mu sync.Mutex
	seen := map[string][]string{}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	// Runner 1: healthy database; one hung handler plus fast ones.
	healthy := NewRunner(env.store, env.auditor, client, safetyMetrics,
		slowHandler{name: "test_slow", release: release, started: started},
		countingHandler{runner: "healthy", mu: &mu, seen: seen})
	healthy.Configure(RunnerConfig{Concurrency: 2, JobTimeout: 30 * time.Second, MaxDeliver: 3, FetchWait: 200 * time.Millisecond})
	go func() { _ = healthy.Start(runCtx, "healthy") }()

	hung := env.queuedRemediation(t, ctx, "test_slow")
	publish := func(remediationID, eventID string) {
		t.Helper()
		if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: eventID, Payload: map[string]any{"remediation_id": remediationID}}); err != nil {
			t.Fatal(err)
		}
	}
	publish(hung.ID, hung.ID)
	waitFor(t, 10*time.Second, func() bool { return started.Load() == 1 })

	var fast []string
	for i := range 5 {
		rem := env.queuedRemediation(t, ctx, "test_counter")
		fast = append(fast, rem.ID)
		publish(rem.ID, fmt.Sprintf("%s-%d", rem.ID, i))
	}
	waitFor(t, 15*time.Second, func() bool {
		for _, id := range fast {
			if rem, _ := env.store.GetRemediation(ctx, id); rem.Status != remediationpkg.StateSucceeded {
				return false
			}
		}
		return true
	})

	// Poison: dead-lettered immediately.
	if _, err := js.PublishMsg(&nats.Msg{Subject: queue.RemediationSubject, Data: []byte("garbage")}); err != nil {
		t.Fatal(err)
	}
	poison := nextDeadLetter(t, dlq)
	if poison.Header.Get("Argus-Dead-Letter-Reason") != "undecodable_payload" || string(poison.Data) != "garbage" || poison.Header.Get("Argus-Deliveries") != "1" {
		t.Fatalf("poison dead letter headers=%v data=%q", poison.Header, poison.Data)
	}
	stop()
	time.Sleep(500 * time.Millisecond)

	// Runner 2: database down. Retries back off (1s, 2s), then dead-letter.
	_ = js.DeleteConsumer(queue.RemediationStream, WorkerConsumer)
	if err := js.PurgeStream(queue.RemediationStream); err != nil {
		t.Fatal(err)
	}
	outageCtx, stopOutage := context.WithCancel(ctx)
	defer stopOutage()
	down := NewRunner(brokenStore, env.auditor, client, safetyMetrics, DefaultHandlers(env.state)...)
	down.Configure(RunnerConfig{Concurrency: 2, MaxDeliver: 3, FetchWait: 200 * time.Millisecond})
	go func() { _ = down.Start(outageCtx, "down") }()
	start := time.Now()
	// Unique per run: JetStream remembers a Nats-Msg-Id for the duplicate window.
	publish("rem_during_outage", fmt.Sprintf("outage-%d", time.Now().UnixNano()))
	exhausted := nextDeadLetter(t, dlq)
	elapsed := time.Since(start)
	if exhausted.Header.Get("Argus-Dead-Letter-Reason") != "retries_exhausted" || exhausted.Header.Get("Argus-Deliveries") != "3" {
		t.Fatalf("outage dead letter headers=%v", exhausted.Header)
	}
	if elapsed < 2500*time.Millisecond {
		t.Fatalf("redelivery did not back off: dead-lettered after %s", elapsed)
	}
	var event queue.Event
	_ = json.Unmarshal(exhausted.Data, &event)
	if event.Payload["remediation_id"] != "rem_during_outage" {
		t.Fatalf("dead letter lost the original job: %s", exhausted.Data)
	}
	t.Logf("database outage: 3 deliveries with backoff, dead-lettered after %s", elapsed.Round(100*time.Millisecond))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func nextDeadLetter(t *testing.T, sub *nats.Subscription) *nats.Msg {
	t.Helper()
	msgs, err := sub.Fetch(1, nats.MaxWait(15*time.Second))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("no dead letter arrived: %v", err)
	}
	_ = msgs[0].Ack()
	return msgs[0]
}
