package workers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/testutil"
	"github.com/nats-io/nats.go"
)

// End to end against PostgreSQL and JetStream: an operator executes a
// remediation while the worker's database is unreachable. The worker retries
// and dead-letters the job; the remediation is still queued. Once the
// database is back, the reconciler notices that no worker ran the job and
// re-sends it from the outbox, and a healthy worker executes it exactly
// once. Before the outbox this remediation stayed queued forever.
func TestDeadLetteredJobIsRecoveredByTheReconciler(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database := testutil.ScratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	safetyMetricsOnce.Do(func() { safetyMetrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)

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

	incident, err := store.CreateManualIncident(ctx, incidents.ManualIncidentRequest{Title: "outbox e2e", Service: "outbox-svc", Severity: "sev2"})
	if err != nil {
		t.Fatal(err)
	}
	rem := incidents.RemediationAction{
		ID: fmt.Sprintf("rem_outbox_%d", time.Now().UnixNano()), IncidentID: incident.ID, ActionType: "test_counter",
		Target: "outbox-svc", Status: remediationpkg.StateApproved, Risk: "low",
		IdempotencyKey: fmt.Sprintf("outbox-%d", time.Now().UnixNano()), ProposedBy: "test", MaxAttempts: 3, PolicyDecision: map[string]any{},
	}
	if err := store.CreateRemediation(ctx, rem); err != nil {
		t.Fatal(err)
	}

	// The worker's database is down.
	broken, err := sql.Open("pgx", os.Getenv("ARGUS_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	outageCtx, endOutage := context.WithCancel(ctx)
	down := NewRunner(incidents.NewStore(broken), auditor, client, safetyMetrics, DefaultHandlers(NewPostgresControlStateStore(database))...)
	down.Configure(RunnerConfig{Concurrency: 1, MaxDeliver: 2, FetchWait: 200 * time.Millisecond})
	downDone := make(chan struct{})
	go func() { defer close(downDone); _ = down.Start(outageCtx, "down") }()

	service := remediationpkg.NewService(store, auditor, policy.NewEngine(), nil, remediationpkg.NewLocalExecutor(), safetyMetrics, nil)
	dispatcher := remediationpkg.NewDispatcher(store, auditor, client, safetyMetrics, nil, remediationpkg.DispatcherConfig{RedispatchAfter: time.Second, MaxRedispatches: 3})
	service.UseDispatcher(dispatcher)
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}

	letter := nextDeadLetter(t, dlq)
	if letter.Header.Get("Argus-Dead-Letter-Reason") != "retries_exhausted" {
		t.Fatalf("dead letter headers=%v", letter.Header)
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediationpkg.StateQueued {
		t.Fatalf("status after dead letter=%s", after.Status)
	}
	endOutage()
	<-downDone

	// Database back; a healthy worker is running.
	var mu sync.Mutex
	seen := map[string][]string{}
	healthy := NewRunner(store, auditor, client, safetyMetrics, countingHandler{runner: "healthy", mu: &mu, seen: seen})
	healthy.Configure(RunnerConfig{Concurrency: 2, MaxDeliver: 3, FetchWait: 200 * time.Millisecond})
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = healthy.Start(runCtx, "healthy") }()

	// Nothing re-sends the job until the reconciler runs.
	time.Sleep(1200 * time.Millisecond)
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediationpkg.StateQueued {
		t.Fatalf("job ran before it was re-sent: %s", after.Status)
	}
	result, err := dispatcher.Reconcile(ctx)
	if err != nil || len(result.Redispatched) != 1 || result.Redispatched[0] != rem.ID {
		t.Fatalf("reconcile=%+v err=%v", result, err)
	}
	waitFor(t, 15*time.Second, func() bool {
		after, _ := store.GetRemediation(ctx, rem.ID)
		return after.Status == remediationpkg.StateSucceeded
	})
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	runs := len(seen[rem.ID])
	mu.Unlock()
	if runs != 1 {
		t.Fatalf("handler ran %d times, want once", runs)
	}
	if n := testutil.AuditCount(t, database, rem.ID, "remediation.redispatched"); n != 1 {
		t.Fatalf("redispatch audit entries=%d", n)
	}
}
