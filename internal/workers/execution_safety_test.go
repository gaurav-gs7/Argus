package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/nats-io/nats.go"
)

var (
	safetyMetricsOnce sync.Once
	safetyMetrics     *telemetry.Metrics
)

type safetyEnv struct {
	db       *sql.DB
	store    *incidents.Store
	auditor  *audit.Service
	state    *PostgresControlStateStore
	incident incidents.Incident
}

func newSafetyEnv(t *testing.T, ctx context.Context) safetyEnv {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	safetyMetricsOnce.Do(func() { safetyMetrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	incident, err := store.CreateManualIncident(ctx, incidents.ManualIncidentRequest{Title: fmt.Sprintf("safety-%d", time.Now().UnixNano()), Service: "safety-svc", Severity: "sev2"})
	if err != nil {
		t.Fatal(err)
	}
	return safetyEnv{db: database, store: store, auditor: audit.NewService(database), state: NewPostgresControlStateStore(database), incident: incident}
}

func (e safetyEnv) queuedRemediation(t *testing.T, ctx context.Context, actionType string) incidents.RemediationAction {
	t.Helper()
	id := fmt.Sprintf("rem_safety_%d", time.Now().UnixNano())
	rem := incidents.RemediationAction{
		ID: id, IncidentID: e.incident.ID, ActionType: actionType, Target: "safety-svc",
		Parameters: map[string]any{"size": 20}, Status: remediationpkg.StateQueued, Risk: "medium",
		IdempotencyKey: id + "_key", ProposedBy: "test", MaxAttempts: 1, PolicyDecision: map[string]any{},
	}
	if err := e.store.CreateRemediation(ctx, rem); err != nil {
		t.Fatal(err)
	}
	return rem
}

func (e safetyEnv) executed(t *testing.T, ctx context.Context, rem incidents.RemediationAction) bool {
	t.Helper()
	var n int
	if err := e.db.QueryRowContext(ctx, `SELECT count(*) FROM remediation_execution_receipts WHERE idempotency_key = $1`, rem.IdempotencyKey).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func executeMessage(remediationID string) *nats.Msg {
	data, _ := json.Marshal(queue.Event{EventType: "remediation.execute", Payload: map[string]any{"remediation_id": remediationID}})
	return &nats.Msg{Subject: "remediation.execute", Data: data}
}

func (e safetyEnv) remediationService() *remediationpkg.Service {
	return remediationpkg.NewService(e.store, e.auditor, policy.NewEngine(), nil, nil, safetyMetrics, nil)
}

// An operator cancels a queued remediation; the already-published message is
// then delivered. Nothing may execute.
func TestCancelledQueuedRemediationIsNotExecuted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	rem := env.queuedRemediation(t, ctx, "resize_connection_pool")

	if err := env.remediationService().Cancel(ctx, rem.ID, "operator"); err != nil {
		t.Fatalf("cancel queued remediation: %v", err)
	}
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)
	_ = runner.handleMessage(ctx, executeMessage(rem.ID))

	after, err := env.store.GetRemediation(ctx, rem.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != remediationpkg.StateCancelled || env.executed(t, ctx, rem) {
		t.Fatalf("cancelled remediation was executed: status=%s receipt=%v", after.Status, env.executed(t, ctx, rem))
	}
}

// Cancel and worker delivery race. Whatever wins, a remediation that ends up
// cancelled must never have executed, and a cancel that loses must say so.
func TestCancelRaceNeverExecutesACancelledAction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	service := env.remediationService()
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)

	outcomes := map[string]int{}
	for i := 0; i < 40; i++ {
		rem := env.queuedRemediation(t, ctx, "resize_connection_pool")
		var wg sync.WaitGroup
		var cancelErr error
		wg.Add(2)
		go func() { defer wg.Done(); cancelErr = service.Cancel(ctx, rem.ID, "operator") }()
		go func() { defer wg.Done(); _ = runner.handleMessage(ctx, executeMessage(rem.ID)) }()
		wg.Wait()

		after, err := env.store.GetRemediation(ctx, rem.ID)
		if err != nil {
			t.Fatal(err)
		}
		ran := env.executed(t, ctx, rem)
		switch {
		case after.Status == remediationpkg.StateCancelled && ran:
			t.Fatalf("iteration %d: cancelled remediation executed", i)
		case after.Status == remediationpkg.StateCancelled && cancelErr != nil:
			t.Fatalf("iteration %d: cancel succeeded but returned %v", i, cancelErr)
		case after.Status == remediationpkg.StateSucceeded && cancelErr == nil:
			t.Fatalf("iteration %d: cancel reported success but the action ran", i)
		case after.Status != remediationpkg.StateCancelled && after.Status != remediationpkg.StateSucceeded:
			t.Fatalf("iteration %d: unexpected final status %s", i, after.Status)
		}
		outcomes[after.Status]++
	}
	t.Logf("race outcomes: %v", outcomes)
}

func TestStaleMessagesForFinishedRemediationsAreSkipped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)
	for _, status := range []string{remediationpkg.StateFailed, remediationpkg.StateTimedOut, remediationpkg.StateCancelled, remediationpkg.StateApproved} {
		rem := env.queuedRemediation(t, ctx, "resize_connection_pool")
		if _, err := env.db.ExecContext(ctx, `UPDATE remediation_actions SET status = $2 WHERE id = $1`, rem.ID, status); err != nil {
			t.Fatal(err)
		}
		_ = runner.handleMessage(ctx, executeMessage(rem.ID))
		after, _ := env.store.GetRemediation(ctx, rem.ID)
		if after.Status != status || env.executed(t, ctx, rem) {
			t.Fatalf("%s remediation was executed or changed: status=%s", status, after.Status)
		}
	}
}

func TestStoreTransitionsAreConditional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	rem := env.queuedRemediation(t, ctx, "resize_connection_pool")
	if ok, err := env.store.ClaimRemediation(ctx, rem.ID); err != nil || !ok {
		t.Fatalf("claim queued: %v %v", ok, err)
	}
	if ok, _ := env.store.CancelRemediation(ctx, rem.ID, remediationpkg.StateQueued); ok {
		t.Fatal("cancel applied to a running remediation")
	}
	if ok, _ := env.store.CompleteRemediation(ctx, rem.ID, remediationpkg.StateSucceeded, nil, ""); !ok {
		t.Fatal("complete running remediation failed")
	}
	if ok, _ := env.store.CompleteRemediation(ctx, rem.ID, remediationpkg.StateFailed, nil, "late"); ok {
		t.Fatal("completion overwrote a terminal state")
	}
	if ok, _ := env.store.ClaimRemediation(ctx, rem.ID); ok {
		t.Fatal("claimed a succeeded remediation")
	}
	err := env.remediationService().Cancel(ctx, rem.ID, "operator")
	if err == nil {
		t.Fatal("cancelling a succeeded remediation should fail")
	}
	_ = errors.Is(err, remediationpkg.ErrStateChanged)
}

// countingHandler records which runner executed each remediation.
type countingHandler struct {
	runner string
	mu     *sync.Mutex
	seen   map[string][]string
}

func (h countingHandler) Name() string                               { return "test_counter" }
func (h countingHandler) Validate(incidents.RemediationAction) error { return nil }
func (h countingHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	return h.Execute(ctx, req)
}
func (h countingHandler) Execute(_ context.Context, req incidents.RemediationAction) (map[string]any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen[req.ID] = append(h.seen[req.ID], h.runner)
	return map[string]any{"runner": h.runner}, nil
}

// values-production.yaml runs worker.replicas: 2. Both replicas must
// subscribe, share the work, and execute each remediation exactly once.
func TestWorkerReplicasShareWorkExactlyOnce(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)

	// Drain anything left in the stream by earlier runs so the consumer
	// starts from a known point.
	publisher, err := queue.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if err := publisher.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	if err := publisher.JetStream().PurgeStream("ARGUS_REMEDIATION"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := map[string][]string{}
	var exited atomic.Int32
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	for _, name := range []string{"replica-a", "replica-b"} {
		client, err := queue.Connect(url)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		runner := NewRunner(env.store, env.auditor, client, safetyMetrics, countingHandler{runner: name, mu: &mu, seen: seen})
		go func() {
			if err := runner.Start(runCtx, name); err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("%s exited: %v", name, err)
				exited.Add(1)
			}
		}()
		time.Sleep(300 * time.Millisecond)
	}
	if exited.Load() != 0 {
		t.FailNow()
	}

	const jobs = 30
	ids := make([]string, 0, jobs)
	for range jobs {
		rem := env.queuedRemediation(t, ctx, "test_counter")
		ids = append(ids, rem.ID)
		if err := publisher.Publish(ctx, "remediation.execute", queue.Event{EventType: "remediation.execute", Payload: map[string]any{"remediation_id": rem.ID}}); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		done := 0
		for _, id := range ids {
			if rem, err := env.store.GetRemediation(ctx, id); err == nil && rem.Status == remediationpkg.StateSucceeded {
				done++
			}
		}
		if done == jobs {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d remediations completed", done, jobs)
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	perReplica := map[string]int{}
	for _, id := range ids {
		if len(seen[id]) != 1 {
			t.Fatalf("remediation %s executed %d times: %v", id, len(seen[id]), seen[id])
		}
		perReplica[seen[id][0]]++
	}
	if len(perReplica) != 2 {
		t.Fatalf("work was not shared across replicas: %v", perReplica)
	}
	t.Logf("executions per replica: %v", perReplica)
}
