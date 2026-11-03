package remediation_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/testutil"
)

// fakePublisher stands in for JetStream; fail makes every publish error.
type fakePublisher struct {
	mu     sync.Mutex
	fail   atomic.Bool
	delay  time.Duration
	events []queue.Event
}

func (p *fakePublisher) Publish(ctx context.Context, subject string, event queue.Event) (bool, error) {
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if p.fail.Load() {
		return false, errors.New("nats: no responders available for request")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
	return false, nil
}

func (p *fakePublisher) published(remediationID string) []queue.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []queue.Event
	for _, e := range p.events {
		if e.Payload["remediation_id"] == remediationID {
			out = append(out, e)
		}
	}
	return out
}

type dispatchRow struct {
	ID, Reason, State string
	Attempts          int
	LastError         sql.NullString
}

func dispatches(t *testing.T, database *sql.DB, remediationID string) []dispatchRow {
	t.Helper()
	rows, err := database.Query(`SELECT id, reason, state, attempts, last_error FROM remediation_dispatches WHERE remediation_id = $1 ORDER BY created_at`, remediationID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []dispatchRow
	for rows.Next() {
		var r dispatchRow
		if err := rows.Scan(&r.ID, &r.Reason, &r.State, &r.Attempts, &r.LastError); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// makeDue lets the next poll retry rows that are waiting out their backoff.
func makeDue(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`UPDATE remediation_dispatches SET next_attempt_at = now() WHERE state = 'pending'`); err != nil {
		t.Fatal(err)
	}
}

func outboxService(t *testing.T, ctx context.Context, publisher remediation.Publisher, cfg remediation.DispatcherConfig) (*sql.DB, *incidents.Store, *remediation.Service, *remediation.Dispatcher) {
	t.Helper()
	return outboxServiceOn(t, ctx, publisher, cfg, false)
}

// outboxServiceOn with isolated=true uses a scratch database: the
// reconciler acts on every queued remediation, including ones other tests
// left behind.
func outboxServiceOn(t *testing.T, ctx context.Context, publisher remediation.Publisher, cfg remediation.DispatcherConfig, isolated bool) (*sql.DB, *incidents.Store, *remediation.Service, *remediation.Dispatcher) {
	t.Helper()
	var database *sql.DB
	var store *incidents.Store
	var auditor *audit.Service
	if isolated {
		database = testutil.ScratchDatabase(t)
		if err := db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
		metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
		store, auditor = incidents.NewStore(database), audit.NewService(database)
	} else {
		database, store, auditor = auditCouplingEnv(t, ctx)
	}
	service := remediation.NewService(store, auditor, policy.NewEngine(), nil, remediation.NewLocalExecutor(), metrics, nil)
	dispatcher := remediation.NewDispatcher(store, auditor, publisher, metrics, nil, cfg)
	service.UseDispatcher(dispatcher)
	return database, store, service, dispatcher
}

// JetStream down when execution is requested: the request still succeeds,
// the remediation is durably queued with its job in the outbox, and the job
// is published once JetStream is back.
func TestExecuteSurvivesJetStreamOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	publisher := &fakePublisher{}
	publisher.fail.Store(true)
	database, store, service, dispatcher := outboxService(t, ctx, publisher, remediation.DispatcherConfig{})
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)

	reused, err := service.Execute(ctx, rem.ID, true, "operator-1")
	if err != nil || reused {
		t.Fatalf("execute during outage: reused=%v err=%v", reused, err)
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateQueued {
		t.Fatalf("status=%s, want queued", after.Status)
	}
	rows := dispatches(t, database, rem.ID)
	if len(rows) != 1 || rows[0].State != "pending" || rows[0].Attempts != 1 || !rows[0].LastError.Valid {
		t.Fatalf("outbox after failed publish: %+v", rows)
	}

	// Still down: the poll retries and keeps the job.
	makeDue(t, database)
	if n, err := dispatcher.PublishPending(ctx); err != nil || n != 0 {
		t.Fatalf("publish while down: n=%d err=%v", n, err)
	}
	publisher.fail.Store(false)
	makeDue(t, database)
	if n, err := dispatcher.PublishPending(ctx); err != nil || n < 1 {
		t.Fatalf("publish after recovery: n=%d err=%v", n, err)
	}
	rows = dispatches(t, database, rem.ID)
	events := publisher.published(rem.ID)
	if len(rows) != 1 || rows[0].State != "published" || rows[0].Attempts != 3 || len(events) != 1 || events[0].EventID != rows[0].ID {
		t.Fatalf("rows=%+v events=%+v", rows, events)
	}
	if events[0].Payload["dry_run"] != true {
		t.Fatalf("job lost the dry-run flag: %+v", events[0].Payload)
	}
}

// The API process dies after the reservation commits and before it
// publishes. Previously the remediation stayed queued with no job forever;
// now any dispatcher (another replica, or this one after restart) publishes
// it exactly once.
func TestCrashAfterReservationIsDispatchedByAnotherReplica(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, store, auditor := auditCouplingEnv(t, ctx)
	crashed := remediation.NewService(store, auditor, policy.NewEngine(), nil, remediation.NewLocalExecutor(), metrics, nil)
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	// No dispatcher: nothing is published after the commit, as if the
	// process exited right there.
	if _, err := crashed.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if rows := dispatches(t, database, rem.ID); len(rows) != 1 || rows[0].State != "pending" || rows[0].Attempts != 0 {
		t.Fatalf("reservation without its job: %+v", rows)
	}

	publisher := &fakePublisher{}
	survivor := remediation.NewDispatcher(store, auditor, publisher, metrics, nil, remediation.DispatcherConfig{})
	for range 3 {
		if _, err := survivor.PublishPending(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if events := publisher.published(rem.ID); len(events) != 1 {
		t.Fatalf("published %d times, want once", len(events))
	}
}

// A failed audit append rolls back the reservation and its job together.
func TestReservationAndJobRollBackTogether(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	publisher := &fakePublisher{}
	database, store, service, _ := outboxService(t, ctx, publisher, remediation.DispatcherConfig{})
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	restore := testutil.FailAuditAction(t, database, "remediation.execute_requested")
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err == nil {
		t.Fatal("execute succeeded although its audit entry failed")
	}
	restore()
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateApproved {
		t.Fatalf("status=%s", after.Status)
	}
	if rows := dispatches(t, database, rem.ID); len(rows) != 0 || len(publisher.published(rem.ID)) != 0 {
		t.Fatalf("a job exists for a reservation that rolled back: %+v", rows)
	}
}

// A job whose remediation was cancelled before it could be published is
// skipped, not sent.
func TestPendingJobForCancelledRemediationIsSkipped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	publisher := &fakePublisher{}
	publisher.fail.Store(true)
	database, store, service, dispatcher := outboxService(t, ctx, publisher, remediation.DispatcherConfig{})
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(ctx, rem.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	publisher.fail.Store(false)
	makeDue(t, database)
	if _, err := dispatcher.PublishPending(ctx); err != nil {
		t.Fatal(err)
	}
	rows := dispatches(t, database, rem.ID)
	if len(rows) != 1 || rows[0].State != "skipped" || len(publisher.published(rem.ID)) != 0 {
		t.Fatalf("rows=%+v published=%d", rows, len(publisher.published(rem.ID)))
	}
}

// API replicas poll the same outbox; each job is published once.
func TestConcurrentDispatchersPublishEachJobOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, store, auditor := auditCouplingEnv(t, ctx)
	database.SetMaxOpenConns(30)
	crashed := remediation.NewService(store, auditor, policy.NewEngine(), nil, remediation.NewLocalExecutor(), metrics, nil)
	var ids []string
	for range 20 {
		rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
		if _, err := crashed.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rem.ID)
	}
	publisher := &fakePublisher{delay: 5 * time.Millisecond}
	var wg sync.WaitGroup
	for range 4 {
		d := remediation.NewDispatcher(store, auditor, publisher, metrics, nil, remediation.DispatcherConfig{BatchSize: 3})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 15 {
				if _, err := d.PublishPending(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if n := len(publisher.published(id)); n != 1 {
			t.Fatalf("%s published %d times", id, n)
		}
	}
}

// A job no worker runs (dead-lettered during a database outage, expired, or
// lost with the JetStream node) is re-sent after RedispatchAfter, up to
// MaxRedispatches, and the remediation then times out instead of staying
// queued forever. A remediation queued before the outbox existed (no
// dispatch row) is picked up the same way.
func TestReconcilerRedispatchesThenTimesOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	publisher := &fakePublisher{}
	cfg := remediation.DispatcherConfig{RedispatchAfter: 300 * time.Millisecond, MaxRedispatches: 2}
	database, store, service, dispatcher := outboxServiceOn(t, ctx, publisher, cfg, true)
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	legacy := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := store.MarkRemediationQueued(ctx, legacy.ID, false); err != nil {
		t.Fatal(err)
	}

	// Freshly published: nothing to do yet.
	if result, err := dispatcher.Reconcile(ctx); err != nil || contains(result.Redispatched, rem.ID) {
		t.Fatalf("reconciled a job published moments ago: %+v err=%v", result, err)
	}
	for pass := 1; pass <= 2; pass++ {
		time.Sleep(400 * time.Millisecond)
		result, err := dispatcher.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !contains(result.Redispatched, rem.ID) || !contains(result.Redispatched, legacy.ID) {
			t.Fatalf("pass %d: %+v", pass, result)
		}
		if n := len(publisher.published(rem.ID)); n != pass+1 {
			t.Fatalf("pass %d: job published %d times", pass, n)
		}
	}
	time.Sleep(400 * time.Millisecond)
	result, err := dispatcher.Reconcile(ctx)
	if err != nil || !contains(result.Exhausted, rem.ID) || !contains(result.Exhausted, legacy.ID) {
		t.Fatalf("final pass: %+v err=%v", result, err)
	}
	after, _ := store.GetRemediation(ctx, rem.ID)
	if after.Status != remediation.StateTimedOut {
		t.Fatalf("status=%s, want timed_out", after.Status)
	}
	rows := dispatches(t, database, rem.ID)
	if len(rows) != 3 || rows[0].Reason != "execute" || rows[1].Reason != "redispatch" || rows[2].Reason != "redispatch" {
		t.Fatalf("dispatch history: %+v", rows)
	}
	if testutil.AuditCount(t, database, rem.ID, "remediation.redispatched") != 2 || testutil.AuditCount(t, database, rem.ID, "remediation.dispatch_exhausted") != 1 {
		t.Fatal("reconciler actions were not audited")
	}
	// Nothing left to do, and a late worker cannot run it: the claim fails.
	if ok, _ := store.ClaimRemediation(ctx, rem.ID); ok {
		t.Fatal("a timed-out remediation was claimable")
	}
}

// Replicas reconcile concurrently without sending a job twice.
func TestConcurrentReconcilersRedispatchOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	publisher := &fakePublisher{}
	cfg := remediation.DispatcherConfig{RedispatchAfter: 200 * time.Millisecond, MaxRedispatches: 5}
	database, store, service, _ := outboxServiceOn(t, ctx, publisher, cfg, true)
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	auditor := audit.NewService(database)
	var wg sync.WaitGroup
	for range 6 {
		d := remediation.NewDispatcher(store, auditor, publisher, metrics, nil, cfg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.Reconcile(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if rows := dispatches(t, database, rem.ID); len(rows) != 2 {
		t.Fatalf("concurrent reconcilers wrote %d dispatches, want execute + one redispatch: %+v", len(rows), rows)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
