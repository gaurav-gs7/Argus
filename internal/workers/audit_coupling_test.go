package workers

import (
	"context"
	"testing"
	"time"

	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/testutil"
)

// If the completion audit entry cannot be written, the completion itself
// must not be recorded; the job is retried and then completes exactly once.
func TestWorkerCompletionAndAuditCommitTogether(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)
	rem := env.queuedRemediation(t, ctx, "resize_connection_pool")

	restore := testutil.FailAuditAction(t, env.db, "remediation.completed")
	if err := runner.handleMessage(ctx, executeMessage(rem.ID)); err == nil {
		t.Fatal("completion succeeded although its audit entry could not be written")
	}
	after, _ := env.store.GetRemediation(ctx, rem.ID)
	if after.Status != remediationpkg.StateRunning || testutil.AuditCount(t, env.db, rem.ID, "remediation.completed") != 0 {
		t.Fatalf("status=%s after a failed audit; the outcome must not be recorded without it", after.Status)
	}

	restore()
	// The return value is msg.Ack(), which errors for a hand-built message;
	// the database is the source of truth here.
	_ = runner.handleMessage(ctx, executeMessage(rem.ID))
	after, _ = env.store.GetRemediation(ctx, rem.ID)
	if after.Status != remediationpkg.StateSucceeded || testutil.AuditCount(t, env.db, rem.ID, "remediation.completed") != 1 {
		t.Fatalf("status=%s completed-audits=%d", after.Status, testutil.AuditCount(t, env.db, rem.ID, "remediation.completed"))
	}
}

func TestWorkerFailureOutcomesCommitWithAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)
	runner := NewRunner(env.store, env.auditor, nil, safetyMetrics, DefaultHandlers(env.state)...)

	// No handler registered: failed + remediation.failed, together.
	rem := env.queuedRemediation(t, ctx, "not_a_registered_action")
	restore := testutil.FailAuditAction(t, env.db, "remediation.failed")
	_ = runner.handleMessage(ctx, executeMessage(rem.ID))
	if after, _ := env.store.GetRemediation(ctx, rem.ID); after.Status != remediationpkg.StateQueued {
		t.Fatalf("status=%s although the failure audit could not be written", after.Status)
	}
	restore()
	_ = runner.handleMessage(ctx, executeMessage(rem.ID))
	if after, _ := env.store.GetRemediation(ctx, rem.ID); after.Status != remediationpkg.StateFailed || testutil.AuditCount(t, env.db, rem.ID, "remediation.failed") != 1 {
		t.Fatalf("status=%s failed-audits=%d", after.Status, testutil.AuditCount(t, env.db, rem.ID, "remediation.failed"))
	}
}
