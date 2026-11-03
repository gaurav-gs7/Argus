package remediation_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/rca"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/testutil"
)

var (
	metricsOnce sync.Once
	metrics     *telemetry.Metrics
)

// The policy used to be told every incident was "local", so production
// incidents passed the environment gate.
func TestProposalUsesIncidentEnvironment(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	manager := incidents.NewServiceManager(store, auditor, 30*time.Minute)

	ingest := func(environment string) incidents.Incident {
		created, err := manager.IngestAlertmanager(ctx, incidents.AlertmanagerWebhook{Alerts: []incidents.AlertmanagerAlert{{
			Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: fmt.Sprintf("env-%s-%d", environment, time.Now().UnixNano()),
			Labels: map[string]string{"alertname": "PolicyEnvTest", "service": fmt.Sprintf("policy-%s-%d", environment, time.Now().UnixNano()), "environment": environment},
		}}}, "test")
		if err != nil {
			t.Fatal(err)
		}
		return created[0]
	}
	diagnostics := []rca.Candidate{{ActionType: "collect_diagnostics", Target: "payments-api", Risk: "low"}}

	service := remediation.NewService(store, auditor, policy.NewEngine(), nil, nil, metrics, nil)
	production := ingest("production")
	actions, err := service.Propose(ctx, production, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StatePolicyBlocked || !strings.Contains(fmt.Sprint(actions[0].PolicyDecision["reason"]), `"production"`) {
		t.Fatalf("production proposal not blocked: %s %v", actions[0].Status, actions[0].PolicyDecision)
	}

	local := ingest("local")
	actions, err = service.Propose(ctx, local, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StateApproved || actions[0].Risk != "low" {
		t.Fatalf("local low-risk proposal: %s risk=%s %v", actions[0].Status, actions[0].Risk, actions[0].PolicyDecision)
	}

	enabled := remediation.NewService(store, auditor, policy.NewEngineForEnvironments([]string{"local", "production"}), nil, nil, metrics, nil)
	other := ingest("production")
	actions, err = enabled.Propose(ctx, other, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StateApproved {
		t.Fatalf("explicitly enabled production proposal: %s %v", actions[0].Status, actions[0].PolicyDecision)
	}
}

func TestExecuteRefusesClosedIncident(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	incident, err := store.CreateManualIncident(ctx, incidents.ManualIncidentRequest{Title: fmt.Sprintf("closed-%d", time.Now().UnixNano()), Service: "closed-svc", Severity: "sev2"})
	if err != nil {
		t.Fatal(err)
	}
	rem := incidents.RemediationAction{
		ID: fmt.Sprintf("rem_closed_%d", time.Now().UnixNano()), IncidentID: incident.ID, ActionType: "collect_diagnostics",
		Target: "closed-svc", Status: remediation.StateApproved, Risk: "low", IdempotencyKey: fmt.Sprintf("closed-%d", time.Now().UnixNano()),
		ProposedBy: "test", MaxAttempts: 1, PolicyDecision: map[string]any{},
	}
	if err := store.CreateRemediation(ctx, rem); err != nil {
		t.Fatal(err)
	}
	if _, applied, err := store.TransitionIncident(ctx, incident.ID, incidents.StatusResolved); err != nil || !applied {
		t.Fatalf("resolve: %v %v", applied, err)
	}
	service := remediation.NewService(store, audit.NewService(database), policy.NewEngine(), nil, nil, metrics, nil)
	if _, err := service.Execute(ctx, rem.ID, true, "operator-1"); !errors.Is(err, remediation.ErrIncidentClosed) {
		t.Fatalf("execute on resolved incident: %v", err)
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateApproved {
		t.Fatalf("remediation status changed to %s", after.Status)
	}
}

type countingExecutor struct{ calls int }

func (e *countingExecutor) Name() string { return "counting" }
func (e *countingExecutor) Execute(context.Context, incidents.RemediationAction, incidents.Incident, bool) (remediation.ExecutionOutcome, error) {
	e.calls++
	return remediation.ExecutionOutcome{Status: remediation.StateQueued}, nil
}

func auditCouplingEnv(t *testing.T, ctx context.Context) (*sql.DB, *incidents.Store, *audit.Service) {
	t.Helper()
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	return database, incidents.NewStore(database), audit.NewService(database)
}

func approvedRemediation(t *testing.T, ctx context.Context, store *incidents.Store, status string) incidents.RemediationAction {
	t.Helper()
	incident, err := store.CreateManualIncident(ctx, incidents.ManualIncidentRequest{Title: fmt.Sprintf("coupling-%d", time.Now().UnixNano()), Service: "coupling-svc", Severity: "sev3"})
	if err != nil {
		t.Fatal(err)
	}
	rem := incidents.RemediationAction{
		ID: fmt.Sprintf("rem_coupling_%d", time.Now().UnixNano()), IncidentID: incident.ID, ActionType: "collect_diagnostics",
		Target: "coupling-svc", Status: status, Risk: "low", IdempotencyKey: fmt.Sprintf("coupling-%d", time.Now().UnixNano()),
		ProposedBy: "test", MaxAttempts: 1, PolicyDecision: map[string]any{},
	}
	if err := store.CreateRemediation(ctx, rem); err != nil {
		t.Fatal(err)
	}
	return rem
}

// A reservation whose audit entry cannot be written is not made, and nothing
// is dispatched.
func TestExecuteReservationCommitsWithAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, store, auditor := auditCouplingEnv(t, ctx)
	executor := &countingExecutor{}
	service := remediation.NewService(store, auditor, policy.NewEngine(), nil, executor, metrics, nil)
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)

	restore := testutil.FailAuditAction(t, database, "remediation.execute_requested")
	if _, err := service.Execute(ctx, rem.ID, true, "operator-1"); err == nil {
		t.Fatal("execution was dispatched although its audit entry failed")
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateApproved || executor.calls != 0 {
		t.Fatalf("status=%s executor calls=%d after a failed audit", after.Status, executor.calls)
	}
	restore()
	if _, err := service.Execute(ctx, rem.ID, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateQueued || executor.calls != 1 ||
		testutil.AuditCount(t, database, rem.ID, "remediation.execute_requested") != 1 {
		t.Fatalf("status=%s calls=%d", after.Status, executor.calls)
	}
}

func TestCancelCommitsWithAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, store, auditor := auditCouplingEnv(t, ctx)
	service := remediation.NewService(store, auditor, policy.NewEngine(), nil, &countingExecutor{}, metrics, nil)
	rem := approvedRemediation(t, ctx, store, remediation.StateQueued)

	restore := testutil.FailAuditAction(t, database, "remediation.cancelled")
	if err := service.Cancel(ctx, rem.ID, "operator-1"); err == nil {
		t.Fatal("cancel reported success although its audit entry failed")
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateQueued {
		t.Fatalf("status=%s after a failed cancel audit", after.Status)
	}
	restore()
	if err := service.Cancel(ctx, rem.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if after, _ := store.GetRemediation(ctx, rem.ID); after.Status != remediation.StateCancelled || testutil.AuditCount(t, database, rem.ID, "remediation.cancelled") != 1 {
		t.Fatalf("status=%s", after.Status)
	}
}

func TestRecordReportsAuditFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _, auditor := auditCouplingEnv(t, ctx)
	testutil.FailAuditAction(t, database, "remediation.execution_reused")
	var reported []string
	auditor.OnFailure(func(entry audit.Entry, err error) { reported = append(reported, entry.Action+": "+err.Error()) })
	auditor.Record(ctx, audit.Entry{ActorType: "user", Action: "remediation.execution_reused", ResourceType: "remediation", ResourceID: "rem_x"})
	if len(reported) != 1 || !strings.Contains(reported[0], "injected audit failure") {
		t.Fatalf("failure not reported: %v", reported)
	}
}
