package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/approvals"
	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

func TestApprovalDecisionIsAtomicWithRemediationAndAudit(t *testing.T) {
	dsn := os.Getenv("ARGUS_INTEGRATION_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_INTEGRATION_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	serviceID := common.NewID("svc")
	incidentID := common.NewID("inc")
	remediationID := common.NewID("rem")
	approvalID := common.NewID("apr")
	insertFixture(t, database, serviceID, incidentID, remediationID)
	t.Cleanup(func() { cleanupFixture(database, approvalID, remediationID, incidentID, serviceID) })

	now := time.Now().UTC()
	store := approvals.NewStore(database)
	request, err := store.Create(ctx, approvals.Request{
		ID: approvalID, RemediationID: remediationID, IncidentID: incidentID,
		ActionType: "restart_service", Target: "payments-api", Risk: "medium",
		Status: approvals.StatusPending, RequestedBy: "operator@local",
		RequestedAt: now, EscalatesAt: now.Add(time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		NotificationStatus: "pending", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if request.ID != approvalID {
		t.Fatalf("approval ID = %q, want %q", request.ID, approvalID)
	}

	decided, err := store.Decide(ctx, approvalID, "admin@local", "user", approvals.DecisionApprove, "Error rate is stable and rollback is available", "api", now.Add(time.Second))
	if err != nil {
		t.Fatalf("decide approval: %v", err)
	}
	if decided.Status != approvals.StatusApproved || decided.DecidedBy != "admin@local" {
		t.Fatalf("unexpected decision: %+v", decided)
	}

	var remediationStatus, approvedBy string
	if err := database.QueryRowContext(ctx, `SELECT status, approved_by FROM remediation_actions WHERE id = $1`, remediationID).Scan(&remediationStatus, &approvedBy); err != nil {
		t.Fatalf("read remediation: %v", err)
	}
	if remediationStatus != "approved" || approvedBy != "admin@local" {
		t.Fatalf("remediation status=%q approved_by=%q", remediationStatus, approvedBy)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE resource_id IN ($1, $2)
		  AND action IN ('approval.approved', 'remediation.approved')
	`, approvalID, remediationID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("approval decision audit count = %d, want 2", auditCount)
	}
	if _, err := store.Decide(ctx, approvalID, "other@local", "user", approvals.DecisionDeny, "changed mind", "api", now.Add(2*time.Second)); !errors.Is(err, approvals.ErrAlreadyDecided) {
		t.Fatalf("replayed decision error = %v, want ErrAlreadyDecided", err)
	}
	assertAuditChainValid(t, database)
}

func TestApprovalExpiryTimesOutRemediationAndWritesAudit(t *testing.T) {
	dsn := os.Getenv("ARGUS_INTEGRATION_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_INTEGRATION_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	serviceID := common.NewID("svc")
	incidentID := common.NewID("inc")
	remediationID := common.NewID("rem")
	approvalID := common.NewID("apr")
	insertFixture(t, database, serviceID, incidentID, remediationID)
	t.Cleanup(func() { cleanupFixture(database, approvalID, remediationID, incidentID, serviceID) })

	now := time.Now().UTC()
	store := approvals.NewStore(database)
	if _, err := store.Create(ctx, approvals.Request{
		ID: approvalID, RemediationID: remediationID, IncidentID: incidentID,
		ActionType: "restart_service", Target: "payments-api", Risk: "medium",
		Status: approvals.StatusPending, RequestedBy: "operator@local",
		RequestedAt: now.Add(-time.Minute), EscalatesAt: now.Add(-30 * time.Second),
		ExpiresAt: now.Add(-time.Second), NotificationStatus: "delivered",
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("create expired approval fixture: %v", err)
	}
	expired, err := store.ExpireDue(ctx, now, 10)
	if err != nil {
		t.Fatalf("expire due approvals: %v", err)
	}
	if len(expired) != 1 || expired[0].ID != approvalID {
		t.Fatalf("expired requests = %+v", expired)
	}
	var status string
	if err := database.QueryRowContext(ctx, `SELECT status FROM remediation_actions WHERE id = $1`, remediationID).Scan(&status); err != nil {
		t.Fatalf("read timed-out remediation: %v", err)
	}
	if status != "timed_out" {
		t.Fatalf("remediation status = %q, want timed_out", status)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE resource_id IN ($1, $2)
		  AND action IN ('approval.expired', 'remediation.approval_timed_out')
	`, approvalID, remediationID).Scan(&auditCount); err != nil {
		t.Fatalf("count timeout audit entries: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("timeout audit count = %d, want 2", auditCount)
	}
	assertAuditChainValid(t, database)
}

func TestSignedSlackModalRecordsMappedIdentityAndReason(t *testing.T) {
	dsn := os.Getenv("ARGUS_INTEGRATION_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_INTEGRATION_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	serviceID := common.NewID("svc")
	incidentID := common.NewID("inc")
	remediationID := common.NewID("rem")
	approvalID := common.NewID("apr")
	insertFixture(t, database, serviceID, incidentID, remediationID)
	t.Cleanup(func() { cleanupFixture(database, approvalID, remediationID, incidentID, serviceID) })
	now := time.Now().UTC()
	store := approvals.NewStore(database)
	if _, err := store.Create(ctx, approvals.Request{
		ID: approvalID, RemediationID: remediationID, IncidentID: incidentID,
		ActionType: "restart_service", Target: "payments-api", Risk: "medium",
		Status: approvals.StatusPending, RequestedBy: "operator@local",
		RequestedAt: now, EscalatesAt: now.Add(time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		NotificationStatus: "delivered", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create approval: %v", err)
	}

	metrics := telemetry.MustRegister()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	notifier, err := approvals.NewWebhookNotifier("", "", "http://localhost:8080", "generic", time.Second)
	if err != nil {
		t.Fatalf("create disabled notifier: %v", err)
	}
	service := approvals.NewService(store, notifier, metrics, logger, 5*time.Minute, time.Minute, time.Second, false)
	workflow, err := approvals.NewSlackWorkflow(service, "slack-secret", "xoxb-test", "U123=admin@local", time.Second)
	if err != nil {
		t.Fatalf("create Slack workflow: %v", err)
	}

	privateMetadata, _ := json.Marshal(map[string]string{"approval_id": approvalID, "decision": "approve"})
	payload, _ := json.Marshal(map[string]any{
		"type": "view_submission",
		"user": map[string]string{"id": "U123"},
		"view": map[string]any{
			"private_metadata": string(privateMetadata),
			"state": map[string]any{"values": map[string]any{
				"decision_reason": map[string]any{
					"reason": map[string]string{"value": "Reviewed error-rate recovery and rollback plan"},
				},
			}},
		},
	})
	body := []byte(url.Values{"payload": []string{string(payload)}}.Encode())
	headers := signedSlackHeaders("slack-secret", body, now)
	result, err := workflow.Handle(ctx, headers, body)
	if err != nil {
		t.Fatalf("handle Slack submission: %v", err)
	}
	if result["status"] != approvals.StatusApproved || result["decided_by"] != "admin@local" {
		t.Fatalf("Slack result = %+v", result)
	}

	stored, err := store.Get(ctx, approvalID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if stored.DecidedBy != "admin@local" || stored.DecisionSource != "slack" ||
		stored.DecisionReason != "Reviewed error-rate recovery and rollback plan" {
		t.Fatalf("stored Slack decision = %+v", stored)
	}
	assertAuditChainValid(t, database)
}

func TestRepeatedExecutionReusesDurableRemediationWithoutRequeue(t *testing.T) {
	dsn := os.Getenv("ARGUS_INTEGRATION_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_INTEGRATION_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	serviceID := common.NewID("svc")
	incidentID := common.NewID("inc")
	remediationID := common.NewID("rem")
	insertFixture(t, database, serviceID, incidentID, remediationID)
	t.Cleanup(func() { cleanupFixture(database, "", remediationID, incidentID, serviceID) })
	if _, err := database.ExecContext(ctx, `
		UPDATE remediation_actions SET status = 'approved', approved_by = 'issuer#admin'
		WHERE id = $1
	`, remediationID); err != nil {
		t.Fatalf("approve remediation fixture: %v", err)
	}

	executor := &countingExecutor{}
	metrics := &telemetry.Metrics{
		RemediationFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_remediation_failures_total",
		}, []string{"action_type"}),
		RemediationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_remediation_duration_seconds",
		}, []string{"action_type"}),
	}
	service := remediationpkg.NewService(
		incidents.NewStore(database),
		audit.NewService(database),
		nil,
		nil,
		executor,
		metrics,
		nil,
	)

	reused, err := service.Execute(ctx, remediationID, true, "issuer#admin")
	if err != nil || reused {
		t.Fatalf("first execution reused=%t err=%v", reused, err)
	}
	reused, err = service.Execute(ctx, remediationID, true, "issuer#admin")
	if err != nil || !reused {
		t.Fatalf("second execution reused=%t err=%v", reused, err)
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls=%d, want 1", executor.calls)
	}

	var queued, reusedAudit int
	if err := database.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE action = 'remediation.execute_requested'),
			COUNT(*) FILTER (WHERE action = 'remediation.execution_reused')
		FROM audit_logs
		WHERE resource_id = $1
	`, remediationID).Scan(&queued, &reusedAudit); err != nil {
		t.Fatalf("count execution audit records: %v", err)
	}
	if queued != 1 || reusedAudit != 1 {
		t.Fatalf("execution audit records queued=%d reused=%d, want 1 each", queued, reusedAudit)
	}
	assertAuditChainValid(t, database)
}

type countingExecutor struct {
	calls int
}

func (e *countingExecutor) Name() string {
	return "counting-test"
}

func (e *countingExecutor) Execute(context.Context, incidents.RemediationAction, incidents.Incident, bool) (remediationpkg.ExecutionOutcome, error) {
	e.calls++
	return remediationpkg.ExecutionOutcome{Status: remediationpkg.StateQueued}, nil
}

func signedSlackHeaders(secret string, body []byte, now time.Time) http.Header {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("v0:" + timestamp + ":"))
	_, _ = mac.Write(body)
	return http.Header{
		"X-Slack-Request-Timestamp": []string{timestamp},
		"X-Slack-Signature":         []string{"v0=" + hex.EncodeToString(mac.Sum(nil))},
	}
}

func insertFixture(t *testing.T, database *sql.DB, serviceID, incidentID, remediationID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `
		INSERT INTO services (id, name, tier, environment) VALUES ($1, $2, 'tier1', 'local')
	`, serviceID, "approval-test-"+serviceID); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, service_id, severity, status, dedupe_key, fingerprint, started_at
		) VALUES ($1, 'approval workflow test', $2, 'sev2', 'awaiting_approval', $3, $4, now())
	`, incidentID, serviceID, "dedupe-"+incidentID, "fingerprint-"+incidentID); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO remediation_actions (
			id, incident_id, action_type, target, status, risk, idempotency_key,
			proposed_by, policy_decision
		) VALUES ($1, $2, 'restart_service', 'payments-api', 'awaiting_approval',
		          'medium', $3, 'operator@local', '{"allow":true,"requires_approval":true}')
	`, remediationID, incidentID, "idem-"+remediationID); err != nil {
		t.Fatalf("insert remediation: %v", err)
	}
}

func cleanupFixture(database *sql.DB, approvalID, remediationID, incidentID, serviceID string) {
	ctx := context.Background()
	_, _ = database.ExecContext(ctx, `DELETE FROM approval_requests WHERE id = $1`, approvalID)
	_, _ = database.ExecContext(ctx, `DELETE FROM remediation_actions WHERE id = $1`, remediationID)
	_, _ = database.ExecContext(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID)
	_, _ = database.ExecContext(ctx, `DELETE FROM services WHERE id = $1`, serviceID)
}

func assertAuditChainValid(t *testing.T, database *sql.DB) {
	t.Helper()
	report, err := audit.NewService(database).Verify(context.Background())
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("approval workflow left an invalid audit chain: %+v", report)
	}
}
