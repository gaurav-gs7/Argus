package approvals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
)

var (
	ErrNotFound       = errors.New("approval request not found")
	ErrAlreadyDecided = errors.New("approval request is no longer pending")
	ErrExpired        = errors.New("approval request has expired")
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Create(ctx context.Context, request Request) (Request, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, fmt.Errorf("begin approval request: %w", err)
	}
	defer tx.Rollback()

	existing, err := getByRemediation(ctx, tx, request.RemediationID, false)
	if err == nil {
		return existing, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return Request{}, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO approval_requests (
			id, remediation_id, incident_id, action_type, target, risk, status,
			requested_by, requested_at, escalates_at, expires_at,
			notification_status, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	`, request.ID, request.RemediationID, request.IncidentID, request.ActionType, request.Target,
		request.Risk, request.Status, request.RequestedBy, request.RequestedAt,
		request.EscalatesAt, request.ExpiresAt, request.NotificationStatus,
		request.CreatedAt, request.UpdatedAt)
	if err != nil {
		_ = tx.Rollback()
		existing, getErr := s.GetByRemediation(ctx, request.RemediationID)
		if getErr == nil {
			return existing, nil
		}
		return Request{}, fmt.Errorf("insert approval request: %w", err)
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID:      request.RequestedBy,
		ActorType:    "user",
		Action:       "approval.requested",
		ResourceType: "approval_request",
		ResourceID:   request.ID,
		AfterState: map[string]any{
			"status": request.Status, "remediation_id": request.RemediationID,
			"action_type": request.ActionType, "target": request.Target,
			"risk": request.Risk, "expires_at": request.ExpiresAt,
		},
	}); err != nil {
		return Request{}, err
	}
	if err := tx.Commit(); err != nil {
		return Request{}, fmt.Errorf("commit approval request: %w", err)
	}
	return request, nil
}

func (s *Store) Get(ctx context.Context, id string) (Request, error) {
	return scanRequest(s.db.QueryRowContext(ctx, approvalSelect+` WHERE id = $1`, id))
}

func (s *Store) GetByRemediation(ctx context.Context, remediationID string) (Request, error) {
	return getByRemediation(ctx, s.db, remediationID, false)
}

func (s *Store) List(ctx context.Context, status string, limit int) ([]Request, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := approvalSelect
	args := []any{}
	if strings.TrimSpace(status) != "" {
		query += ` WHERE status = $1 ORDER BY created_at DESC LIMIT $2`
		args = append(args, status, limit)
	} else {
		query += ` ORDER BY created_at DESC LIMIT $1`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list approval requests: %w", err)
	}
	defer rows.Close()
	var requests []Request
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *Store) Decide(ctx context.Context, id, actor, actorType, decision, reason, source string, now time.Time) (Request, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, fmt.Errorf("begin approval decision: %w", err)
	}
	defer tx.Rollback()

	request, err := scanRequest(tx.QueryRowContext(ctx, approvalSelect+` WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return Request{}, err
	}
	if request.Status != StatusPending {
		return Request{}, ErrAlreadyDecided
	}
	if !now.Before(request.ExpiresAt) {
		if err := expireTx(ctx, tx, request, now); err != nil {
			return Request{}, err
		}
		if err := tx.Commit(); err != nil {
			return Request{}, fmt.Errorf("commit expired approval: %w", err)
		}
		return Request{}, ErrExpired
	}

	status := StatusDenied
	remediationStatus := "rejected"
	auditAction := "approval.denied"
	if decision == DecisionApprove {
		status = StatusApproved
		remediationStatus = "approved"
		auditAction = "approval.approved"
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE approval_requests
		SET status = $2, decided_at = $3, decided_by = $4, decision_reason = $5,
		    decision_source = $6, updated_at = $3
		WHERE id = $1
	`, id, status, now, actor, reason, source)
	if err != nil {
		return Request{}, fmt.Errorf("record approval decision: %w", err)
	}
	approvedBy := ""
	if decision == DecisionApprove {
		approvedBy = actor
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE remediation_actions
		SET status = $2, approved_by = NULLIF($3, '')
		WHERE id = $1 AND status = 'awaiting_approval'
	`, request.RemediationID, remediationStatus, approvedBy)
	if err != nil {
		return Request{}, fmt.Errorf("transition approved remediation: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return Request{}, fmt.Errorf("remediation is no longer awaiting approval")
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID:      actor,
		ActorType:    actorType,
		Action:       auditAction,
		ResourceType: "approval_request",
		ResourceID:   request.ID,
		BeforeState:  map[string]any{"status": StatusPending},
		AfterState: map[string]any{
			"status": status, "remediation_id": request.RemediationID,
			"remediation_status": remediationStatus, "decided_by": actor,
			"reason": reason, "source": source,
		},
	}); err != nil {
		return Request{}, err
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID:      actor,
		ActorType:    actorType,
		Action:       "remediation." + remediationStatus,
		ResourceType: "remediation",
		ResourceID:   request.RemediationID,
		BeforeState:  map[string]any{"status": "awaiting_approval"},
		AfterState: map[string]any{
			"status": remediationStatus, "approval_request_id": request.ID,
			"decision_reason": reason, "decision_source": source,
		},
	}); err != nil {
		return Request{}, err
	}
	if err := tx.Commit(); err != nil {
		return Request{}, fmt.Errorf("commit approval decision: %w", err)
	}
	request.Status = status
	request.DecidedAt = &now
	request.DecidedBy = actor
	request.DecisionReason = reason
	request.DecisionSource = source
	request.UpdatedAt = now
	return request, nil
}

func (s *Store) CancelByRemediation(ctx context.Context, remediationID, actor, reason string, now time.Time) (Request, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, fmt.Errorf("begin approval cancellation: %w", err)
	}
	defer tx.Rollback()
	request, err := getByRemediation(ctx, tx, remediationID, true)
	if err != nil {
		return Request{}, err
	}
	if request.Status != StatusPending {
		return Request{}, ErrAlreadyDecided
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE approval_requests
		SET status = 'cancelled', decided_at = $2, decided_by = $3,
		    decision_reason = $4, decision_source = 'api', updated_at = $2
		WHERE id = $1
	`, request.ID, now, actor, reason); err != nil {
		return Request{}, fmt.Errorf("cancel approval request: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE remediation_actions SET status = 'cancelled'
		WHERE id = $1 AND status = 'awaiting_approval'
	`, remediationID)
	if err != nil {
		return Request{}, fmt.Errorf("cancel remediation awaiting approval: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return Request{}, fmt.Errorf("remediation is no longer awaiting approval")
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID: actor, ActorType: "user", Action: "approval.cancelled",
		ResourceType: "approval_request", ResourceID: request.ID,
		BeforeState: map[string]any{"status": StatusPending},
		AfterState:  map[string]any{"status": StatusCancelled, "reason": reason},
		Metadata:    map[string]any{"remediation_id": remediationID},
	}); err != nil {
		return Request{}, err
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID: actor, ActorType: "user", Action: "remediation.cancelled",
		ResourceType: "remediation", ResourceID: remediationID,
		BeforeState: map[string]any{"status": "awaiting_approval"},
		AfterState:  map[string]any{"status": "cancelled", "approval_request_id": request.ID},
	}); err != nil {
		return Request{}, err
	}
	if err := tx.Commit(); err != nil {
		return Request{}, fmt.Errorf("commit approval cancellation: %w", err)
	}
	request.Status = StatusCancelled
	request.DecidedAt = &now
	request.DecidedBy = actor
	request.DecisionReason = reason
	request.DecisionSource = "api"
	request.UpdatedAt = now
	return request, nil
}

func (s *Store) CountPending(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM approval_requests WHERE status = 'pending'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending approvals: %w", err)
	}
	return count, nil
}

func (s *Store) MarkNotification(ctx context.Context, id, status, message string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE approval_requests
		SET notification_status = $2, notification_attempts = notification_attempts + 1,
		    last_notification_error = NULLIF($3, ''), updated_at = now()
		WHERE id = $1
	`, id, status, message)
	if err != nil {
		return fmt.Errorf("update approval notification: %w", err)
	}
	return nil
}

func (s *Store) DueEscalations(ctx context.Context, now time.Time, limit int) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, approvalSelect+`
		WHERE status = 'pending' AND escalated_at IS NULL AND escalates_at <= $1
		ORDER BY escalates_at LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due approval escalations: %w", err)
	}
	defer rows.Close()
	var requests []Request
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *Store) MarkEscalated(ctx context.Context, request Request, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE approval_requests SET escalated_at = $2, updated_at = $2
		WHERE id = $1 AND status = 'pending' AND escalated_at IS NULL
	`, request.ID, now)
	if err != nil {
		return false, fmt.Errorf("mark approval escalated: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return false, nil
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID: "approval-controller", ActorType: "system", Action: "approval.escalated",
		ResourceType: "approval_request", ResourceID: request.ID,
		BeforeState: map[string]any{"status": StatusPending, "escalated_at": nil},
		AfterState:  map[string]any{"status": StatusPending, "escalated_at": now},
		Metadata:    map[string]any{"remediation_id": request.RemediationID},
	}); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) ExpireDue(ctx context.Context, now time.Time, limit int) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, approvalSelect+`
		WHERE status = 'pending' AND expires_at <= $1
		ORDER BY expires_at LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list expired approvals: %w", err)
	}
	defer rows.Close()
	var due []Request
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		due = append(due, request)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var expired []Request
	for _, request := range due {
		ok, err := s.expire(ctx, request, now)
		if err != nil {
			return expired, err
		}
		if ok {
			request.Status = StatusExpired
			request.UpdatedAt = now
			expired = append(expired, request)
		}
	}
	return expired, nil
}

func (s *Store) expire(ctx context.Context, request Request, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE approval_requests SET status = 'expired', updated_at = $2
		WHERE id = $1 AND status = 'pending'
	`, request.ID, now)
	if err != nil {
		return false, fmt.Errorf("expire approval request: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return false, nil
	}
	if err := expireRemediationAndAudit(ctx, tx, request, now); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func expireTx(ctx context.Context, tx *sql.Tx, request Request, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE approval_requests SET status = 'expired', updated_at = $2
		WHERE id = $1 AND status = 'pending'
	`, request.ID, now)
	if err != nil {
		return fmt.Errorf("expire approval request: %w", err)
	}
	return expireRemediationAndAudit(ctx, tx, request, now)
}

func expireRemediationAndAudit(ctx context.Context, tx *sql.Tx, request Request, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE remediation_actions SET status = 'timed_out'
		WHERE id = $1 AND status = 'awaiting_approval'
	`, request.RemediationID); err != nil {
		return fmt.Errorf("time out remediation approval: %w", err)
	}
	if err := writeAuditTx(ctx, tx, audit.Entry{
		ActorID: "approval-controller", ActorType: "system", Action: "approval.expired",
		ResourceType: "approval_request", ResourceID: request.ID,
		BeforeState: map[string]any{"status": StatusPending},
		AfterState:  map[string]any{"status": StatusExpired, "expired_at": now},
		Metadata:    map[string]any{"remediation_id": request.RemediationID},
	}); err != nil {
		return err
	}
	return writeAuditTx(ctx, tx, audit.Entry{
		ActorID: "approval-controller", ActorType: "system", Action: "remediation.approval_timed_out",
		ResourceType: "remediation", ResourceID: request.RemediationID,
		BeforeState: map[string]any{"status": "awaiting_approval"},
		AfterState:  map[string]any{"status": "timed_out", "approval_request_id": request.ID},
	})
}

const approvalSelect = `
	SELECT id, remediation_id, incident_id, action_type, target, risk, status,
	       requested_by, requested_at, escalates_at, expires_at, escalated_at,
	       decided_at, COALESCE(decided_by, ''), COALESCE(decision_reason, ''),
	       COALESCE(decision_source, ''), notification_status, notification_attempts,
	       COALESCE(last_notification_error, ''), created_at, updated_at
	FROM approval_requests`

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type scanner interface {
	Scan(...any) error
}

func getByRemediation(ctx context.Context, db queryRower, remediationID string, forUpdate bool) (Request, error) {
	query := approvalSelect + ` WHERE remediation_id = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	return scanRequest(db.QueryRowContext(ctx, query, remediationID))
}

func scanRequest(row scanner) (Request, error) {
	var request Request
	err := row.Scan(
		&request.ID, &request.RemediationID, &request.IncidentID, &request.ActionType,
		&request.Target, &request.Risk, &request.Status, &request.RequestedBy,
		&request.RequestedAt, &request.EscalatesAt, &request.ExpiresAt,
		&request.EscalatedAt, &request.DecidedAt, &request.DecidedBy,
		&request.DecisionReason, &request.DecisionSource, &request.NotificationStatus,
		&request.NotificationAttempts, &request.LastNotificationError,
		&request.CreatedAt, &request.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("scan approval request: %w", err)
	}
	return request, nil
}

func writeAuditTx(ctx context.Context, tx *sql.Tx, entry audit.Entry) error {
	if err := audit.WriteTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("write approval audit log: %w", err)
	}
	return nil
}
