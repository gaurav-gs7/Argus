package approvals

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Service struct {
	store         *Store
	notifier      Notifier
	metrics       *telemetry.Metrics
	logger        *slog.Logger
	timeout       time.Duration
	escalateAfter time.Duration
	sweepInterval time.Duration
	now           func() time.Time
	allowSelf     bool
}

func NewService(store *Store, notifier Notifier, metrics *telemetry.Metrics, logger *slog.Logger, timeout, escalateAfter, sweepInterval time.Duration, allowSelf bool) *Service {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	if escalateAfter <= 0 || escalateAfter >= timeout {
		escalateAfter = timeout / 2
	}
	if sweepInterval <= 0 {
		sweepInterval = 15 * time.Second
	}
	return &Service{
		store: store, notifier: notifier, metrics: metrics, logger: logger,
		timeout: timeout, escalateAfter: escalateAfter, sweepInterval: sweepInterval,
		now:       func() time.Time { return time.Now().UTC() },
		allowSelf: allowSelf,
	}
}

func (s *Service) RequestApproval(ctx context.Context, incident incidents.Incident, remediation incidents.RemediationAction) (Request, error) {
	now := s.now()
	request := Request{
		ID: common.NewID("apr"), RemediationID: remediation.ID, IncidentID: incident.ID,
		ActionType: remediation.ActionType, Target: remediation.Target, Risk: remediation.Risk,
		Status: StatusPending, RequestedBy: remediation.ProposedBy, RequestedAt: now,
		EscalatesAt: now.Add(s.escalateAfter), ExpiresAt: now.Add(s.timeout),
		NotificationStatus: "pending", CreatedAt: now, UpdatedAt: now,
	}
	stored, err := s.store.Create(ctx, request)
	if err != nil {
		return Request{}, err
	}
	if stored.ID != request.ID {
		return stored, nil
	}
	s.metrics.ApprovalRequestsTotal.WithLabelValues(StatusPending, s.notifier.Name()).Inc()
	s.metrics.ApprovalsPending.Inc()
	if err := s.notifier.Notify(ctx, stored, false); err != nil {
		s.metrics.ApprovalNotificationFailuresTotal.WithLabelValues(s.notifier.Name()).Inc()
		_ = s.store.MarkNotification(ctx, stored.ID, "failed", err.Error())
		s.logger.Warn("approval notification failed", "approval_id", stored.ID, "transport", s.notifier.Name(), "error", err)
		return stored, nil
	}
	status := "delivered"
	if s.notifier.Name() == "disabled" {
		status = "disabled"
	}
	_ = s.store.MarkNotification(ctx, stored.ID, status, "")
	stored.NotificationStatus = status
	stored.NotificationAttempts++
	return stored, nil
}

func (s *Service) DecideByRemediation(ctx context.Context, remediationID, actor, actorType, decision, reason string) (Request, error) {
	request, err := s.store.GetByRemediation(ctx, remediationID)
	if err != nil {
		return Request{}, err
	}
	return s.Decide(ctx, request.ID, actor, actorType, decision, reason, "api")
}

func (s *Service) CancelByRemediation(ctx context.Context, remediationID, actor, reason string) (Request, error) {
	if strings.TrimSpace(actor) == "" {
		return Request{}, fmt.Errorf("authenticated actor identity is required")
	}
	request, err := s.store.CancelByRemediation(ctx, remediationID, actor, strings.TrimSpace(reason), s.now())
	if err != nil {
		return Request{}, err
	}
	s.metrics.ApprovalsPending.Dec()
	s.metrics.ApprovalRequestsTotal.WithLabelValues(StatusCancelled, "api").Inc()
	return request, nil
}

func (s *Service) Decide(ctx context.Context, id, actor, actorType, decision, reason, source string) (Request, error) {
	decision = strings.ToLower(strings.TrimSpace(decision))
	reason = strings.TrimSpace(reason)
	if err := validateDecision(decision, reason, actor); err != nil {
		return Request{}, err
	}
	started := s.now()
	pending, err := s.store.Get(ctx, id)
	if err != nil {
		return Request{}, err
	}
	if err := validateSeparation(pending.RequestedBy, actor, s.allowSelf); err != nil {
		return Request{}, err
	}
	request, err := s.store.Decide(ctx, id, actor, actorType, decision, reason, source, started)
	if err != nil {
		return Request{}, err
	}
	s.metrics.ApprovalsPending.Dec()
	s.metrics.ApprovalRequestsTotal.WithLabelValues(request.Status, source).Inc()
	s.metrics.ApprovalDecisionDuration.Observe(started.Sub(request.RequestedAt).Seconds())
	return request, nil
}

func validateDecision(decision, reason, actor string) error {
	if decision != DecisionApprove && decision != DecisionDeny {
		return fmt.Errorf("decision must be approve or deny")
	}
	if strings.TrimSpace(actor) == "" || actor == "system" {
		return fmt.Errorf("authenticated approver identity is required")
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("decision reason is required")
	}
	return nil
}

func validateSeparation(requestedBy, actor string, allowSelf bool) error {
	if !allowSelf && strings.EqualFold(strings.TrimSpace(requestedBy), strings.TrimSpace(actor)) {
		return fmt.Errorf("proposer cannot approve or deny their own remediation")
	}
	return nil
}

func (s *Service) Get(ctx context.Context, id string) (Request, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) List(ctx context.Context, status string, limit int) ([]Request, error) {
	return s.store.List(ctx, status, limit)
}

func (s *Service) Start(ctx context.Context) {
	if count, err := s.store.CountPending(ctx); err != nil {
		s.logger.Warn("initialize pending approval metric", "error", err)
	} else {
		s.metrics.ApprovalsPending.Set(float64(count))
	}
	go func() {
		ticker := time.NewTicker(s.sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.processDue(ctx)
			}
		}
	}()
}

func (s *Service) processDue(ctx context.Context) {
	now := s.now()
	expired, err := s.store.ExpireDue(ctx, now, 100)
	if err != nil {
		s.logger.Error("expire approval requests", "error", err)
	} else {
		for range expired {
			s.metrics.ApprovalsPending.Dec()
			s.metrics.ApprovalRequestsTotal.WithLabelValues(StatusExpired, "controller").Inc()
		}
	}

	due, err := s.store.DueEscalations(ctx, now, 100)
	if err != nil {
		s.logger.Error("list approval escalations", "error", err)
		return
	}
	for _, request := range due {
		if err := s.notifier.Notify(ctx, request, true); err != nil {
			s.metrics.ApprovalNotificationFailuresTotal.WithLabelValues(s.notifier.Name()).Inc()
			_ = s.store.MarkNotification(ctx, request.ID, "escalation_failed", err.Error())
			continue
		}
		marked, err := s.store.MarkEscalated(ctx, request, now)
		if err != nil {
			s.logger.Error("mark approval escalation", "approval_id", request.ID, "error", err)
			continue
		}
		if marked {
			s.metrics.ApprovalEscalationsTotal.WithLabelValues(s.notifier.Name()).Inc()
		}
	}
}
