package remediation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/approvals"
	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/rca"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Service struct {
	store     *incidents.Store
	auditor   *audit.Service
	policy    *policy.Engine
	metrics   *telemetry.Metrics
	exec      Executor
	approvals approvals.Workflow
}

func NewService(store *incidents.Store, auditor *audit.Service, policyEngine *policy.Engine, queueClient *queue.Client, executor Executor, metrics *telemetry.Metrics, approvalWorkflow approvals.Workflow) *Service {
	if executor == nil {
		executor = NewLocalExecutor(queueClient)
	}
	return &Service{store: store, auditor: auditor, policy: policyEngine, metrics: metrics, exec: executor, approvals: approvalWorkflow}
}

func BuildIdempotencyKey(incidentID, actionType, target string, attempt int) string {
	return fmt.Sprintf("%s_%s_%s_%d", incidentID, actionType, target, attempt)
}

func (s *Service) Propose(ctx context.Context, incident incidents.Incident, candidates []rca.Candidate, actor, actorRole string) ([]incidents.RemediationAction, error) {
	var actions []incidents.RemediationAction
	awaitingApproval := false

	for _, candidate := range candidates {
		if existing, err := s.store.FindActiveRemediationByAction(ctx, incident.ID, candidate.ActionType, candidate.Target); err != nil {
			return nil, err
		} else if existing != nil {
			if existing.Status == StateAwaitingApproval && s.approvals != nil {
				if _, err := s.approvals.RequestApproval(ctx, incident, *existing); err != nil {
					return nil, err
				}
			}
			actions = append(actions, *existing)
			_ = s.auditor.Write(ctx, audit.Entry{
				ActorID: actor, ActorType: "user", Action: "remediation.proposal_reused", ResourceType: "remediation", ResourceID: existing.ID,
				AfterState: map[string]any{"status": existing.Status, "idempotency_key": existing.IdempotencyKey},
			})
			if existing.Status == StateAwaitingApproval {
				awaitingApproval = true
			}
			continue
		}

		recentCount, err := s.store.CountRecentSimilarRemediations(ctx, incident.ID, candidate.ActionType, candidate.Target)
		if err != nil {
			return nil, err
		}
		failedCount, err := s.store.CountFailedRemediations(ctx, incident.ID, candidate.ActionType, candidate.Target)
		if err != nil {
			return nil, err
		}

		var input policy.Input
		input.Actor.ID = actor
		input.Actor.Role = actorRole
		input.Incident.ID = incident.ID
		input.Incident.Severity = incident.Severity
		input.Incident.Service = incident.Service
		input.Incident.Environment = "local"
		input.Remediation.Type = candidate.ActionType
		input.Remediation.Target = candidate.Target
		input.Remediation.Risk = candidate.Risk
		input.Remediation.DryRun = true
		input.History.SameActionLast10m = recentCount
		input.History.FailedAttempts = failedCount

		decision := s.policy.Evaluate(input)
		if !decision.Allow {
			s.metrics.PolicyDenialsTotal.WithLabelValues(candidate.ActionType, decision.Reason).Inc()
		}

		status := StatePolicyBlocked
		if decision.Allow && decision.RequiresApproval {
			status = StateAwaitingApproval
			awaitingApproval = true
		}
		if decision.Allow && !decision.RequiresApproval {
			status = StateApproved
		}

		attempt := recentCount + 1
		action := incidents.RemediationAction{
			ID:             common.NewID("rem"),
			IncidentID:     incident.ID,
			ActionType:     candidate.ActionType,
			Target:         candidate.Target,
			Status:         status,
			Risk:           candidate.Risk,
			IdempotencyKey: BuildIdempotencyKey(incident.ID, candidate.ActionType, candidate.Target, attempt),
			ProposedBy:     actor,
			PolicyDecision: map[string]any{
				"allow":             decision.Allow,
				"requires_approval": decision.RequiresApproval,
				"reason":            decision.Reason,
				"max_attempts":      decision.MaxAttempts,
				"failed_attempts":   failedCount,
				"same_action_10m":   recentCount,
			},
			DryRun:      true,
			Attempt:     attempt,
			MaxAttempts: decision.MaxAttempts,
			CreatedAt:   time.Now().UTC(),
		}

		if err := s.store.CreateRemediation(ctx, action); err != nil {
			return nil, err
		}
		if action.Status == StateAwaitingApproval {
			if s.approvals == nil {
				return nil, fmt.Errorf("approval workflow is unavailable")
			}
			if _, err := s.approvals.RequestApproval(ctx, incident, action); err != nil {
				return nil, err
			}
		}
		actions = append(actions, action)
		s.metrics.RemediationsTotal.WithLabelValues(action.ActionType, action.Status).Inc()

		_ = s.auditor.Write(ctx, audit.Entry{
			ActorID: actor, ActorType: "user", Action: "remediation.proposed", ResourceType: "remediation", ResourceID: action.ID,
			AfterState: map[string]any{"status": action.Status, "risk": action.Risk, "idempotency_key": action.IdempotencyKey},
			Metadata:   action.PolicyDecision,
		})
	}

	if len(actions) > 0 {
		status := incidents.StatusRemediationProposed
		if awaitingApproval {
			status = incidents.StatusAwaitingApproval
		}
		_ = s.store.UpdateIncidentStatus(ctx, incident.ID, status)
	}
	return actions, nil
}

func (s *Service) Approve(ctx context.Context, remediationID, approvedBy, reason string) error {
	if s.approvals == nil {
		return fmt.Errorf("approval workflow is unavailable")
	}
	_, err := s.approvals.DecideByRemediation(ctx, remediationID, approvedBy, "user", approvals.DecisionApprove, reason)
	return err
}

func (s *Service) Reject(ctx context.Context, remediationID, rejectedBy, reason string) error {
	if s.approvals == nil {
		return fmt.Errorf("approval workflow is unavailable")
	}
	_, err := s.approvals.DecideByRemediation(ctx, remediationID, rejectedBy, "user", approvals.DecisionDeny, reason)
	return err
}

func (s *Service) Cancel(ctx context.Context, remediationID, actor string) error {
	rem, err := s.store.GetRemediation(ctx, remediationID)
	if err != nil {
		return err
	}
	if rem.Status == StateAwaitingApproval {
		if s.approvals == nil {
			return fmt.Errorf("approval workflow is unavailable")
		}
		_, err := s.approvals.CancelByRemediation(ctx, remediationID, actor, "remediation cancelled by operator")
		return err
	}
	if err := RequireTransition(rem.Status, StateCancelled); err != nil {
		return err
	}
	if err := s.store.UpdateRemediationApproval(ctx, remediationID, StateCancelled, ""); err != nil {
		return err
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID: actor, ActorType: "user", Action: "remediation.cancelled", ResourceType: "remediation", ResourceID: remediationID,
		BeforeState: map[string]any{"status": rem.Status},
		AfterState:  map[string]any{"status": StateCancelled},
	})
}

func (s *Service) Execute(ctx context.Context, remediationID string, dryRun bool, actor string) error {
	remediation, err := s.store.GetRemediation(ctx, remediationID)
	if err != nil {
		return err
	}
	if remediation.Status == StateSucceeded || remediation.Status == StateQueued || remediation.Status == StateRunning {
		_ = s.auditor.Write(ctx, audit.Entry{
			ActorID: actor, ActorType: "user", Action: "remediation.execution_reused", ResourceType: "remediation", ResourceID: remediationID,
			AfterState: map[string]any{"status": remediation.Status, "idempotency_key": remediation.IdempotencyKey},
		})
		return nil
	}
	if remediation.Status == StateAwaitingApproval {
		return fmt.Errorf("remediation requires approval")
	}
	if IsTerminalState(remediation.Status) {
		return fmt.Errorf("remediation cannot be executed from state %s", remediation.Status)
	}
	if err := RequireTransition(remediation.Status, StateQueued); err != nil {
		return err
	}

	incident, err := s.store.GetIncident(ctx, remediation.IncidentID)
	if err != nil {
		return err
	}

	start := time.Now()
	outcome, err := s.exec.Execute(ctx, remediation, incident, dryRun)
	if err != nil {
		return err
	}

	if err := s.applyOutcome(ctx, remediation, outcome, dryRun); err != nil {
		return err
	}
	if strings.EqualFold(outcome.Status, StateFailed) {
		s.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
	}
	s.metrics.RemediationDuration.WithLabelValues(remediation.ActionType).Observe(time.Since(start).Seconds())

	action := "remediation.execute_requested"
	if strings.EqualFold(outcome.Status, StateSucceeded) {
		action = "remediation.completed"
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID: actor, ActorType: "user", Action: action, ResourceType: "remediation", ResourceID: remediationID,
		BeforeState: map[string]any{"status": remediation.Status},
		AfterState:  map[string]any{"status": outcome.Status, "dry_run": dryRun, "executor": s.exec.Name(), "result": outcome.Result},
	})
}

func (s *Service) applyOutcome(ctx context.Context, remediation incidents.RemediationAction, outcome ExecutionOutcome, dryRun bool) error {
	switch outcome.Status {
	case StateQueued:
		return s.store.MarkRemediationQueued(ctx, remediation.ID, dryRun)
	case StateRunning:
		if err := s.store.MarkRemediationQueued(ctx, remediation.ID, dryRun); err != nil {
			return err
		}
		return s.store.MarkRemediationRunning(ctx, remediation.ID)
	case StateSucceeded:
		if err := s.store.MarkRemediationQueued(ctx, remediation.ID, dryRun); err != nil {
			return err
		}
		if err := s.store.MarkRemediationRunning(ctx, remediation.ID); err != nil {
			return err
		}
		return s.store.CompleteRemediation(ctx, remediation.ID, StateSucceeded, outcome.Result, "")
	case StateFailed:
		return s.store.CompleteRemediation(ctx, remediation.ID, StateFailed, outcome.Result, "executor reported failure")
	default:
		return fmt.Errorf("unknown execution outcome status %q", outcome.Status)
	}
}
