package remediation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/rca"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Service struct {
	store   *incidents.Store
	auditor *audit.Service
	policy  *policy.Engine
	metrics *telemetry.Metrics
	exec    Executor
}

func NewService(store *incidents.Store, auditor *audit.Service, policyEngine *policy.Engine, queueClient *queue.Client, executor Executor, metrics *telemetry.Metrics) *Service {
	if executor == nil {
		executor = NewLocalExecutor(queueClient)
	}
	return &Service{
		store:   store,
		auditor: auditor,
		policy:  policyEngine,
		metrics: metrics,
		exec:    executor,
	}
}

func BuildIdempotencyKey(incidentID, actionType, target string, attempt int) string {
	return fmt.Sprintf("%s_%s_%s_%d", incidentID, actionType, target, attempt)
}

func (s *Service) Propose(ctx context.Context, incident incidents.Incident, candidates []rca.Candidate, actor string) ([]incidents.RemediationAction, error) {
	var actions []incidents.RemediationAction
	for _, candidate := range candidates {
		recentCount, err := s.store.CountRecentSimilarRemediations(ctx, incident.ID, candidate.ActionType, candidate.Target)
		if err != nil {
			return nil, err
		}

		var input policy.Input
		input.Actor.ID = actor
		input.Actor.Role = "operator"
		input.Incident.ID = incident.ID
		input.Incident.Severity = incident.Severity
		input.Incident.Service = incident.Service
		input.Incident.Environment = "local"
		input.Remediation.Type = candidate.ActionType
		input.Remediation.Target = candidate.Target
		input.Remediation.Risk = candidate.Risk
		input.Remediation.DryRun = true
		input.History.SameActionLast10m = recentCount
		input.History.FailedAttempts = 0

		decision := s.policy.Evaluate(input)
		if !decision.Allow {
			s.metrics.PolicyDenialsTotal.WithLabelValues(candidate.ActionType, decision.Reason).Inc()
		}

		status := "policy_blocked"
		if decision.Allow && decision.RequiresApproval {
			status = "awaiting_approval"
		}
		if decision.Allow && !decision.RequiresApproval {
			status = "approved"
		}

		action := incidents.RemediationAction{
			ID:             common.NewID("rem"),
			IncidentID:     incident.ID,
			ActionType:     candidate.ActionType,
			Target:         candidate.Target,
			Status:         status,
			Risk:           candidate.Risk,
			IdempotencyKey: BuildIdempotencyKey(incident.ID, candidate.ActionType, candidate.Target, recentCount+1),
			ProposedBy:     actor,
			PolicyDecision: map[string]any{
				"allow":             decision.Allow,
				"requires_approval": decision.RequiresApproval,
				"reason":            decision.Reason,
				"max_attempts":      decision.MaxAttempts,
			},
			DryRun:      true,
			Attempt:     recentCount + 1,
			MaxAttempts: decision.MaxAttempts,
			CreatedAt:   time.Now().UTC(),
		}

		if err := s.store.CreateRemediation(ctx, action); err != nil {
			return nil, err
		}
		actions = append(actions, action)
		s.metrics.RemediationsTotal.WithLabelValues(action.ActionType, action.Status).Inc()

		_ = s.auditor.Write(ctx, audit.Entry{
			ActorID:      actor,
			ActorType:    "user",
			Action:       "remediation.proposed",
			ResourceType: "remediation",
			ResourceID:   action.ID,
			AfterState: map[string]any{
				"status": action.Status,
				"risk":   action.Risk,
			},
			Metadata: action.PolicyDecision,
		})
	}

	if len(actions) > 0 {
		_ = s.store.UpdateIncidentStatus(ctx, incident.ID, incidents.StatusRemediationProposed)
	}

	return actions, nil
}

func (s *Service) Approve(ctx context.Context, remediationID, approvedBy string) error {
	if err := s.store.UpdateRemediationApproval(ctx, remediationID, "approved", approvedBy); err != nil {
		return err
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID:      approvedBy,
		ActorType:    "user",
		Action:       "remediation.approved",
		ResourceType: "remediation",
		ResourceID:   remediationID,
		AfterState: map[string]any{
			"status":      "approved",
			"approved_by": approvedBy,
		},
	})
}

func (s *Service) Reject(ctx context.Context, remediationID, rejectedBy string) error {
	if err := s.store.UpdateRemediationApproval(ctx, remediationID, "rejected", ""); err != nil {
		return err
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID:      rejectedBy,
		ActorType:    "user",
		Action:       "remediation.rejected",
		ResourceType: "remediation",
		ResourceID:   remediationID,
		AfterState: map[string]any{
			"status": "rejected",
		},
	})
}

func (s *Service) Cancel(ctx context.Context, remediationID, actor string) error {
	if err := s.store.UpdateRemediationApproval(ctx, remediationID, "cancelled", ""); err != nil {
		return err
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID:      actor,
		ActorType:    "user",
		Action:       "remediation.cancelled",
		ResourceType: "remediation",
		ResourceID:   remediationID,
		AfterState: map[string]any{
			"status": "cancelled",
		},
	})
}

func (s *Service) Execute(ctx context.Context, remediationID string, dryRun bool, actor string) error {
	remediation, err := s.store.GetRemediation(ctx, remediationID)
	if err != nil {
		return err
	}
	if remediation.Status == "succeeded" || remediation.Status == "running" || remediation.Status == "queued" {
		return nil
	}
	if remediation.Status == "awaiting_approval" {
		return fmt.Errorf("remediation requires approval")
	}
	if remediation.Status == "policy_blocked" || remediation.Status == "rejected" || remediation.Status == "cancelled" {
		return fmt.Errorf("remediation cannot be executed from state %s", remediation.Status)
	}

	incident, err := s.store.GetIncident(ctx, remediation.IncidentID)
	if err != nil {
		return err
	}

	outcome, err := s.exec.Execute(ctx, remediation, incident, dryRun)
	if err != nil {
		return err
	}

	switch outcome.Status {
	case "queued":
		if err := s.store.MarkRemediationQueued(ctx, remediationID, dryRun); err != nil {
			return err
		}
	case "running":
		if err := s.store.MarkRemediationQueued(ctx, remediationID, dryRun); err != nil {
			return err
		}
		if err := s.store.MarkRemediationRunning(ctx, remediationID); err != nil {
			return err
		}
	case "succeeded":
		if err := s.store.MarkRemediationQueued(ctx, remediationID, dryRun); err != nil {
			return err
		}
		if err := s.store.MarkRemediationRunning(ctx, remediationID); err != nil {
			return err
		}
		if err := s.store.CompleteRemediation(ctx, remediationID, "succeeded", outcome.Result, ""); err != nil {
			return err
		}
	case "failed":
		if err := s.store.CompleteRemediation(ctx, remediationID, "failed", outcome.Result, "executor reported failure"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown execution outcome status %q", outcome.Status)
	}

	action := "remediation.execute_requested"
	if strings.EqualFold(outcome.Status, "succeeded") {
		action = "remediation.completed"
	}
	return s.auditor.Write(ctx, audit.Entry{
		ActorID:      actor,
		ActorType:    "user",
		Action:       action,
		ResourceType: "remediation",
		ResourceID:   remediationID,
		AfterState: map[string]any{
			"status":   outcome.Status,
			"dry_run":  dryRun,
			"executor": s.exec.Name(),
			"result":   outcome.Result,
		},
	})
}
