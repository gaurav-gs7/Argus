package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	store      *incidents.Store
	auditor    *audit.Service
	policy     *policy.Engine
	metrics    *telemetry.Metrics
	exec       Executor
	approvals  approvals.Workflow
	dispatcher *Dispatcher
}

// NewService builds the remediation service. With the local executor (the
// default) and a queue client, it also builds the outbox Dispatcher that
// publishes jobs; run it with Dispatcher().Run.
func NewService(store *incidents.Store, auditor *audit.Service, policyEngine *policy.Engine, queueClient *queue.Client, executor Executor, metrics *telemetry.Metrics, approvalWorkflow approvals.Workflow) *Service {
	if executor == nil {
		executor = NewLocalExecutor()
	}
	s := &Service{store: store, auditor: auditor, policy: policyEngine, metrics: metrics, exec: executor, approvals: approvalWorkflow}
	if queueClient != nil && isQueued(executor) {
		s.dispatcher = NewDispatcher(store, auditor, queueClient, metrics, nil, DispatcherConfig{})
	}
	return s
}

// UseDispatcher replaces the outbox dispatcher (configuration, tests).
func (s *Service) UseDispatcher(d *Dispatcher) { s.dispatcher = d }

// Dispatcher returns the outbox dispatcher, or nil when the executor does
// not dispatch through JetStream.
func (s *Service) Dispatcher() *Dispatcher { return s.dispatcher }

func firstNonEmptyRisk(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "medium"
}

func BuildIdempotencyKey(incidentID, actionType, target string, attempt int, parameters ...map[string]any) string {
	base := fmt.Sprintf("%s_%s_%s_%d", incidentID, actionType, target, attempt)
	if len(parameters) == 0 || len(parameters[0]) == 0 {
		return base
	}
	encoded, _ := json.Marshal(parameters[0])
	sum := sha256.Sum256(encoded)
	return base + "_" + hex.EncodeToString(sum[:6])
}

func (s *Service) Propose(ctx context.Context, incident incidents.Incident, candidates []rca.Candidate, actor, actorRole string) ([]incidents.RemediationAction, error) {
	var actions []incidents.RemediationAction
	awaitingApproval := false

	for _, candidate := range candidates {
		if candidate.Parameters == nil {
			candidate.Parameters = map[string]any{}
		}
		if existing, err := s.store.FindActiveRemediationByAction(ctx, incident.ID, candidate.ActionType, candidate.Target, candidate.Parameters); err != nil {
			return nil, err
		} else if existing != nil {
			if existing.Status == StateAwaitingApproval && s.approvals != nil {
				if _, err := s.approvals.RequestApproval(ctx, incident, *existing); err != nil {
					return nil, err
				}
			}
			actions = append(actions, *existing)
			s.auditor.Record(ctx, audit.Entry{
				ActorID: actor, ActorType: "user", Action: "remediation.proposal_reused", ResourceType: "remediation", ResourceID: existing.ID,
				AfterState: map[string]any{"status": existing.Status, "idempotency_key": existing.IdempotencyKey},
			})
			if existing.Status == StateAwaitingApproval {
				awaitingApproval = true
			}
			continue
		}

		recentCount, err := s.store.CountRecentSimilarRemediations(ctx, incident.ID, candidate.ActionType, candidate.Target, candidate.Parameters)
		if err != nil {
			return nil, err
		}
		failedCount, err := s.store.CountFailedRemediations(ctx, incident.ID, candidate.ActionType, candidate.Target, candidate.Parameters)
		if err != nil {
			return nil, err
		}

		var input policy.Input
		input.Actor.ID = actor
		input.Actor.Role = actorRole
		input.Incident.ID = incident.ID
		input.Incident.Severity = incident.Severity
		input.Incident.Service = incident.Service
		input.Incident.Environment = incident.Environment
		input.Remediation.Type = candidate.ActionType
		input.Remediation.Target = candidate.Target
		input.Remediation.Risk = candidate.Risk
		input.Remediation.DryRun = true
		input.Remediation.Parameters = candidate.Parameters
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
			Parameters:     candidate.Parameters,
			Status:         status,
			Risk:           firstNonEmptyRisk(decision.Risk, candidate.Risk),
			IdempotencyKey: BuildIdempotencyKey(incident.ID, candidate.ActionType, candidate.Target, attempt, candidate.Parameters),
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

		if err := s.store.InTx(ctx, func(tx *incidents.Store) error {
			if err := tx.CreateRemediation(ctx, action); err != nil {
				return err
			}
			return audit.WriteTx(ctx, tx.Tx(), audit.Entry{
				ActorID: actor, ActorType: "user", Action: "remediation.proposed", ResourceType: "remediation", ResourceID: action.ID,
				AfterState: map[string]any{"status": action.Status, "risk": action.Risk, "idempotency_key": action.IdempotencyKey},
				Metadata:   action.PolicyDecision,
			})
		}); err != nil {
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
	}

	if len(actions) > 0 {
		status := incidents.StatusRemediationProposed
		if awaitingApproval {
			status = incidents.StatusAwaitingApproval
		}
		// Advance only; an incident already further along keeps its status.
		_, _, _ = s.store.TransitionIncident(ctx, incident.ID, status)
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
	cancelled := false
	err = s.store.InTx(ctx, func(tx *incidents.Store) error {
		ok, err := tx.CancelRemediation(ctx, remediationID, rem.Status)
		if err != nil || !ok {
			return err
		}
		cancelled = true
		return audit.WriteTx(ctx, tx.Tx(), audit.Entry{
			ActorID: actor, ActorType: "user", Action: "remediation.cancelled", ResourceType: "remediation", ResourceID: remediationID,
			BeforeState: map[string]any{"status": rem.Status},
			AfterState:  map[string]any{"status": StateCancelled},
		})
	})
	if err != nil {
		return err
	}
	if !cancelled {
		latest, getErr := s.store.GetRemediation(ctx, remediationID)
		if getErr != nil {
			return getErr
		}
		return fmt.Errorf("%w: remediation moved from %s to %s before it could be cancelled", ErrStateChanged, rem.Status, latest.Status)
	}
	return nil
}

func (s *Service) Execute(ctx context.Context, remediationID string, dryRun bool, actor string) (bool, error) {
	remediation, err := s.store.GetRemediation(ctx, remediationID)
	if err != nil {
		return false, err
	}
	if remediation.Status == StateSucceeded || remediation.Status == StateQueued || remediation.Status == StateRunning {
		s.auditor.Record(ctx, audit.Entry{
			ActorID: actor, ActorType: "user", Action: "remediation.execution_reused", ResourceType: "remediation", ResourceID: remediationID,
			AfterState: map[string]any{"status": remediation.Status, "idempotency_key": remediation.IdempotencyKey},
		})
		return true, nil
	}
	if remediation.Status == StateAwaitingApproval {
		return false, fmt.Errorf("remediation requires approval")
	}
	if IsTerminalState(remediation.Status) {
		return false, fmt.Errorf("remediation cannot be executed from state %s", remediation.Status)
	}
	if err := RequireTransition(remediation.Status, StateQueued); err != nil {
		return false, err
	}

	incident, err := s.store.GetIncident(ctx, remediation.IncidentID)
	if err != nil {
		return false, err
	}
	if incidents.IsClosed(incident.Status) {
		return false, fmt.Errorf("%w: incident %s is %s", ErrIncidentClosed, incident.ID, incident.Status)
	}

	start := time.Now()
	queued := isQueued(s.exec)
	// Reserve execution before dispatch so concurrent callers and fast workers
	// cannot race the persisted mode or enqueue the same action twice. The
	// reservation, its audit entry and (for queued executors) the outbox job
	// commit together, so a crash after this point cannot strand the
	// remediation in queued without a job to publish.
	var queuedAt time.Time
	var dispatchID string
	err = s.store.InTx(ctx, func(tx *incidents.Store) error {
		reservedAt, err := tx.MarkRemediationQueued(ctx, remediation.ID, dryRun)
		if err != nil {
			return err
		}
		queuedAt = reservedAt
		after := map[string]any{"status": StateQueued, "dry_run": dryRun, "executor": s.exec.Name()}
		if queued {
			reserved := remediation
			reserved.QueuedAt, reserved.DryRun = &queuedAt, dryRun
			dispatchID = reservationEventID(reserved)
			if err := Enqueue(ctx, tx.Tx(), reserved, dispatchID, DispatchExecute); err != nil {
				return err
			}
			after["dispatch_id"] = dispatchID
		}
		return audit.WriteTx(ctx, tx.Tx(), audit.Entry{
			ActorID: actor, ActorType: "user", Action: "remediation.execute_requested", ResourceType: "remediation", ResourceID: remediationID,
			BeforeState: map[string]any{"status": remediation.Status},
			AfterState:  after,
		})
	})
	if err != nil {
		latest, getErr := s.store.GetRemediation(ctx, remediation.ID)
		if getErr == nil && (latest.Status == StateQueued || latest.Status == StateRunning || latest.Status == StateSucceeded) {
			s.auditor.Record(ctx, audit.Entry{
				ActorID: actor, ActorType: "user", Action: "remediation.execution_reused", ResourceType: "remediation", ResourceID: remediationID,
				AfterState: map[string]any{"status": latest.Status, "idempotency_key": latest.IdempotencyKey},
			})
			return true, nil
		}
		return false, err
	}
	remediation.QueuedAt = &queuedAt
	remediation.DryRun = dryRun
	if queued {
		// Publish now so the usual path has no poll delay. If JetStream is
		// unavailable the job stays in the outbox and the dispatcher keeps
		// retrying; the remediation is durably queued either way.
		if s.dispatcher != nil {
			_ = s.dispatcher.PublishOne(ctx, dispatchID)
		}
		s.metrics.RemediationDuration.WithLabelValues(remediation.ActionType).Observe(time.Since(start).Seconds())
		return false, nil
	}
	outcome, err := s.exec.Execute(ctx, remediation, incident, dryRun)
	if err != nil {
		if releaseErr := s.store.InTx(ctx, func(tx *incidents.Store) error {
			if err := tx.ReleaseRemediationQueueReservation(ctx, remediation.ID); err != nil {
				return err
			}
			return audit.WriteTx(ctx, tx.Tx(), audit.Entry{
				ActorID: actor, ActorType: "user", Action: "remediation.dispatch_failed", ResourceType: "remediation", ResourceID: remediationID,
				BeforeState: map[string]any{"status": StateQueued},
				AfterState:  map[string]any{"status": StateApproved, "error": err.Error()},
			})
		}); releaseErr != nil {
			return false, fmt.Errorf("%w (releasing the reservation also failed: %v)", err, releaseErr)
		}
		return false, err
	}

	if err := s.applyQueuedOutcome(ctx, remediation, outcome, actor); err != nil {
		return false, err
	}
	if strings.EqualFold(outcome.Status, StateFailed) {
		s.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
	}
	s.metrics.RemediationDuration.WithLabelValues(remediation.ActionType).Observe(time.Since(start).Seconds())
	return false, nil
}

// ErrIncidentClosed reports an attempt to dispatch remediation for a resolved
// or cancelled incident.
var ErrIncidentClosed = errors.New("incident is closed")

// ErrStateChanged reports that a remediation moved to another state while a
// conditional transition was in flight.
var ErrStateChanged = errors.New("remediation state changed")

func requireApplied(applied bool, err error) error {
	if err != nil {
		return err
	}
	if !applied {
		return ErrStateChanged
	}
	return nil
}

// applyQueuedOutcome records what a synchronous executor (Helios) reported.
// The local executor only queues, which needs no further change. Each
// transition commits with its audit entry.
func (s *Service) applyQueuedOutcome(ctx context.Context, remediation incidents.RemediationAction, outcome ExecutionOutcome, actor string) error {
	entry := audit.Entry{
		ActorID: actor, ActorType: "user", ResourceType: "remediation", ResourceID: remediation.ID,
		BeforeState: map[string]any{"status": StateQueued},
		AfterState:  map[string]any{"status": outcome.Status, "executor": s.exec.Name(), "result": outcome.Result},
	}
	switch outcome.Status {
	case StateQueued:
		return nil
	case StateRunning:
		entry.Action = "remediation.running"
		// Persist the executor's result (for Helios, the workflow id) so the
		// reconciler can follow the workflow to its final state.
		return s.store.InTx(ctx, func(tx *incidents.Store) error {
			if err := requireApplied(tx.MarkRemediationRunning(ctx, remediation.ID, outcome.Result)); err != nil {
				return err
			}
			return audit.WriteTx(ctx, tx.Tx(), entry)
		})
	case StateSucceeded:
		entry.Action = "remediation.completed"
		return s.store.InTx(ctx, func(tx *incidents.Store) error {
			if err := requireApplied(tx.ClaimRemediation(ctx, remediation.ID)); err != nil {
				return err
			}
			if err := requireApplied(tx.CompleteRemediation(ctx, remediation.ID, StateSucceeded, outcome.Result, "")); err != nil {
				return err
			}
			return audit.WriteTx(ctx, tx.Tx(), entry)
		})
	case StateFailed:
		entry.Action = "remediation.failed"
		return s.store.InTx(ctx, func(tx *incidents.Store) error {
			if err := requireApplied(tx.CompleteRemediation(ctx, remediation.ID, StateFailed, outcome.Result, "executor reported failure")); err != nil {
				return err
			}
			return audit.WriteTx(ctx, tx.Tx(), entry)
		})
	default:
		return fmt.Errorf("unknown execution outcome status %q", outcome.Status)
	}
}
