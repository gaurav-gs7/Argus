package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/incidents"
)

// HeliosReconcileConfig bounds the Helios reconciler. Zero fields take
// defaults.
type HeliosReconcileConfig struct {
	// Interval is how often the reconciler runs.
	Interval time.Duration
	// MaxRuntime is how long a Helios workflow may run before Argus cancels
	// it and marks the remediation timed_out.
	MaxRuntime time.Duration
	// SubmitLostAfter is how long a remediation may stay queued with no
	// workflow recorded before the reconciler assumes the submitting process
	// died. It must exceed one submission (HTTP timeout plus poll timeout).
	SubmitLostAfter time.Duration
}

func DefaultHeliosReconcileConfig() HeliosReconcileConfig {
	return HeliosReconcileConfig{Interval: 30 * time.Second, MaxRuntime: 30 * time.Minute, SubmitLostAfter: 2 * time.Minute}
}

// HeliosReconcileResult reports one pass.
type HeliosReconcileResult struct {
	Succeeded, Failed, TimedOut, Adopted, Resubmitted, Errors []string
}

// RunHeliosReconciler reconciles every Interval until ctx ends. It does
// nothing unless the executor is Helios.
func (s *Service) RunHeliosReconciler(ctx context.Context, cfg HeliosReconcileConfig, logger *slog.Logger) {
	if _, ok := s.exec.(*HeliosExecutor); !ok {
		return
	}
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := s.ReconcileHelios(ctx, cfg)
			if err != nil && ctx.Err() == nil {
				logger.Error("reconcile Helios workflows", "error", err)
			}
			if len(result.Errors) > 0 {
				logger.Warn("could not reach Helios for some remediations", "remediations", result.Errors)
			}
		}
	}
}

func (c HeliosReconcileConfig) withDefaults() HeliosReconcileConfig {
	def := DefaultHeliosReconcileConfig()
	if c.Interval <= 0 {
		c.Interval = def.Interval
	}
	if c.MaxRuntime <= 0 {
		c.MaxRuntime = def.MaxRuntime
	}
	if c.SubmitLostAfter <= 0 {
		c.SubmitLostAfter = def.SubmitLostAfter
	}
	return c
}

// ReconcileHelios settles remediations the Helios executor left unfinished:
//
//   - running with a recorded workflow (the executor's poll ended before the
//     workflow did): follow the workflow to succeeded, failed or cancelled,
//     and cancel it and mark timed_out after MaxRuntime;
//   - queued with no workflow recorded for SubmitLostAfter (the process that
//     submitted it died mid-call): adopt the workflow if Helios has one
//     labelled with the remediation id, otherwise submit it again. Helios
//     tasks carry the remediation's idempotency key, so a repeat submission
//     cannot repeat the side effect.
//
// One replica reconciles at a time.
func (s *Service) ReconcileHelios(ctx context.Context, cfg HeliosReconcileConfig) (HeliosReconcileResult, error) {
	var result HeliosReconcileResult
	helios, ok := s.exec.(*HeliosExecutor)
	if !ok {
		return result, nil
	}
	cfg = cfg.withDefaults()
	err := s.store.InTx(ctx, func(tx *incidents.Store) error {
		var locked bool
		if err := tx.Tx().QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('argus_helios_reconcile'))`).Scan(&locked); err != nil || !locked {
			return err
		}
		txs := *s
		txs.store = tx
		if err := txs.settleRunningHelios(ctx, helios, cfg, &result); err != nil {
			return err
		}
		return txs.recoverLostHeliosSubmissions(ctx, helios, cfg, &result)
	})
	if s.metrics != nil {
		for label, ids := range map[string][]string{
			"succeeded": result.Succeeded, "failed": result.Failed, "timed_out": result.TimedOut,
			"adopted": result.Adopted, "resubmitted": result.Resubmitted, "error": result.Errors,
		} {
			s.metrics.HeliosReconciliationsTotal.WithLabelValues(label).Add(float64(len(ids)))
		}
	}
	return result, err
}

type runningHelios struct {
	id, workflowID string
	result         map[string]any
	overdue        bool
}

func (s *Service) settleRunningHelios(ctx context.Context, helios *HeliosExecutor, cfg HeliosReconcileConfig, result *HeliosReconcileResult) error {
	rows, err := s.store.Tx().QueryContext(ctx, `
		SELECT id, result->>'helios_workflow_id', result::text, started_at < now() - make_interval(secs => $1)
		FROM remediation_actions
		WHERE status = 'running' AND result->>'executor' = 'helios' AND COALESCE(result->>'helios_workflow_id', '') <> ''
		ORDER BY started_at
		LIMIT 50
		FOR UPDATE SKIP LOCKED
	`, cfg.MaxRuntime.Seconds())
	if err != nil {
		return fmt.Errorf("find running Helios remediations: %w", err)
	}
	var running []runningHelios
	for rows.Next() {
		var r runningHelios
		var raw string
		if err := rows.Scan(&r.id, &r.workflowID, &raw, &r.overdue); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal([]byte(raw), &r.result)
		running = append(running, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range running {
		summary, err := helios.getWorkflow(ctx, r.workflowID)
		if err != nil {
			result.Errors = append(result.Errors, r.id)
			continue
		}
		if err := s.settleHelios(ctx, helios, r, summary, result); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) settleHelios(ctx context.Context, helios *HeliosExecutor, r runningHelios, summary heliosWorkflowSummary, result *HeliosReconcileResult) error {
	final := maps.Clone(r.result)
	if final == nil {
		final = map[string]any{}
	}
	final["helios_workflow_state"] = summary.State
	final["reconciled"] = true
	status, action, errText := "", "", ""
	switch summary.State {
	case "succeeded":
		status, action = StateSucceeded, "remediation.completed"
		result.Succeeded = append(result.Succeeded, r.id)
	case "failed", "cancelled":
		status, action = StateFailed, "remediation.failed"
		errText = fmt.Sprintf("helios workflow %s finished in state %s", r.workflowID, summary.State)
		result.Failed = append(result.Failed, r.id)
	default:
		if !r.overdue {
			return nil
		}
		// Stop the workflow so it cannot finish later behind Argus's back.
		cancelErr := helios.cancelWorkflow(ctx, r.workflowID)
		final["helios_cancel_requested"] = cancelErr == nil
		status, action = StateTimedOut, "remediation.timed_out"
		errText = fmt.Sprintf("helios workflow %s still %s after the maximum runtime", r.workflowID, summary.State)
		if cancelErr != nil {
			errText += "; cancelling it failed: " + cancelErr.Error()
		}
		result.TimedOut = append(result.TimedOut, r.id)
	}
	if err := requireApplied(s.store.CompleteRemediation(ctx, r.id, status, final, errText)); err != nil {
		return err
	}
	if status == StateFailed || status == StateTimedOut {
		if rem, err := s.store.GetRemediation(ctx, r.id); err == nil && s.metrics != nil {
			s.metrics.RemediationFailuresTotal.WithLabelValues(rem.ActionType).Inc()
		}
	}
	return audit.WriteTx(ctx, s.store.Tx(), audit.Entry{
		ActorType: "system", Action: action, ResourceType: "remediation", ResourceID: r.id,
		BeforeState: map[string]any{"status": StateRunning},
		AfterState:  map[string]any{"status": status, "executor": "helios", "result": final, "error": errText},
		Metadata:    map[string]any{"reconciled_by": "helios_reconciler", "helios_workflow_id": r.workflowID},
	})
}

func (s *Service) recoverLostHeliosSubmissions(ctx context.Context, helios *HeliosExecutor, cfg HeliosReconcileConfig, result *HeliosReconcileResult) error {
	rows, err := s.store.Tx().QueryContext(ctx, `
		SELECT r.id FROM remediation_actions r
		WHERE r.status = 'queued' AND r.queued_at < now() - make_interval(secs => $1)
		  AND NOT EXISTS (SELECT 1 FROM remediation_dispatches d WHERE d.remediation_id = r.id)
		ORDER BY r.queued_at
		LIMIT 20
		FOR UPDATE OF r SKIP LOCKED
	`, cfg.SubmitLostAfter.Seconds())
	if err != nil {
		return fmt.Errorf("find lost Helios submissions: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		found, err := helios.findWorkflow(ctx, id)
		if err != nil {
			result.Errors = append(result.Errors, id)
			continue
		}
		if found != nil {
			adopted := map[string]any{
				"executor": "helios", "helios_workflow_id": found.WorkflowID, "helios_workflow_name": found.Name,
				"helios_workflow_state": found.State, "adopted": true,
			}
			if err := requireApplied(s.store.MarkRemediationRunning(ctx, id, adopted)); err != nil {
				return err
			}
			if err := audit.WriteTx(ctx, s.store.Tx(), audit.Entry{
				ActorType: "system", Action: "remediation.running", ResourceType: "remediation", ResourceID: id,
				BeforeState: map[string]any{"status": StateQueued},
				AfterState:  map[string]any{"status": StateRunning, "executor": "helios", "result": adopted},
				Metadata:    map[string]any{"reconciled_by": "helios_reconciler", "reason": "adopted the workflow a crashed submission created"},
			}); err != nil {
				return err
			}
			result.Adopted = append(result.Adopted, id)
			if err := s.settleHelios(ctx, helios, runningHelios{id: id, workflowID: found.WorkflowID, result: adopted}, *found, result); err != nil {
				return err
			}
			continue
		}
		rem, err := s.store.GetRemediation(ctx, id)
		if err != nil {
			return err
		}
		incident, err := s.store.GetIncident(ctx, rem.IncidentID)
		if err != nil {
			return err
		}
		if incidents.IsClosed(incident.Status) {
			reason := "incident closed before the lost Helios submission was recovered"
			if err := requireApplied(s.store.CompleteRemediation(ctx, id, StateCancelled, nil, reason)); err != nil {
				return err
			}
			if err := audit.WriteTx(ctx, s.store.Tx(), audit.Entry{
				ActorType: "system", Action: "remediation.cancelled", ResourceType: "remediation", ResourceID: id,
				BeforeState: map[string]any{"status": StateQueued}, AfterState: map[string]any{"status": StateCancelled, "error": reason},
				Metadata: map[string]any{"reconciled_by": "helios_reconciler"},
			}); err != nil {
				return err
			}
			continue
		}
		outcome, err := helios.Execute(ctx, rem, incident, rem.DryRun)
		if err != nil {
			// Not submitted, or the workflow failed; a failed workflow is
			// found and settled on the next pass.
			result.Errors = append(result.Errors, id)
			continue
		}
		if err := s.applyQueuedOutcome(ctx, rem, outcome, "system"); err != nil {
			return err
		}
		result.Resubmitted = append(result.Resubmitted, id)
	}
	return nil
}

// findWorkflow returns the most recent workflow labelled with the
// remediation id among Helios's latest 500, or nil.
func (e *HeliosExecutor) findWorkflow(ctx context.Context, remediationID string) (*heliosWorkflowSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+"/api/v1/workflows?limit=500", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.adminToken)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list helios workflows: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("list helios workflows returned status %s", resp.Status)
	}
	var list struct {
		Workflows []struct {
			heliosWorkflowSummary
			Labels map[string]string `json:"labels"`
		} `json:"workflows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode helios workflow list: %w", err)
	}
	for _, wf := range list.Workflows { // newest first
		if wf.Labels["remediation_id"] == remediationID && wf.Labels["source"] == "argus" {
			summary := wf.heliosWorkflowSummary
			return &summary, nil
		}
	}
	return nil, nil
}

func (e *HeliosExecutor) cancelWorkflow(ctx context.Context, workflowID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/api/v1/workflows/"+workflowID+"/cancel", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.adminToken)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cancel helios workflow: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cancel helios workflow returned status %s", resp.Status)
	}
	return nil
}
