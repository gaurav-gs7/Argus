package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
)

type ExecutionOutcome struct {
	Status string
	Result map[string]any
}

type Executor interface {
	Name() string
	Execute(ctx context.Context, remediation incidents.RemediationAction, incident incidents.Incident, dryRun bool) (ExecutionOutcome, error)
}

type LocalExecutor struct {
	queue *queue.Client
}

func NewLocalExecutor(queueClient *queue.Client) *LocalExecutor {
	return &LocalExecutor{queue: queueClient}
}

func (e *LocalExecutor) Name() string {
	return "local"
}

func (e *LocalExecutor) Execute(ctx context.Context, remediation incidents.RemediationAction, incident incidents.Incident, dryRun bool) (ExecutionOutcome, error) {
	if err := e.queue.Publish(ctx, "remediation.execute", queue.Event{
		EventID:        common.NewID("evt"),
		EventType:      "remediation.execute",
		OccurredAt:     time.Now().UTC(),
		Producer:       "argus-api",
		IdempotencyKey: remediation.IdempotencyKey,
		Payload: map[string]any{
			"remediation_id": remediation.ID,
			"incident_id":    incident.ID,
			"dry_run":        dryRun,
			"executor":       e.Name(),
		},
	}); err != nil {
		return ExecutionOutcome{}, err
	}

	return ExecutionOutcome{
		Status: "queued",
		Result: map[string]any{
			"executor":        e.Name(),
			"queue_subject":   "remediation.execute",
			"idempotency_key": remediation.IdempotencyKey,
			"dry_run":         dryRun,
		},
	}, nil
}

type HeliosExecutor struct {
	baseURL     string
	adminToken  string
	pollTimeout time.Duration
	httpClient  *http.Client
}

func NewHeliosExecutor(baseURL, adminToken string, pollTimeout time.Duration) *HeliosExecutor {
	return &HeliosExecutor{
		baseURL:     strings.TrimRight(baseURL, "/"),
		adminToken:  adminToken,
		pollTimeout: pollTimeout,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (e *HeliosExecutor) Name() string {
	return "helios"
}

func (e *HeliosExecutor) Execute(ctx context.Context, remediation incidents.RemediationAction, incident incidents.Incident, dryRun bool) (ExecutionOutcome, error) {
	if e.baseURL == "" {
		return ExecutionOutcome{}, fmt.Errorf("helios base URL is not configured")
	}
	if e.adminToken == "" {
		return ExecutionOutcome{}, fmt.Errorf("helios admin token is not configured")
	}

	spec := e.workflowSpec(remediation, incident, dryRun)
	body, _ := json.Marshal(spec)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/api/v1/workflows", bytes.NewReader(body))
	if err != nil {
		return ExecutionOutcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.adminToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return ExecutionOutcome{}, fmt.Errorf("submit helios workflow: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ExecutionOutcome{}, fmt.Errorf("submit helios workflow returned status %s", resp.Status)
	}

	var created struct {
		WorkflowID string            `json:"workflow_id"`
		Name       string            `json:"name"`
		State      string            `json:"state"`
		Metadata   map[string]string `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return ExecutionOutcome{}, fmt.Errorf("decode helios workflow response: %w", err)
	}

	summary, err := e.pollWorkflow(ctx, created.WorkflowID)
	if err != nil {
		return ExecutionOutcome{}, err
	}

	result := map[string]any{
		"executor":              e.Name(),
		"helios_workflow_id":    summary.WorkflowID,
		"helios_workflow_name":  summary.Name,
		"helios_workflow_state": summary.State,
		"dry_run":               dryRun,
		"delegated_task_type":   "persist_artifact",
	}
	if summary.Metadata != nil {
		result["helios_metadata"] = summary.Metadata
	}

	switch summary.State {
	case "succeeded":
		return ExecutionOutcome{Status: "succeeded", Result: result}, nil
	case "failed", "cancelled":
		return ExecutionOutcome{}, fmt.Errorf("helios workflow %s finished in state %s", summary.WorkflowID, summary.State)
	default:
		return ExecutionOutcome{Status: "running", Result: result}, nil
	}
}

type heliosWorkflowSummary struct {
	WorkflowID string            `json:"workflow_id"`
	Name       string            `json:"name"`
	State      string            `json:"state"`
	Metadata   map[string]string `json:"metadata"`
}

func (e *HeliosExecutor) pollWorkflow(ctx context.Context, workflowID string) (heliosWorkflowSummary, error) {
	deadline := time.Now().Add(e.pollTimeout)
	for {
		summary, err := e.getWorkflow(ctx, workflowID)
		if err != nil {
			return heliosWorkflowSummary{}, err
		}
		switch summary.State {
		case "succeeded", "failed", "cancelled":
			return summary, nil
		}
		if time.Now().After(deadline) {
			return summary, nil
		}
		select {
		case <-ctx.Done():
			return heliosWorkflowSummary{}, ctx.Err()
		case <-time.After(750 * time.Millisecond):
		}
	}
}

func (e *HeliosExecutor) getWorkflow(ctx context.Context, workflowID string) (heliosWorkflowSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+"/api/v1/workflows/"+workflowID, nil)
	if err != nil {
		return heliosWorkflowSummary{}, err
	}
	req.Header.Set("Authorization", "Bearer "+e.adminToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return heliosWorkflowSummary{}, fmt.Errorf("get helios workflow: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return heliosWorkflowSummary{}, fmt.Errorf("get helios workflow returned status %s", resp.Status)
	}

	var summary heliosWorkflowSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return heliosWorkflowSummary{}, fmt.Errorf("decode helios workflow summary: %w", err)
	}
	return summary, nil
}

func (e *HeliosExecutor) workflowSpec(remediation incidents.RemediationAction, incident incidents.Incident, dryRun bool) map[string]any {
	parametersJSON, _ := json.Marshal(remediation.Parameters)
	return map[string]any{
		"name": fmt.Sprintf("argus-remediation-%s", remediation.ID),
		"labels": map[string]string{
			"source":         "argus",
			"incident_id":    incident.ID,
			"remediation_id": remediation.ID,
			"action_type":    remediation.ActionType,
		},
		"metadata": map[string]string{
			"owner":            "argus",
			"incident_id":      incident.ID,
			"incident_service": incident.Service,
			"remediation_id":   remediation.ID,
			"action_type":      remediation.ActionType,
			"target":           remediation.Target,
			"risk":             remediation.Risk,
			"parameters":       string(parametersJSON),
			"dry_run":          fmt.Sprintf("%t", dryRun),
		},
		"tasks": []map[string]any{
			{
				"task_id":                   "record-remediation-execution",
				"task_type":                 "persist_artifact",
				"timeout_seconds":           15,
				"priority":                  90,
				"cpu_units":                 200,
				"memory_mb":                 128,
				"expected_duration_seconds": 2,
				"idempotency_key":           remediation.IdempotencyKey,
				"retry_policy": map[string]any{
					"max_attempts":            remediation.MaxAttempts,
					"initial_backoff_seconds": 1,
					"max_backoff_seconds":     5,
					"multiplier":              2,
				},
				"input_payload": map[string]any{
					"sink":    "argus://helios-remediation-executor",
					"dataset": "argus_remediation_actions",
					"artifact": map[string]any{
						"incident_id":      incident.ID,
						"incident_title":   incident.Title,
						"service":          incident.Service,
						"severity":         incident.Severity,
						"remediation_id":   remediation.ID,
						"action_type":      remediation.ActionType,
						"target":           remediation.Target,
						"risk":             remediation.Risk,
						"parameters":       remediation.Parameters,
						"idempotency_key":  remediation.IdempotencyKey,
						"attempt":          remediation.Attempt,
						"dry_run":          dryRun,
						"submitted_by":     remediation.ProposedBy,
						"executor_backend": "helios",
					},
				},
			},
		},
	}
}
