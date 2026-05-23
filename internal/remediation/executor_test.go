package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

func TestHeliosExecutorExecute(t *testing.T) {
	t.Helper()

	var submitted map[string]any
	executor := NewHeliosExecutor("http://helios.local", "admin-token", 2*time.Second)
	executor.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows":
				if got := r.Header.Get("Authorization"); got != "Bearer admin-token" {
					t.Fatalf("unexpected authorization header: %q", got)
				}
				if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
					t.Fatalf("decode submitted workflow: %v", err)
				}
				return jsonResponse(http.StatusAccepted, map[string]any{
					"workflow_id": "wf_123",
					"name":        "argus-remediation-rem_123",
					"state":       "submitted",
				}), nil
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workflows/wf_123":
				return jsonResponse(http.StatusOK, map[string]any{
					"workflow_id": "wf_123",
					"name":        "argus-remediation-rem_123",
					"state":       "succeeded",
					"metadata": map[string]string{
						"owner": "argus",
					},
				}), nil
			default:
				return nil, fmt.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}),
	}

	outcome, err := executor.Execute(context.Background(),
		incidents.RemediationAction{
			ID:             "rem_123",
			IncidentID:     "inc_123",
			ActionType:     "restart_service",
			Target:         "payments-api",
			Risk:           "medium",
			IdempotencyKey: "inc_123_restart_service_payments-api_1",
			Attempt:        1,
			MaxAttempts:    1,
			ProposedBy:     "admin@local",
		},
		incidents.Incident{
			ID:       "inc_123",
			Title:    "High 5xx on payments-api",
			Service:  "payments-api",
			Severity: "sev2",
		},
		false,
	)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if outcome.Status != "succeeded" {
		t.Fatalf("expected succeeded, got %q", outcome.Status)
	}
	if submitted["name"] == "" {
		t.Fatalf("expected workflow name to be set")
	}
	tasks, ok := submitted["tasks"].([]any)
	if !ok || len(tasks) != 1 {
		t.Fatalf("expected exactly one helios task, got %#v", submitted["tasks"])
	}
	task, ok := tasks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected task to be an object, got %#v", tasks[0])
	}
	if task["task_type"] != "persist_artifact" {
		t.Fatalf("expected persist_artifact task type, got %#v", task["task_type"])
	}
}

func TestHeliosExecutorRequiresConfig(t *testing.T) {
	executor := NewHeliosExecutor("", "", time.Second)
	_, err := executor.Execute(context.Background(), incidents.RemediationAction{}, incidents.Incident{}, true)
	if err == nil {
		t.Fatal("expected missing config error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func jsonResponse(status int, body any) *http.Response {
	data, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(data))),
	}
}
