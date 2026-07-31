package workers

import (
	"context"
	"fmt"
	"strings"

	"github.com/gauravgs7/argus/internal/actions"
	"github.com/gauravgs7/argus/internal/incidents"
)

type PodRestartHandler struct{ state ControlStateStore }
type ConnectionPoolResizeHandler struct{ state ControlStateStore }
type FeatureFlagToggleHandler struct{ state ControlStateStore }
type CachePurgeHandler struct{ state ControlStateStore }

func NewPodRestartHandler(state ControlStateStore) *PodRestartHandler {
	return &PodRestartHandler{state: state}
}

func NewConnectionPoolResizeHandler(state ControlStateStore) *ConnectionPoolResizeHandler {
	return &ConnectionPoolResizeHandler{state: state}
}

func NewFeatureFlagToggleHandler(state ControlStateStore) *FeatureFlagToggleHandler {
	return &FeatureFlagToggleHandler{state: state}
}

func NewCachePurgeHandler(state ControlStateStore) *CachePurgeHandler {
	return &CachePurgeHandler{state: state}
}

func (h *PodRestartHandler) Name() string { return actions.RestartPod }
func (h *PodRestartHandler) Validate(req incidents.RemediationAction) error {
	return validateTypedRequest(h.state, h.Name(), req)
}
func (h *PodRestartHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	namespace, pod, _ := strings.Cut(req.Target, "/")
	return h.state.Preview(ctx, "pod", req.Target, map[string]any{
		"namespace":     namespace,
		"pod":           pod,
		"restart_token": req.IdempotencyKey,
	})
}
func (h *PodRestartHandler) Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	namespace, pod, _ := strings.Cut(req.Target, "/")
	return h.state.ApplyOnce(ctx, req.IdempotencyKey, h.Name(), "pod", req.Target, map[string]any{
		"namespace":     namespace,
		"pod":           pod,
		"restart_token": req.IdempotencyKey,
	})
}

func (h *ConnectionPoolResizeHandler) Name() string { return actions.ResizeConnectionPool }
func (h *ConnectionPoolResizeHandler) Validate(req incidents.RemediationAction) error {
	return validateTypedRequest(h.state, h.Name(), req)
}
func (h *ConnectionPoolResizeHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	size, _ := actions.Integer(req.Parameters["size"])
	return h.state.Preview(ctx, "connection_pool", req.Target, map[string]any{"max_connections": size})
}
func (h *ConnectionPoolResizeHandler) Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	size, _ := actions.Integer(req.Parameters["size"])
	return h.state.ApplyOnce(ctx, req.IdempotencyKey, h.Name(), "connection_pool", req.Target, map[string]any{"max_connections": size})
}

func (h *FeatureFlagToggleHandler) Name() string { return actions.ToggleFeatureFlag }
func (h *FeatureFlagToggleHandler) Validate(req incidents.RemediationAction) error {
	return validateTypedRequest(h.state, h.Name(), req)
}
func (h *FeatureFlagToggleHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	return h.state.Preview(ctx, "feature_flag", req.Target, map[string]any{"enabled": req.Parameters["enabled"]})
}
func (h *FeatureFlagToggleHandler) Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	return h.state.ApplyOnce(ctx, req.IdempotencyKey, h.Name(), "feature_flag", req.Target, map[string]any{"enabled": req.Parameters["enabled"]})
}

func (h *CachePurgeHandler) Name() string { return actions.PurgeCache }
func (h *CachePurgeHandler) Validate(req incidents.RemediationAction) error {
	return validateTypedRequest(h.state, h.Name(), req)
}
func (h *CachePurgeHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	maxKeys, _ := actions.Integer(req.Parameters["max_keys"])
	return h.state.Preview(ctx, "cache_prefix", req.Target, map[string]any{
		"max_keys":    maxKeys,
		"purge_token": req.IdempotencyKey,
	})
}
func (h *CachePurgeHandler) Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	if err := h.Validate(req); err != nil {
		return nil, err
	}
	maxKeys, _ := actions.Integer(req.Parameters["max_keys"])
	return h.state.ApplyOnce(ctx, req.IdempotencyKey, h.Name(), "cache_prefix", req.Target, map[string]any{
		"max_keys":    maxKeys,
		"purge_token": req.IdempotencyKey,
	})
}

func validateTypedRequest(state ControlStateStore, action string, req incidents.RemediationAction) error {
	if state == nil {
		return fmt.Errorf("control-state backend is unavailable")
	}
	if req.IdempotencyKey == "" {
		return fmt.Errorf("idempotency key is required")
	}
	if req.ActionType != action {
		return fmt.Errorf("handler %s cannot execute action %s", action, req.ActionType)
	}
	return actions.Validate(action, req.Target, req.Parameters)
}
