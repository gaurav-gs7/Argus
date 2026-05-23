package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/nats-io/nats.go"
)

type Handler interface {
	Name() string
	Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error)
	DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error)
}

type Runner struct {
	store    *incidents.Store
	auditor  *audit.Service
	queue    *queue.Client
	metrics  *telemetry.Metrics
	handlers map[string]Handler
}

func NewRunner(store *incidents.Store, auditor *audit.Service, queueClient *queue.Client, metrics *telemetry.Metrics, handlers ...Handler) *Runner {
	registry := make(map[string]Handler, len(handlers))
	for _, handler := range handlers {
		registry[handler.Name()] = handler
	}
	return &Runner{
		store:    store,
		auditor:  auditor,
		queue:    queueClient,
		metrics:  metrics,
		handlers: registry,
	}
}

func (r *Runner) Start(ctx context.Context, workerID string) error {
	if err := r.queue.EnsureStreams(); err != nil {
		return err
	}

	_, err := r.queue.JetStream().Subscribe("remediation.execute", func(msg *nats.Msg) {
		_ = r.handleMessage(ctx, msg)
	}, nats.Durable("argus-worker"), nats.ManualAck(), nats.AckExplicit())
	if err != nil {
		return fmt.Errorf("subscribe remediation.execute: %w", err)
	}

	go r.heartbeat(ctx, workerID)
	<-ctx.Done()
	return ctx.Err()
}

func (r *Runner) handleMessage(ctx context.Context, msg *nats.Msg) error {
	var event queue.Event
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		_ = msg.Term()
		return err
	}

	remediationID, _ := event.Payload["remediation_id"].(string)
	remediation, err := r.store.GetRemediation(ctx, remediationID)
	if err != nil {
		_ = msg.Nak()
		return err
	}

	if remediation.Status == "succeeded" {
		return msg.Ack()
	}

	handler, ok := r.handlers[remediation.ActionType]
	if !ok {
		_ = r.store.CompleteRemediation(ctx, remediation.ID, "failed", nil, "no handler registered")
		_ = msg.Ack()
		return fmt.Errorf("no handler for %s", remediation.ActionType)
	}

	start := time.Now()
	if err := r.store.MarkRemediationRunning(ctx, remediation.ID); err != nil {
		_ = msg.Nak()
		return err
	}

	var result map[string]any
	if remediation.DryRun {
		result, err = handler.DryRun(ctx, remediation)
	} else {
		result, err = handler.Execute(ctx, remediation)
	}
	if err != nil {
		r.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
		_ = r.store.CompleteRemediation(ctx, remediation.ID, "failed", result, err.Error())
		_ = r.auditor.Write(ctx, audit.Entry{
			ActorType:    "system",
			Action:       "remediation.failed",
			ResourceType: "remediation",
			ResourceID:   remediation.ID,
			AfterState: map[string]any{
				"status": "failed",
				"error":  err.Error(),
			},
		})
		_ = msg.Ack()
		return err
	}

	if err := r.store.CompleteRemediation(ctx, remediation.ID, "succeeded", result, ""); err != nil {
		_ = msg.Nak()
		return err
	}
	r.metrics.RemediationDuration.WithLabelValues(remediation.ActionType).Observe(time.Since(start).Seconds())

	_ = r.auditor.Write(ctx, audit.Entry{
		ActorType:    "system",
		Action:       "remediation.completed",
		ResourceType: "remediation",
		ResourceID:   remediation.ID,
		AfterState: map[string]any{
			"status": "succeeded",
			"result": result,
		},
	})
	return msg.Ack()
}

func (r *Runner) heartbeat(ctx context.Context, workerID string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	hostname, _ := os.Hostname()
	for {
		now := time.Now().UTC()
		r.metrics.WorkerHeartbeatAgeSeconds.WithLabelValues(workerID).Set(0)
		_ = r.store.UpsertWorkerHeartbeat(ctx, workerID, hostname, now, []string{
			"restart_service",
			"rollback_config",
			"reload_nginx",
			"clear_redis_keyspace",
			"drain_postgres_connections",
			"revert_feature_flag",
		})
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type staticHandler struct {
	name    string
	message string
}

func (h staticHandler) Name() string { return h.name }

func (h staticHandler) Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	return map[string]any{
		"mode":    "execute",
		"message": h.message,
		"target":  req.Target,
	}, nil
}

func (h staticHandler) DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error) {
	return map[string]any{
		"mode":    "dry-run",
		"message": h.message,
		"target":  req.Target,
	}, nil
}

func DefaultHandlers() []Handler {
	return []Handler{
		staticHandler{name: "restart_service", message: "Would restart the demo service using a typed worker handler"},
		staticHandler{name: "rollback_config", message: "Would restore the previous known-good demo configuration"},
		staticHandler{name: "reload_nginx", message: "Would trigger an nginx reload in the demo environment"},
		staticHandler{name: "clear_redis_keyspace", message: "Would delete only demo-scoped redis keys"},
		staticHandler{name: "drain_postgres_connections", message: "Would drain only demo application postgres sessions"},
		staticHandler{name: "revert_feature_flag", message: "Would disable the demo feature flag for the slow dependency path"},
		staticHandler{name: "disable_bad_route", message: "Would disable the affected bad demo route"},
	}
}
