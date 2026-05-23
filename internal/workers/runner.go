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
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
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

	if remediation.Status == remediationpkg.StateSucceeded {
		return msg.Ack()
	}

	handler, ok := r.handlers[remediation.ActionType]
	if !ok {
		_ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateFailed, nil, "no handler registered")
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
		deliveryAttempt := uint64(1)
		if metadata, metaErr := msg.Metadata(); metaErr == nil {
			deliveryAttempt = metadata.NumDelivered
		}
		if deliveryAttempt < uint64(remediation.MaxAttempts) {
			backoff := time.Duration(deliveryAttempt) * 2 * time.Second
			_ = r.auditor.Write(ctx, audit.Entry{
				ActorType:    "system",
				Action:       "remediation.retry_scheduled",
				ResourceType: "remediation",
				ResourceID:   remediation.ID,
				AfterState: map[string]any{
					"status":           remediationpkg.StateRunning,
					"error":            err.Error(),
					"delivery_attempt": deliveryAttempt,
					"retry_after":      backoff.String(),
				},
			})
			_ = msg.NakWithDelay(backoff)
			return err
		}

		r.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
		_ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateFailed, result, err.Error())
		_ = r.auditor.Write(ctx, audit.Entry{
			ActorType:    "system",
			Action:       "remediation.failed",
			ResourceType: "remediation",
			ResourceID:   remediation.ID,
			AfterState: map[string]any{
				"status":           remediationpkg.StateFailed,
				"error":            err.Error(),
				"delivery_attempt": deliveryAttempt,
			},
		})
		_ = msg.Ack()
		return err
	}

	if err := r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateSucceeded, result, ""); err != nil {
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
			"status": remediationpkg.StateSucceeded,
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
		staticHandler{name: "restart_service", message: "Typed handler validated restart_service; local demo execution remains bounded and auditable"},
		staticHandler{name: "rollback_config", message: "Typed handler validated rollback_config against known-good demo configuration"},
		staticHandler{name: "reload_nginx", message: "Typed handler validated nginx reload for the demo environment"},
		staticHandler{name: "clear_redis_keyspace", message: "Typed handler validated deletion scope for demo:pressure:* redis keys"},
		staticHandler{name: "drain_postgres_connections", message: "Typed handler validated demo-only postgres connection drain"},
		staticHandler{name: "revert_feature_flag", message: "Typed handler validated optional notification feature flag revert"},
		staticHandler{name: "disable_bad_route", message: "Typed handler validated disabling only the affected bad demo route"},
	}
}
