package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gauravgs7/argus/internal/actions"
	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/nats-io/nats.go"
)

type Handler interface {
	Name() string
	Validate(req incidents.RemediationAction) error
	Execute(ctx context.Context, req incidents.RemediationAction) (map[string]any, error)
	DryRun(ctx context.Context, req incidents.RemediationAction) (map[string]any, error)
}

// RunnerConfig bounds how a worker consumes remediation jobs.
type RunnerConfig struct {
	// Concurrency is how many jobs one worker runs at once, so one slow
	// handler cannot stall the queue.
	Concurrency int
	// JobTimeout bounds a single handler execution. A job that exceeds it is
	// marked timed_out and not retried, because its side effect is unknown.
	JobTimeout time.Duration
	// MaxDeliver caps deliveries of one message, including retries after
	// transient database errors. The last attempt is dead-lettered.
	MaxDeliver int
	// FetchWait is how long one pull request waits for work.
	FetchWait time.Duration
}

func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{Concurrency: 4, JobTimeout: 2 * time.Minute, MaxDeliver: 5, FetchWait: 2 * time.Second}
}

type Runner struct {
	store    *incidents.Store
	auditor  *audit.Service
	queue    *queue.Client
	metrics  *telemetry.Metrics
	handlers map[string]Handler
	cfg      RunnerConfig
	inflight sync.WaitGroup
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
		cfg:      DefaultRunnerConfig(),
	}
}

// Configure overrides the defaults; zero fields keep their default.
func (r *Runner) Configure(cfg RunnerConfig) {
	def := DefaultRunnerConfig()
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = def.Concurrency
	}
	if cfg.JobTimeout <= 0 {
		cfg.JobTimeout = def.JobTimeout
	}
	if cfg.MaxDeliver <= 0 {
		cfg.MaxDeliver = def.MaxDeliver
	}
	if cfg.FetchWait <= 0 {
		cfg.FetchWait = def.FetchWait
	}
	r.cfg = cfg
}

const (
	// WorkerConsumer is the durable pull consumer every worker replica shares.
	WorkerConsumer = "argus-remediation-workers"
)

// legacyConsumers are push consumers from earlier versions. A push consumer
// cannot become a pull consumer, so they are removed at startup.
var legacyConsumers = []string{"argus-worker", "argus-workers"}

// ConsumerConfig is the durable pull consumer for remediation jobs. AckWait
// exceeds the job timeout so JetStream does not redeliver a job that is still
// running.
func (r *Runner) ConsumerConfig() nats.ConsumerConfig {
	return nats.ConsumerConfig{
		Durable:       WorkerConsumer,
		FilterSubject: queue.RemediationSubject,
		AckPolicy:     nats.AckExplicitPolicy,
		AckWait:       r.cfg.JobTimeout + 30*time.Second,
		MaxDeliver:    r.cfg.MaxDeliver,
		MaxAckPending: 256,
		DeliverPolicy: nats.DeliverAllPolicy,
	}
}

func (r *Runner) ensureConsumer(js nats.JetStreamContext) error {
	for _, name := range legacyConsumers {
		if err := js.DeleteConsumer(queue.RemediationStream, name); err != nil && !errors.Is(err, nats.ErrConsumerNotFound) {
			return fmt.Errorf("remove legacy consumer %s: %w", name, err)
		}
	}
	want := r.ConsumerConfig()
	if _, err := js.ConsumerInfo(queue.RemediationStream, WorkerConsumer); err != nil {
		if !errors.Is(err, nats.ErrConsumerNotFound) {
			return fmt.Errorf("inspect worker consumer: %w", err)
		}
		if _, err := js.AddConsumer(queue.RemediationStream, &want); err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
			return fmt.Errorf("create worker consumer: %w", err)
		}
		return nil
	}
	if _, err := js.UpdateConsumer(queue.RemediationStream, &want); err != nil {
		return fmt.Errorf("update worker consumer: %w", err)
	}
	return nil
}

func (r *Runner) Start(ctx context.Context, workerID string) error {
	if err := r.queue.EnsureStreams(); err != nil {
		return err
	}
	js := r.queue.JetStream()
	if err := r.ensureConsumer(js); err != nil {
		return err
	}
	sub, err := js.PullSubscribe(queue.RemediationSubject, WorkerConsumer, nats.Bind(queue.RemediationStream, WorkerConsumer))
	if err != nil {
		return fmt.Errorf("subscribe remediation.execute: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	go r.heartbeat(ctx, workerID)

	// Jobs keep their own context so a shutdown does not abort a handler
	// half way; Start waits for them (bounded by the job timeout) to finish.
	jobCtx := context.WithoutCancel(ctx)
	slots := make(chan struct{}, r.cfg.Concurrency)
	for ctx.Err() == nil {
		free := cap(slots) - len(slots)
		if free == 0 {
			select {
			case slots <- struct{}{}:
				<-slots
			case <-ctx.Done():
			}
			continue
		}
		msgs, err := sub.Fetch(free, nats.MaxWait(r.cfg.FetchWait))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
			}
			continue
		}
		for _, msg := range msgs {
			slots <- struct{}{}
			r.inflight.Add(1)
			go func() {
				defer r.inflight.Done()
				defer func() { <-slots }()
				_ = r.handleMessage(jobCtx, msg)
			}()
		}
	}

	done := make(chan struct{})
	go func() { r.inflight.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(r.cfg.JobTimeout + 5*time.Second):
	}
	return ctx.Err()
}

// deliveries is how many times JetStream has delivered this message.
func deliveries(msg *nats.Msg) uint64 {
	if meta, err := msg.Metadata(); err == nil {
		return meta.NumDelivered
	}
	return 1
}

// RetryDelay is the backoff before redelivering after a transient failure.
func RetryDelay(delivery uint64) time.Duration {
	const ceiling = 60 * time.Second
	if delivery < 1 {
		delivery = 1
	}
	if delivery > 7 {
		return ceiling
	}
	return min(time.Duration(1<<(delivery-1))*time.Second, ceiling)
}

// deadLetter republishes a message to the dead-letter stream and terminates
// it so JetStream stops redelivering.
func (r *Runner) deadLetter(ctx context.Context, msg *nats.Msg, reason string) {
	if r.metrics != nil {
		r.metrics.RemediationDeadLettersTotal.WithLabelValues(reason).Inc()
	}
	if r.queue != nil {
		_ = r.queue.DeadLetter(ctx, msg, reason)
	}
	_ = msg.Term()
}

// retryLater handles a transient failure (typically PostgreSQL being
// unavailable): back off and redeliver, or dead-letter on the last attempt.
func (r *Runner) retryLater(ctx context.Context, msg *nats.Msg, cause error) error {
	n := deliveries(msg)
	if n >= uint64(r.cfg.MaxDeliver) {
		r.deadLetter(ctx, msg, "retries_exhausted")
		return fmt.Errorf("dead-lettered after %d deliveries: %w", n, cause)
	}
	_ = msg.NakWithDelay(RetryDelay(n))
	return cause
}

func (r *Runner) handleMessage(ctx context.Context, msg *nats.Msg) error {
	var event queue.Event
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		r.deadLetter(ctx, msg, "undecodable_payload")
		return err
	}
	remediationID, _ := event.Payload["remediation_id"].(string)
	if remediationID == "" {
		r.deadLetter(ctx, msg, "missing_remediation_id")
		return fmt.Errorf("job has no remediation_id")
	}
	remediation, err := r.store.GetRemediation(ctx, remediationID)
	if errors.Is(err, sql.ErrNoRows) {
		r.deadLetter(ctx, msg, "remediation_not_found")
		return err
	}
	if err != nil {
		return r.retryLater(ctx, msg, err)
	}

	if remediation.Status != remediationpkg.StateQueued && remediation.Status != remediationpkg.StateRunning {
		// Cancelled, failed, timed out, succeeded, or never queued: the
		// message is stale and must not execute anything.
		r.auditSkip(ctx, remediation.ID, remediation.Status)
		return msg.Ack()
	}

	handler, ok := r.handlers[remediation.ActionType]
	if !ok {
		_, _ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateFailed, nil, "no handler registered")
		_ = msg.Ack()
		return fmt.Errorf("no handler for %s", remediation.ActionType)
	}
	if err := handler.Validate(remediation); err != nil {
		r.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
		_, _ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateFailed, nil, err.Error())
		_ = r.auditor.Write(ctx, audit.Entry{
			ActorType: "system", Action: "remediation.validation_failed", ResourceType: "remediation", ResourceID: remediation.ID,
			AfterState: map[string]any{"status": remediationpkg.StateFailed, "error": err.Error()},
		})
		_ = msg.Ack()
		return err
	}

	start := time.Now()
	claimed, err := r.store.ClaimRemediation(ctx, remediation.ID)
	if err != nil {
		return r.retryLater(ctx, msg, err)
	}
	if !claimed {
		// It left queued between the read above and this claim (for example
		// an operator cancelled it). Do not execute.
		latest, getErr := r.store.GetRemediation(ctx, remediation.ID)
		status := "unknown"
		if getErr == nil {
			status = latest.Status
		}
		r.auditSkip(ctx, remediation.ID, status)
		return msg.Ack()
	}

	result, err, timedOut := r.runHandler(ctx, handler, remediation)
	if timedOut {
		r.metrics.RemediationFailuresTotal.WithLabelValues(remediation.ActionType).Inc()
		reason := fmt.Sprintf("handler exceeded the %s job timeout; outcome unknown, not retried", r.cfg.JobTimeout)
		_, _ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateTimedOut, nil, reason)
		_ = r.auditor.Write(ctx, audit.Entry{
			ActorType: "system", Action: "remediation.timed_out", ResourceType: "remediation", ResourceID: remediation.ID,
			AfterState: map[string]any{"status": remediationpkg.StateTimedOut, "error": reason},
		})
		_ = msg.Ack()
		return fmt.Errorf("%s", reason)
	}
	if err != nil {
		deliveryAttempt := deliveries(msg)
		if deliveryAttempt < uint64(remediation.MaxAttempts) && deliveryAttempt < uint64(r.cfg.MaxDeliver) {
			backoff := RetryDelay(deliveryAttempt)
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
		_, _ = r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateFailed, result, err.Error())
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

	completed, err := r.store.CompleteRemediation(ctx, remediation.ID, remediationpkg.StateSucceeded, result, "")
	if err != nil {
		return r.retryLater(ctx, msg, err)
	}
	if !completed {
		_ = r.auditor.Write(ctx, audit.Entry{
			ActorType: "system", Action: "remediation.completion_conflict", ResourceType: "remediation", ResourceID: remediation.ID,
			AfterState: map[string]any{"result": result},
			Metadata:   map[string]any{"reason": "remediation left running before the result was recorded"},
		})
		return msg.Ack()
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

// runHandler executes one job under the job timeout. The handler receives a
// context that is cancelled at the deadline; if it does not return by then
// the job is reported as timed out and the handler is left to finish on its
// own (its late completion then fails the status compare-and-swap).
func (r *Runner) runHandler(ctx context.Context, handler Handler, remediation incidents.RemediationAction) (map[string]any, error, bool) {
	jobCtx, cancel := context.WithTimeout(ctx, r.cfg.JobTimeout)
	defer cancel()
	type outcome struct {
		result map[string]any
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		if remediation.DryRun {
			o.result, o.err = handler.DryRun(jobCtx, remediation)
		} else {
			o.result, o.err = handler.Execute(jobCtx, remediation)
		}
		done <- o
	}()
	select {
	case o := <-done:
		if o.err != nil && errors.Is(o.err, context.DeadlineExceeded) && jobCtx.Err() != nil {
			return nil, o.err, true
		}
		return o.result, o.err, false
	case <-jobCtx.Done():
		return nil, jobCtx.Err(), true
	}
}

func (r *Runner) auditSkip(ctx context.Context, remediationID, status string) {
	if status == remediationpkg.StateSucceeded {
		return // replay of a completed action; nothing worth recording
	}
	_ = r.auditor.Write(ctx, audit.Entry{
		ActorType: "system", Action: "remediation.execution_skipped", ResourceType: "remediation", ResourceID: remediationID,
		AfterState: map[string]any{"status": status},
		Metadata:   map[string]any{"reason": "remediation is not queued or running"},
	})
}

func (r *Runner) heartbeat(ctx context.Context, workerID string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	hostname, _ := os.Hostname()
	supportedActions := make([]string, 0, len(r.handlers))
	for action := range r.handlers {
		supportedActions = append(supportedActions, action)
	}
	sort.Strings(supportedActions)
	for {
		now := time.Now().UTC()
		r.metrics.WorkerHeartbeatAgeSeconds.WithLabelValues(workerID).Set(0)
		_ = r.store.UpsertWorkerHeartbeat(ctx, workerID, hostname, now, supportedActions)
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
func (h staticHandler) Validate(req incidents.RemediationAction) error {
	if req.ActionType != h.name {
		return fmt.Errorf("handler %s cannot execute action %s", h.name, req.ActionType)
	}
	return actions.Validate(req.ActionType, req.Target, req.Parameters)
}

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

func DefaultHandlers(state ControlStateStore) []Handler {
	return []Handler{
		staticHandler{name: "restart_service", message: "Typed handler validated restart_service; local demo execution remains bounded and auditable"},
		staticHandler{name: "rollback_config", message: "Typed handler validated rollback_config against known-good demo configuration"},
		staticHandler{name: "reload_nginx", message: "Typed handler validated nginx reload for the demo environment"},
		staticHandler{name: "clear_redis_keyspace", message: "Typed handler validated deletion scope for demo:pressure:* redis keys"},
		staticHandler{name: "drain_postgres_connections", message: "Typed handler validated demo-only postgres connection drain"},
		staticHandler{name: "revert_feature_flag", message: "Typed handler validated optional notification feature flag revert"},
		staticHandler{name: "disable_bad_route", message: "Typed handler validated disabling only the affected bad demo route"},
		NewPodRestartHandler(state),
		NewConnectionPoolResizeHandler(state),
		NewFeatureFlagToggleHandler(state),
		NewCachePurgeHandler(state),
	}
}
