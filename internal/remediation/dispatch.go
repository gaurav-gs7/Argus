package remediation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/telemetry"
)

// Dispatch reasons recorded in remediation_dispatches.
const (
	DispatchExecute    = "execute"
	DispatchRedispatch = "redispatch"
	DispatchReplay     = "replay"
)

// Publisher is the JetStream side of the outbox (*queue.Client).
type Publisher interface {
	Publish(ctx context.Context, subject string, event queue.Event) (bool, error)
}

// DispatcherConfig bounds the outbox loops. Zero fields take defaults.
type DispatcherConfig struct {
	// PollInterval is how often pending dispatches are retried.
	PollInterval time.Duration
	// BatchSize caps the dispatches published per poll.
	BatchSize int
	// PublishTimeout bounds one JetStream publish.
	PublishTimeout time.Duration
	// RedispatchAfter is how long a remediation may stay queued after its job
	// was published before the reconciler sends it again.
	RedispatchAfter time.Duration
	// MaxRedispatches is how many times the reconciler re-sends a job before
	// it gives up and marks the remediation timed_out.
	MaxRedispatches int
	// ReconcileInterval is how often the reconciler runs.
	ReconcileInterval time.Duration
	// RunningStaleAfter is how long a remediation may stay running before the
	// reconciler treats the worker that claimed it as gone. It must exceed the
	// worker job timeout, after which a live worker records timed_out itself.
	RunningStaleAfter time.Duration
	// WorkerLiveWindow is how recent a worker heartbeat must be for that
	// worker to count as alive. With no live worker that supports an action,
	// the reconciler neither re-sends nor times out its remediations: a job
	// is not lost just because every worker is down.
	WorkerLiveWindow time.Duration
}

func DefaultDispatcherConfig() DispatcherConfig {
	return DispatcherConfig{
		PollInterval:      time.Second,
		BatchSize:         50,
		PublishTimeout:    5 * time.Second,
		RedispatchAfter:   10 * time.Minute,
		MaxRedispatches:   3,
		ReconcileInterval: 30 * time.Second,
		RunningStaleAfter: 15 * time.Minute,
		WorkerLiveWindow:  time.Minute,
	}
}

// Dispatcher publishes remediation jobs from the remediation_dispatches
// outbox and reconciles remediations that stay queued without a worker
// picking them up. Every API replica can run one: pending rows are claimed
// with FOR UPDATE SKIP LOCKED, and only one replica reconciles at a time.
type Dispatcher struct {
	store     *incidents.Store
	auditor   *audit.Service
	publisher Publisher
	metrics   *telemetry.Metrics
	logger    *slog.Logger
	cfg       DispatcherConfig
}

func NewDispatcher(store *incidents.Store, auditor *audit.Service, publisher Publisher, metrics *telemetry.Metrics, logger *slog.Logger, cfg DispatcherConfig) *Dispatcher {
	def := DefaultDispatcherConfig()
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = def.PollInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = def.BatchSize
	}
	if cfg.PublishTimeout <= 0 {
		cfg.PublishTimeout = def.PublishTimeout
	}
	if cfg.RedispatchAfter <= 0 {
		cfg.RedispatchAfter = def.RedispatchAfter
	}
	if cfg.MaxRedispatches <= 0 {
		cfg.MaxRedispatches = def.MaxRedispatches
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = def.ReconcileInterval
	}
	if cfg.RunningStaleAfter <= 0 {
		cfg.RunningStaleAfter = def.RunningStaleAfter
	}
	if cfg.WorkerLiveWindow <= 0 {
		cfg.WorkerLiveWindow = def.WorkerLiveWindow
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{store: store, auditor: auditor, publisher: publisher, metrics: metrics, logger: logger, cfg: cfg}
}

// Run publishes pending dispatches every PollInterval and reconciles every
// ReconcileInterval until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	poll := time.NewTicker(d.cfg.PollInterval)
	defer poll.Stop()
	reconcile := time.NewTicker(d.cfg.ReconcileInterval)
	defer reconcile.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if _, err := d.PublishPending(ctx); err != nil && ctx.Err() == nil {
				d.logger.Error("publish pending remediation dispatches", "error", err)
			}
		case <-reconcile.C:
			if _, err := d.Reconcile(ctx); err != nil && ctx.Err() == nil {
				d.logger.Error("reconcile queued remediations", "error", err)
			}
		}
	}
}

// Job builds the JetStream event for one dispatch of a remediation.
func Job(remediation incidents.RemediationAction, dispatchID string) queue.Event {
	return queue.Event{
		EventID:        dispatchID,
		EventType:      queue.RemediationSubject,
		OccurredAt:     time.Now().UTC(),
		Producer:       "argus-api",
		IdempotencyKey: remediation.IdempotencyKey,
		Payload: map[string]any{
			"remediation_id": remediation.ID,
			"incident_id":    remediation.IncidentID,
			"dry_run":        remediation.DryRun,
			"executor":       "local",
		},
	}
}

// Enqueue writes a pending dispatch inside tx. The caller's transaction
// decides whether it exists: commit it together with the state change that
// requires the job.
func Enqueue(ctx context.Context, tx *sql.Tx, remediation incidents.RemediationAction, dispatchID, reason string) error {
	event := Job(remediation, dispatchID)
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode remediation job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_dispatches (id, remediation_id, reason, subject, event)
		VALUES ($1, $2, $3, $4, $5)
	`, dispatchID, remediation.ID, reason, queue.RemediationSubject, body); err != nil {
		return fmt.Errorf("enqueue remediation dispatch: %w", err)
	}
	return nil
}

type pendingDispatch struct {
	id, remediationID, subject, status string
	event                              queue.Event
	attempts                           int
}

// PublishOne publishes one pending dispatch now, if no other replica holds
// it. Execute calls it right after committing so the usual path has no poll
// delay; a failure leaves the row for the poll loop.
func (d *Dispatcher) PublishOne(ctx context.Context, dispatchID string) error {
	_, err := d.publish(ctx, dispatchID)
	return err
}

// PublishPending publishes up to BatchSize due dispatches and returns how
// many JetStream accepted.
func (d *Dispatcher) PublishPending(ctx context.Context) (int, error) {
	return d.publish(ctx, "")
}

func (d *Dispatcher) publish(ctx context.Context, onlyID string) (int, error) {
	published := 0
	err := d.store.InTx(ctx, func(tx *incidents.Store) error {
		rows, err := tx.Tx().QueryContext(ctx, `
			SELECT d.id, d.remediation_id, d.subject, d.event::text, d.attempts, r.status
			FROM remediation_dispatches d
			JOIN remediation_actions r ON r.id = d.remediation_id
			WHERE d.state = 'pending' AND d.next_attempt_at <= now() AND ($1 = '' OR d.id = $1)
			ORDER BY d.created_at
			LIMIT $2
			FOR UPDATE OF d SKIP LOCKED
		`, onlyID, d.cfg.BatchSize)
		if err != nil {
			return fmt.Errorf("select pending dispatches: %w", err)
		}
		var batch []pendingDispatch
		for rows.Next() {
			var p pendingDispatch
			var raw string
			if err := rows.Scan(&p.id, &p.remediationID, &p.subject, &raw, &p.attempts, &p.status); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal([]byte(raw), &p.event); err != nil {
				rows.Close()
				return fmt.Errorf("decode dispatch %s: %w", p.id, err)
			}
			batch = append(batch, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, p := range batch {
			if p.status != StateQueued && p.status != StateRunning {
				// Cancelled, timed out or finished: publishing would only
				// make a worker skip it.
				if _, err := tx.Tx().ExecContext(ctx, `
					UPDATE remediation_dispatches SET state = 'skipped', last_error = $2 WHERE id = $1
				`, p.id, "remediation is "+p.status); err != nil {
					return err
				}
				d.count("skipped")
				continue
			}
			publishCtx, cancel := context.WithTimeout(ctx, d.cfg.PublishTimeout)
			_, pubErr := d.publisher.Publish(publishCtx, p.subject, p.event)
			cancel()
			if pubErr != nil {
				attempts := p.attempts + 1
				if _, err := tx.Tx().ExecContext(ctx, `
					UPDATE remediation_dispatches
					SET attempts = $2, last_error = $3, next_attempt_at = now() + make_interval(secs => $4)
					WHERE id = $1
				`, p.id, attempts, pubErr.Error(), dispatchBackoff(attempts).Seconds()); err != nil {
					return err
				}
				d.count("failed")
				// JetStream is most likely unavailable; leave the rest of
				// the batch for the next poll instead of timing out on each.
				return nil
			}
			if _, err := tx.Tx().ExecContext(ctx, `
				UPDATE remediation_dispatches
				SET state = 'published', published_at = now(), attempts = attempts + 1, last_error = NULL
				WHERE id = $1
			`, p.id); err != nil {
				return err
			}
			published++
			d.count("published")
		}
		return nil
	})
	return published, err
}

// dispatchBackoff spaces publish retries: 1s, 2s, 4s ... capped at 30s.
func dispatchBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := time.Second << min(attempts-1, 5)
	return min(delay, 30*time.Second)
}

func (d *Dispatcher) count(result string) {
	if d.metrics != nil {
		d.metrics.RemediationDispatchesTotal.WithLabelValues(result).Inc()
	}
}

// ReconcileResult reports one reconciler pass.
type ReconcileResult struct {
	Redispatched []string
	Exhausted    []string
	// WaitingForWorker lists stuck remediations left alone because no live
	// worker supports their action.
	WaitingForWorker []string
}

// ErrNotDispatchable means a dispatch was requested for a remediation that
// is neither queued nor running.
var ErrNotDispatchable = errors.New("remediation is not queued or running")

// Dispatchable reports whether a job can be (re-)sent for a remediation in
// this status. Re-sending a running one is safe: the worker re-claims it and
// the execution receipt turns a repeat into a reuse.
func Dispatchable(status string) bool { return status == StateQueued || status == StateRunning }

// Redispatch writes a new dispatch for a queued or running remediation in
// its own transaction, with an audit entry. Replaying a dead letter uses it.
func (d *Dispatcher) Redispatch(ctx context.Context, remediationID, reason, actorID, actorType string, metadata map[string]any) (string, error) {
	var dispatchID string
	err := d.store.InTx(ctx, func(tx *incidents.Store) error {
		var err error
		dispatchID, err = d.redispatchTx(ctx, tx, remediationID, reason, actorID, actorType, metadata)
		return err
	})
	if err != nil {
		return "", err
	}
	_ = d.PublishOne(ctx, dispatchID)
	return dispatchID, nil
}

func (d *Dispatcher) redispatchTx(ctx context.Context, tx *incidents.Store, remediationID, reason, actorID, actorType string, metadata map[string]any) (string, error) {
	var status string
	var count int
	if err := tx.Tx().QueryRowContext(ctx, `
		SELECT r.status, (SELECT count(*) FROM remediation_dispatches d WHERE d.remediation_id = r.id)
		FROM remediation_actions r WHERE r.id = $1 FOR UPDATE
	`, remediationID).Scan(&status, &count); err != nil {
		return "", err
	}
	if !Dispatchable(status) {
		return "", fmt.Errorf("%w: it is %s", ErrNotDispatchable, status)
	}
	rem, err := tx.GetRemediation(ctx, remediationID)
	if err != nil {
		return "", err
	}
	dispatchID := fmt.Sprintf("%s#%s-%d", reservationEventID(rem), reason, count+1)
	if err := Enqueue(ctx, tx.Tx(), rem, dispatchID, reason); err != nil {
		return "", err
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["dispatch_id"] = dispatchID
	metadata["reason"] = reason
	return dispatchID, audit.WriteTx(ctx, tx.Tx(), audit.Entry{
		ActorID: actorID, ActorType: actorType, Action: "remediation.redispatched", ResourceType: "remediation", ResourceID: remediationID,
		BeforeState: map[string]any{"status": status},
		AfterState:  map[string]any{"status": status},
		Metadata:    metadata,
	})
}

// Reconcile finds two kinds of stuck remediation, each with no pending
// dispatch and no publish within RedispatchAfter:
//
//   - queued for RedispatchAfter: no worker took the job (it was
//     dead-lettered, expired, or lost with the JetStream node);
//   - running for RunningStaleAfter: the worker that claimed it died, and
//     its job was dead-lettered instead of redelivered.
//
// It re-sends the job up to MaxRedispatches times since the last execute or
// replay, then marks the remediation timed_out: a job nobody completed for
// that long should not run later by surprise. Re-sending a running
// remediation is safe because the worker re-claims it and its execution
// receipt makes a repeat a reuse. Only while a live worker supports the
// action does any of this happen; otherwise the remediation waits, counted
// in argus_remediation_waiting_for_worker. Remediations queued before the
// outbox existed have no dispatch row and are re-sent the same way; running
// ones without a dispatch row are left alone, since they may belong to a
// synchronous executor.
func (d *Dispatcher) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var result ReconcileResult
	err := d.store.InTx(ctx, func(tx *incidents.Store) error {
		var locked bool
		if err := tx.Tx().QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('argus_remediation_reconcile'))`).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return nil // another replica is reconciling
		}
		var oldest sql.NullFloat64
		if err := tx.Tx().QueryRowContext(ctx, `
			SELECT EXTRACT(EPOCH FROM now() - min(created_at)) FROM remediation_dispatches WHERE state = 'pending'
		`).Scan(&oldest); err != nil {
			return err
		}
		if d.metrics != nil {
			d.metrics.RemediationOutboxOldestPendingSeconds.Set(oldest.Float64)
		}

		after := d.cfg.RedispatchAfter.Seconds()
		rows, err := tx.Tx().QueryContext(ctx, `
			SELECT r.id, r.status,
				(SELECT count(*) FROM remediation_dispatches d
				 WHERE d.remediation_id = r.id AND d.reason = 'redispatch'
				   AND d.created_at > COALESCE((SELECT max(x.created_at) FROM remediation_dispatches x
				                                WHERE x.remediation_id = r.id AND x.reason <> 'redispatch'), '-infinity')),
				EXISTS (SELECT 1 FROM worker_heartbeats w
				        WHERE w.last_heartbeat_at > now() - make_interval(secs => $3)
				          AND r.action_type = ANY(w.supported_actions))
			FROM remediation_actions r
			WHERE ((r.status = 'queued' AND r.queued_at < now() - make_interval(secs => $1))
			    OR (r.status = 'running' AND r.started_at < now() - make_interval(secs => $2)
			        AND EXISTS (SELECT 1 FROM remediation_dispatches d0 WHERE d0.remediation_id = r.id)))
			  AND NOT EXISTS (
				SELECT 1 FROM remediation_dispatches d
				WHERE d.remediation_id = r.id
				  AND (d.state = 'pending' OR d.created_at > now() - make_interval(secs => $1) OR d.published_at > now() - make_interval(secs => $1)))
			ORDER BY r.queued_at
			LIMIT 100
			FOR UPDATE OF r SKIP LOCKED
		`, after, d.cfg.RunningStaleAfter.Seconds(), d.cfg.WorkerLiveWindow.Seconds())
		if err != nil {
			return fmt.Errorf("find stuck remediations: %w", err)
		}
		type stuck struct {
			id, status   string
			redispatches int
			hasWorker    bool
		}
		var found []stuck
		for rows.Next() {
			var s stuck
			if err := rows.Scan(&s.id, &s.status, &s.redispatches, &s.hasWorker); err != nil {
				rows.Close()
				return err
			}
			found = append(found, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, s := range found {
			if !s.hasWorker {
				result.WaitingForWorker = append(result.WaitingForWorker, s.id)
				continue
			}
			if s.redispatches >= d.cfg.MaxRedispatches {
				reason := fmt.Sprintf("no worker completed the job after %d redispatches", s.redispatches)
				if err := requireApplied(tx.CompleteRemediation(ctx, s.id, StateTimedOut, map[string]any{"reason": reason}, reason)); err != nil {
					return err
				}
				if err := audit.WriteTx(ctx, tx.Tx(), audit.Entry{
					ActorType: "system", Action: "remediation.dispatch_exhausted", ResourceType: "remediation", ResourceID: s.id,
					BeforeState: map[string]any{"status": s.status},
					AfterState:  map[string]any{"status": StateTimedOut, "error": reason},
				}); err != nil {
					return err
				}
				result.Exhausted = append(result.Exhausted, s.id)
				continue
			}
			if _, err := d.redispatchTx(ctx, tx, s.id, DispatchRedispatch, "", "system", map[string]any{
				"redispatch": s.redispatches + 1, "max_redispatches": d.cfg.MaxRedispatches, "stuck_in": s.status,
			}); err != nil {
				return err
			}
			result.Redispatched = append(result.Redispatched, s.id)
		}
		return nil
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	if d.metrics != nil {
		d.metrics.RemediationRedispatchesTotal.WithLabelValues("redispatched").Add(float64(len(result.Redispatched)))
		d.metrics.RemediationRedispatchesTotal.WithLabelValues("exhausted").Add(float64(len(result.Exhausted)))
		d.metrics.RemediationWaitingForWorker.Set(float64(len(result.WaitingForWorker)))
	}
	if len(result.WaitingForWorker) > 0 {
		d.logger.Warn("remediations are waiting for a live worker that supports their action", "remediations", result.WaitingForWorker)
	}
	for _, id := range result.Exhausted {
		d.logger.Warn("remediation timed out waiting for a worker", "remediation_id", id)
	}
	if len(result.Redispatched) > 0 {
		d.logger.Warn("re-sent remediation jobs no worker picked up", "remediations", result.Redispatched)
		if _, err := d.PublishPending(ctx); err != nil {
			d.logger.Error("publish redispatched jobs", "error", err)
		}
	}
	return result, nil
}
