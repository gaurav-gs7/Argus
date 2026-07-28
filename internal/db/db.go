package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

func Migrate(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS runbooks (
			id TEXT PRIMARY KEY,
			service_id TEXT,
			title TEXT NOT NULL,
			path TEXT NOT NULL,
			content TEXT NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS services (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			owner TEXT,
			tier TEXT NOT NULL CHECK (tier IN ('tier0', 'tier1', 'tier2', 'tier3')),
			environment TEXT NOT NULL DEFAULT 'local',
			slo_availability NUMERIC(5,2),
			slo_latency_p95_ms INTEGER,
			runbook_id TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			service_id TEXT REFERENCES services(id),
			severity TEXT NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3', 'sev4')),
			status TEXT NOT NULL,
			dedupe_key TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			resolved_at TIMESTAMPTZ,
			summary TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_dedupe_key ON incidents(dedupe_key);`,
		`CREATE TABLE IF NOT EXISTS signals (
			id TEXT PRIMARY KEY,
			incident_id TEXT REFERENCES incidents(id),
			service_id TEXT REFERENCES services(id),
			source TEXT NOT NULL CHECK (source IN ('prometheus', 'alertmanager', 'loki', 'otel', 'manual', 'deploy', 'config')),
			signal_type TEXT NOT NULL,
			severity TEXT,
			name TEXT NOT NULL,
			body JSONB NOT NULL,
			observed_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_incident_time ON signals(incident_id, observed_at);`,
		`CREATE TABLE IF NOT EXISTS incident_timeline_events (
			id TEXT PRIMARY KEY,
			incident_id TEXT REFERENCES incidents(id),
			event_type TEXT NOT NULL,
			source TEXT NOT NULL,
			summary TEXT NOT NULL,
			evidence JSONB NOT NULL,
			confidence NUMERIC(4,3),
			occurred_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS rca_reports (
			id TEXT PRIMARY KEY,
			incident_id TEXT REFERENCES incidents(id),
			deterministic_summary TEXT NOT NULL,
			llm_summary TEXT,
			primary_hypothesis TEXT,
			contributing_factors JSONB,
			evidence JSONB NOT NULL,
			confidence NUMERIC(4,3),
			model_backend TEXT,
			model_name TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE TABLE IF NOT EXISTS remediation_actions (
			id TEXT PRIMARY KEY,
			incident_id TEXT REFERENCES incidents(id),
			action_type TEXT NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			risk TEXT NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
			idempotency_key TEXT NOT NULL UNIQUE,
			proposed_by TEXT NOT NULL,
			approved_by TEXT,
			policy_decision JSONB NOT NULL,
			dry_run BOOLEAN NOT NULL DEFAULT true,
			attempt INTEGER NOT NULL DEFAULT 1,
			max_attempts INTEGER NOT NULL DEFAULT 1,
			queued_at TIMESTAMPTZ,
			started_at TIMESTAMPTZ,
			completed_at TIMESTAMPTZ,
			result JSONB,
			error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_incident ON remediation_actions(incident_id);`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_actions(status);`,
		`CREATE TABLE IF NOT EXISTS approval_requests (
			id TEXT PRIMARY KEY,
			remediation_id TEXT NOT NULL REFERENCES remediation_actions(id),
			incident_id TEXT NOT NULL REFERENCES incidents(id),
			action_type TEXT NOT NULL,
			target TEXT NOT NULL,
			risk TEXT NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
			status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
			requested_by TEXT NOT NULL,
			requested_at TIMESTAMPTZ NOT NULL,
			escalates_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			escalated_at TIMESTAMPTZ,
			decided_at TIMESTAMPTZ,
			decided_by TEXT,
			decision_reason TEXT,
			decision_source TEXT,
			notification_status TEXT NOT NULL DEFAULT 'pending',
			notification_attempts INTEGER NOT NULL DEFAULT 0,
			last_notification_error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_request_remediation ON approval_requests(remediation_id);`,
		`CREATE INDEX IF NOT EXISTS idx_approval_pending_escalation ON approval_requests(escalates_at) WHERE status = 'pending' AND escalated_at IS NULL;`,
		`CREATE INDEX IF NOT EXISTS idx_approval_pending_expiry ON approval_requests(expires_at) WHERE status = 'pending';`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			actor_id TEXT,
			actor_type TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT,
			request_id TEXT,
			ip_address TEXT,
			before_state JSONB,
			after_state JSONB,
			metadata JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS worker_heartbeats (
			worker_id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			version TEXT NOT NULL,
			supported_actions TEXT[] NOT NULL,
			running_jobs INTEGER NOT NULL DEFAULT 0,
			last_heartbeat_at TIMESTAMPTZ NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('healthy', 'stale', 'dead'))
		);`,
	}

	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate statement failed: %w", err)
		}
	}

	return nil
}
