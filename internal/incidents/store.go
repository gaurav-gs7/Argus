package incidents

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gauravgs7/argus/internal/common"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) EnsureService(ctx context.Context, name string) (Service, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, owner, tier, environment, slo_availability, slo_latency_p95_ms, runbook_id, created_at
		FROM services WHERE name = $1
	`, name)

	var svc Service
	err := row.Scan(&svc.ID, &svc.Name, &svc.Owner, &svc.Tier, &svc.Environment, &svc.SLOAvailability, &svc.SLOLatencyP95MS, &svc.RunbookID, &svc.CreatedAt)
	if err == nil {
		return svc, nil
	}
	if err != sql.ErrNoRows {
		return Service{}, fmt.Errorf("query service: %w", err)
	}

	svc = Service{
		ID:          common.NewID("svc"),
		Name:        name,
		Tier:        "tier1",
		Environment: "local",
		CreatedAt:   time.Now().UTC(),
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO services (id, name, owner, tier, environment, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, svc.ID, svc.Name, svc.Owner, svc.Tier, svc.Environment, svc.CreatedAt); err != nil {
		return Service{}, fmt.Errorf("insert service: %w", err)
	}
	return svc, nil
}

func (s *Store) CreateManualIncident(ctx context.Context, req ManualIncidentRequest) (Incident, error) {
	service, err := s.EnsureService(ctx, req.Service)
	if err != nil {
		return Incident{}, err
	}

	now := time.Now().UTC()
	incident := Incident{
		ID:          common.NewID("inc"),
		Title:       req.Title,
		ServiceID:   service.ID,
		Service:     service.Name,
		Severity:    defaultSeverity(req.Severity),
		Status:      StatusDetected,
		DedupeKey:   fmt.Sprintf("%s:manual:%s:manual", service.Name, req.Title),
		Fingerprint: common.NewID("fp"),
		StartedAt:   now,
		DetectedAt:  now,
		Summary:     req.Summary,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, service_id, severity, status, dedupe_key, fingerprint,
			started_at, detected_at, summary, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`,
		incident.ID, incident.Title, incident.ServiceID, incident.Severity, incident.Status, incident.DedupeKey,
		incident.Fingerprint, incident.StartedAt, incident.DetectedAt, incident.Summary, incident.CreatedAt, incident.UpdatedAt,
	)
	if err != nil {
		return Incident{}, fmt.Errorf("insert incident: %w", err)
	}

	return incident, nil
}

func (s *Store) FindOpenByDedupeKey(ctx context.Context, dedupeKey string, window time.Duration) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT i.id, i.title, i.service_id, s.name, i.severity, i.status, i.dedupe_key, i.fingerprint,
		       i.started_at, i.detected_at, i.resolved_at, i.summary, i.created_at, i.updated_at
		FROM incidents i
		LEFT JOIN services s ON s.id = i.service_id
		WHERE i.dedupe_key = $1
		  AND i.status NOT IN ('resolved', 'cancelled')
		  AND i.started_at >= now() - $2::interval
		ORDER BY i.started_at DESC
		LIMIT 1
	`, dedupeKey, intervalLiteral(window))

	var incident Incident
	err := row.Scan(
		&incident.ID, &incident.Title, &incident.ServiceID, &incident.Service, &incident.Severity, &incident.Status,
		&incident.DedupeKey, &incident.Fingerprint, &incident.StartedAt, &incident.DetectedAt, &incident.ResolvedAt,
		&incident.Summary, &incident.CreatedAt, &incident.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find incident by dedupe key: %w", err)
	}
	return &incident, nil
}

func (s *Store) CreateAlertIncident(ctx context.Context, title, serviceName, severity, dedupeKey, fingerprint, summary string, startedAt time.Time) (Incident, error) {
	service, err := s.EnsureService(ctx, serviceName)
	if err != nil {
		return Incident{}, err
	}

	now := time.Now().UTC()
	incident := Incident{
		ID:          common.NewID("inc"),
		Title:       title,
		ServiceID:   service.ID,
		Service:     service.Name,
		Severity:    defaultSeverity(severity),
		Status:      StatusDetected,
		DedupeKey:   dedupeKey,
		Fingerprint: fingerprint,
		StartedAt:   startedAt.UTC(),
		DetectedAt:  now,
		Summary:     summary,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, service_id, severity, status, dedupe_key, fingerprint,
			started_at, detected_at, summary, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`,
		incident.ID, incident.Title, incident.ServiceID, incident.Severity, incident.Status, incident.DedupeKey,
		incident.Fingerprint, incident.StartedAt, incident.DetectedAt, incident.Summary, incident.CreatedAt, incident.UpdatedAt,
	)
	if err != nil {
		return Incident{}, fmt.Errorf("insert alert incident: %w", err)
	}
	return incident, nil
}

func (s *Store) AddSignal(ctx context.Context, signal Signal) error {
	if signal.ID == "" {
		signal.ID = common.NewID("sig")
	}
	if signal.CreatedAt.IsZero() {
		signal.CreatedAt = time.Now().UTC()
	}
	bodyJSON, _ := json.Marshal(signal.Body)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO signals (
			id, incident_id, service_id, source, signal_type, severity, name, body, observed_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, signal.ID, signal.IncidentID, signal.ServiceID, signal.Source, signal.SignalType, signal.Severity, signal.Name, bodyJSON, signal.ObservedAt, signal.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert signal: %w", err)
	}
	return nil
}

func (s *Store) AddTimelineEvent(ctx context.Context, event TimelineEvent) error {
	if event.ID == "" {
		event.ID = common.NewID("tme")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	evidenceJSON, _ := json.Marshal(event.Evidence)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_timeline_events (
			id, incident_id, event_type, source, summary, evidence, confidence, occurred_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, event.ID, event.IncidentID, event.EventType, event.Source, event.Summary, evidenceJSON, event.Confidence, event.OccurredAt, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert timeline event: %w", err)
	}
	return nil
}

func (s *Store) ListIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.id, i.title, i.service_id, COALESCE(s.name, ''), i.severity, i.status, i.dedupe_key,
		       i.fingerprint, i.started_at, i.detected_at, i.resolved_at, COALESCE(i.summary, ''),
		       i.created_at, i.updated_at
		FROM incidents i
		LEFT JOIN services s ON s.id = i.service_id
		ORDER BY i.started_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var incidents []Incident
	for rows.Next() {
		var incident Incident
		if err := rows.Scan(
			&incident.ID, &incident.Title, &incident.ServiceID, &incident.Service, &incident.Severity, &incident.Status, &incident.DedupeKey,
			&incident.Fingerprint, &incident.StartedAt, &incident.DetectedAt, &incident.ResolvedAt, &incident.Summary,
			&incident.CreatedAt, &incident.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		incidents = append(incidents, incident)
	}
	return incidents, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, incidentID string) (Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT i.id, i.title, i.service_id, COALESCE(s.name, ''), i.severity, i.status, i.dedupe_key,
		       i.fingerprint, i.started_at, i.detected_at, i.resolved_at, COALESCE(i.summary, ''),
		       i.created_at, i.updated_at
		FROM incidents i
		LEFT JOIN services s ON s.id = i.service_id
		WHERE i.id = $1
	`, incidentID)

	var incident Incident
	if err := row.Scan(
		&incident.ID, &incident.Title, &incident.ServiceID, &incident.Service, &incident.Severity, &incident.Status, &incident.DedupeKey,
		&incident.Fingerprint, &incident.StartedAt, &incident.DetectedAt, &incident.ResolvedAt, &incident.Summary,
		&incident.CreatedAt, &incident.UpdatedAt,
	); err != nil {
		return Incident{}, fmt.Errorf("get incident: %w", err)
	}
	return incident, nil
}

func (s *Store) UpdateIncidentStatus(ctx context.Context, incidentID, status string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET status = $2, updated_at = now(),
		    resolved_at = CASE WHEN $2 = 'resolved' THEN now() ELSE resolved_at END
		WHERE id = $1
	`, incidentID, status)
	if err != nil {
		return fmt.Errorf("update incident status: %w", err)
	}
	return nil
}

func (s *Store) ListSignals(ctx context.Context, incidentID string) ([]Signal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, incident_id, service_id, source, signal_type, severity, name, body, observed_at, created_at
		FROM signals
		WHERE incident_id = $1
		ORDER BY observed_at ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list signals: %w", err)
	}
	defer rows.Close()

	var items []Signal
	for rows.Next() {
		var item Signal
		var bodyJSON []byte
		if err := rows.Scan(&item.ID, &item.IncidentID, &item.ServiceID, &item.Source, &item.SignalType, &item.Severity, &item.Name, &bodyJSON, &item.ObservedAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan signal: %w", err)
		}
		_ = json.Unmarshal(bodyJSON, &item.Body)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListTimeline(ctx context.Context, incidentID string) ([]TimelineEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, incident_id, event_type, source, summary, evidence, confidence, occurred_at, created_at
		FROM incident_timeline_events
		WHERE incident_id = $1
		ORDER BY occurred_at ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list timeline: %w", err)
	}
	defer rows.Close()

	var items []TimelineEvent
	for rows.Next() {
		var item TimelineEvent
		var evidenceJSON []byte
		if err := rows.Scan(&item.ID, &item.IncidentID, &item.EventType, &item.Source, &item.Summary, &evidenceJSON, &item.Confidence, &item.OccurredAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan timeline event: %w", err)
		}
		_ = json.Unmarshal(evidenceJSON, &item.Evidence)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) SaveRCAReport(ctx context.Context, report RCAReport) error {
	if report.ID == "" {
		report.ID = common.NewID("rca")
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	factorsJSON, _ := json.Marshal(report.ContributingFactors)
	evidenceJSON, _ := json.Marshal(report.Evidence)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rca_reports (
			id, incident_id, deterministic_summary, llm_summary, primary_hypothesis,
			contributing_factors, evidence, confidence, model_backend, model_name, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, report.ID, report.IncidentID, report.DeterministicSummary, report.LLMSummary, report.PrimaryHypothesis,
		factorsJSON, evidenceJSON, report.Confidence, report.ModelBackend, report.ModelName, report.CreatedAt)
	if err != nil {
		return fmt.Errorf("save rca report: %w", err)
	}
	return nil
}

func (s *Store) GetLatestRCAReport(ctx context.Context, incidentID string) (RCAReport, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, deterministic_summary, COALESCE(llm_summary, ''), COALESCE(primary_hypothesis, ''),
		       contributing_factors, evidence, COALESCE(confidence, 0), COALESCE(model_backend, ''), COALESCE(model_name, ''), created_at
		FROM rca_reports
		WHERE incident_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, incidentID)

	var report RCAReport
	var factorsJSON, evidenceJSON []byte
	if err := row.Scan(
		&report.ID, &report.IncidentID, &report.DeterministicSummary, &report.LLMSummary, &report.PrimaryHypothesis,
		&factorsJSON, &evidenceJSON, &report.Confidence, &report.ModelBackend, &report.ModelName, &report.CreatedAt,
	); err != nil {
		return RCAReport{}, fmt.Errorf("get rca report: %w", err)
	}

	_ = json.Unmarshal(factorsJSON, &report.ContributingFactors)
	_ = json.Unmarshal(evidenceJSON, &report.Evidence)
	return report, nil
}

func (s *Store) CreateRemediation(ctx context.Context, action RemediationAction) error {
	if action.ID == "" {
		action.ID = common.NewID("rem")
	}
	if action.CreatedAt.IsZero() {
		action.CreatedAt = time.Now().UTC()
	}
	policyJSON, _ := json.Marshal(action.PolicyDecision)
	resultJSON, _ := json.Marshal(action.Result)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO remediation_actions (
			id, incident_id, action_type, target, status, risk, idempotency_key,
			proposed_by, approved_by, policy_decision, dry_run, attempt, max_attempts,
			queued_at, started_at, completed_at, result, error, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
	`, action.ID, action.IncidentID, action.ActionType, action.Target, action.Status, action.Risk, action.IdempotencyKey,
		action.ProposedBy, nullable(action.ApprovedBy), policyJSON, action.DryRun, action.Attempt, action.MaxAttempts,
		action.QueuedAt, action.StartedAt, action.CompletedAt, resultJSON, nullable(action.Error), action.CreatedAt)
	if err != nil {
		return fmt.Errorf("create remediation: %w", err)
	}
	return nil
}

func (s *Store) ListRemediations(ctx context.Context, incidentID string) ([]RemediationAction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, incident_id, action_type, target, status, risk, idempotency_key,
		       proposed_by, COALESCE(approved_by, ''), policy_decision, dry_run, attempt,
		       max_attempts, queued_at, started_at, completed_at, result, COALESCE(error, ''), created_at
		FROM remediation_actions
		WHERE incident_id = $1
		ORDER BY created_at ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list remediations: %w", err)
	}
	defer rows.Close()

	var items []RemediationAction
	for rows.Next() {
		var item RemediationAction
		var policyJSON, resultJSON []byte
		if err := rows.Scan(
			&item.ID, &item.IncidentID, &item.ActionType, &item.Target, &item.Status, &item.Risk, &item.IdempotencyKey,
			&item.ProposedBy, &item.ApprovedBy, &policyJSON, &item.DryRun, &item.Attempt, &item.MaxAttempts,
			&item.QueuedAt, &item.StartedAt, &item.CompletedAt, &resultJSON, &item.Error, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan remediation: %w", err)
		}
		_ = json.Unmarshal(policyJSON, &item.PolicyDecision)
		_ = json.Unmarshal(resultJSON, &item.Result)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetRemediation(ctx context.Context, remediationID string) (RemediationAction, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, action_type, target, status, risk, idempotency_key,
		       proposed_by, COALESCE(approved_by, ''), policy_decision, dry_run, attempt,
		       max_attempts, queued_at, started_at, completed_at, result, COALESCE(error, ''), created_at
		FROM remediation_actions
		WHERE id = $1
	`, remediationID)

	item, err := scanRemediation(row)
	if err != nil {
		return RemediationAction{}, fmt.Errorf("get remediation: %w", err)
	}
	return item, nil
}

func (s *Store) CountRecentSimilarRemediations(ctx context.Context, incidentID, actionType, target string) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM remediation_actions
		WHERE incident_id = $1
		  AND action_type = $2
		  AND target = $3
		  AND created_at >= now() - interval '10 minutes'
	`, incidentID, actionType, target)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count recent remediations: %w", err)
	}
	return count, nil
}

func (s *Store) FindActiveRemediationByAction(ctx context.Context, incidentID, actionType, target string) (*RemediationAction, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, action_type, target, status, risk, idempotency_key,
		       proposed_by, COALESCE(approved_by, ''), policy_decision, dry_run, attempt,
		       max_attempts, queued_at, started_at, completed_at, result, COALESCE(error, ''), created_at
		FROM remediation_actions
		WHERE incident_id = $1
		  AND action_type = $2
		  AND target = $3
		  AND status NOT IN ('policy_blocked', 'rejected', 'succeeded', 'failed', 'timed_out', 'cancelled')
		ORDER BY created_at DESC
		LIMIT 1
	`, incidentID, actionType, target)

	item, err := scanRemediation(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find active remediation: %w", err)
	}
	return &item, nil
}

func (s *Store) CountFailedRemediations(ctx context.Context, incidentID, actionType, target string) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM remediation_actions
		WHERE incident_id = $1
		  AND action_type = $2
		  AND target = $3
		  AND status IN ('failed', 'timed_out')
	`, incidentID, actionType, target)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count failed remediations: %w", err)
	}
	return count, nil
}

func (s *Store) UpdateRemediationApproval(ctx context.Context, remediationID, status, approvedBy string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE remediation_actions
		SET status = $2, approved_by = NULLIF($3, '')
		WHERE id = $1
	`, remediationID, status, approvedBy)
	if err != nil {
		return fmt.Errorf("update remediation approval: %w", err)
	}
	return nil
}

func (s *Store) MarkRemediationQueued(ctx context.Context, remediationID string, dryRun bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE remediation_actions
		SET status = 'queued', queued_at = now(), dry_run = $2
		WHERE id = $1
	`, remediationID, dryRun)
	if err != nil {
		return fmt.Errorf("mark remediation queued: %w", err)
	}
	return nil
}

func (s *Store) MarkRemediationRunning(ctx context.Context, remediationID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE remediation_actions
		SET status = 'running', started_at = now()
		WHERE id = $1
	`, remediationID)
	if err != nil {
		return fmt.Errorf("mark remediation running: %w", err)
	}
	return nil
}

func (s *Store) CompleteRemediation(ctx context.Context, remediationID, status string, result map[string]any, execErr string) error {
	resultJSON, _ := json.Marshal(result)
	_, err := s.db.ExecContext(ctx, `
		UPDATE remediation_actions
		SET status = $2, completed_at = now(), result = $3, error = NULLIF($4, '')
		WHERE id = $1
	`, remediationID, status, resultJSON, execErr)
	if err != nil {
		return fmt.Errorf("complete remediation: %w", err)
	}
	return nil
}

func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, owner, tier, environment, slo_availability, slo_latency_p95_ms, runbook_id, created_at
		FROM services
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	defer rows.Close()

	var items []Service
	for rows.Next() {
		var item Service
		if err := rows.Scan(&item.ID, &item.Name, &item.Owner, &item.Tier, &item.Environment, &item.SLOAvailability, &item.SLOLatencyP95MS, &item.RunbookID, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListRunbooks(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, service_id, title, path, version, created_at
		FROM runbooks
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list runbooks: %w", err)
	}
	defer rows.Close()

	var items []map[string]any
	for rows.Next() {
		var id, serviceID, title, path string
		var version int
		var createdAt time.Time
		if err := rows.Scan(&id, &serviceID, &title, &path, &version, &createdAt); err != nil {
			return nil, fmt.Errorf("scan runbook: %w", err)
		}
		items = append(items, map[string]any{
			"id":         id,
			"service_id": serviceID,
			"title":      title,
			"path":       path,
			"version":    version,
			"created_at": createdAt,
		})
	}
	return items, rows.Err()
}

func (s *Store) UpsertWorkerHeartbeat(ctx context.Context, workerID, hostname string, at time.Time, supportedActions []string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO worker_heartbeats (
			worker_id, hostname, version, supported_actions, running_jobs, last_heartbeat_at, status
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (worker_id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			version = EXCLUDED.version,
			supported_actions = EXCLUDED.supported_actions,
			running_jobs = EXCLUDED.running_jobs,
			last_heartbeat_at = EXCLUDED.last_heartbeat_at,
			status = EXCLUDED.status
	`, workerID, hostname, "v1", supportedActions, 0, at, "healthy")
	if err != nil {
		return fmt.Errorf("upsert worker heartbeat: %w", err)
	}
	return nil
}

type remediationScanner interface {
	Scan(dest ...any) error
}

func scanRemediation(row remediationScanner) (RemediationAction, error) {
	var item RemediationAction
	var policyJSON, resultJSON []byte
	if err := row.Scan(
		&item.ID, &item.IncidentID, &item.ActionType, &item.Target, &item.Status, &item.Risk, &item.IdempotencyKey,
		&item.ProposedBy, &item.ApprovedBy, &policyJSON, &item.DryRun, &item.Attempt, &item.MaxAttempts,
		&item.QueuedAt, &item.StartedAt, &item.CompletedAt, &resultJSON, &item.Error, &item.CreatedAt,
	); err != nil {
		return RemediationAction{}, err
	}
	_ = json.Unmarshal(policyJSON, &item.PolicyDecision)
	_ = json.Unmarshal(resultJSON, &item.Result)
	return item, nil
}

func defaultSeverity(value string) string {
	switch value {
	case "sev1", "sev2", "sev3", "sev4":
		return value
	default:
		return "sev3"
	}
}

func intervalLiteral(window time.Duration) string {
	return fmt.Sprintf("%f seconds", window.Seconds())
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
