CREATE TABLE IF NOT EXISTS approval_requests (
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
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_request_remediation
    ON approval_requests(remediation_id);
CREATE INDEX IF NOT EXISTS idx_approval_pending_escalation
    ON approval_requests(escalates_at)
    WHERE status = 'pending' AND escalated_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_approval_pending_expiry
    ON approval_requests(expires_at)
    WHERE status = 'pending';
