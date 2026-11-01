-- Alert lifecycle: per-incident alert state, activity-based grouping and an
-- explicit environment column. Mirrors internal/db/db.go Migrate.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS environment TEXT;
UPDATE incidents SET environment = CASE WHEN split_part(dedupe_key, ':', 2) = 'manual' THEN 'local' ELSE COALESCE(NULLIF(split_part(dedupe_key, ':', 3), ''), 'local') END WHERE environment IS NULL;
ALTER TABLE incidents ALTER COLUMN environment SET DEFAULT 'local';
ALTER TABLE incidents ALTER COLUMN environment SET NOT NULL;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alerts_cleared_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    dedupe_key TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    service TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('firing', 'resolved')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    PRIMARY KEY (incident_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_dedupe ON incident_alerts(dedupe_key, status);
