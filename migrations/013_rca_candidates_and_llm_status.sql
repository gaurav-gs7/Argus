-- RCA reports persist their remediation candidates (so proposals reuse the
-- report) and the status of the asynchronous LLM summary.
-- Mirrors internal/db/db.go Migrate.
ALTER TABLE rca_reports ADD COLUMN IF NOT EXISTS candidates JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE rca_reports ADD COLUMN IF NOT EXISTS llm_status TEXT NOT NULL DEFAULT 'disabled';
