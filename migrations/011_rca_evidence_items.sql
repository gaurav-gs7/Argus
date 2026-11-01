-- Structured RCA evidence: every matched alert and backend probe behind a
-- report, plus the confidence arithmetic. Mirrors internal/db/db.go Migrate.
ALTER TABLE rca_reports ADD COLUMN IF NOT EXISTS evidence_items JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE rca_reports ADD COLUMN IF NOT EXISTS score_breakdown JSONB NOT NULL DEFAULT '{}'::jsonb;
