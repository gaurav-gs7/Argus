CREATE TABLE IF NOT EXISTS service_dependencies (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id),
    depends_on_service_id TEXT NOT NULL REFERENCES services(id),
    dependency_type TEXT NOT NULL CHECK (
        dependency_type IN ('synchronous', 'asynchronous', 'datastore', 'edge')
    ),
    criticality TEXT NOT NULL CHECK (
        criticality IN ('critical', 'degraded', 'optional')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(service_id, depends_on_service_id),
    CHECK(service_id <> depends_on_service_id)
);

CREATE INDEX IF NOT EXISTS idx_service_dependencies_service
    ON service_dependencies(service_id);
CREATE INDEX IF NOT EXISTS idx_service_dependencies_target
    ON service_dependencies(depends_on_service_id);

ALTER TABLE rca_reports
    ADD COLUMN IF NOT EXISTS topology_analysis JSONB NOT NULL DEFAULT '{}'::jsonb;
