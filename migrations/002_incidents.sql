CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    owner TEXT,
    tier TEXT NOT NULL CHECK (tier IN ('tier0', 'tier1', 'tier2', 'tier3')),
    environment TEXT NOT NULL DEFAULT 'local',
    slo_availability NUMERIC(5,2),
    slo_latency_p95_ms INTEGER,
    runbook_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidents (
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
);
