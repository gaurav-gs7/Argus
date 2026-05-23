CREATE TABLE IF NOT EXISTS runbooks (
    id TEXT PRIMARY KEY,
    service_id TEXT,
    title TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
