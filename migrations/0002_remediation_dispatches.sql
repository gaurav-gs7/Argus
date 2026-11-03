-- Transactional outbox for remediation jobs.
--
-- Execute writes a dispatch row in the same transaction that moves the
-- remediation to queued, so a crash between the reservation and the JetStream
-- publish can no longer strand it: the dispatcher publishes pending rows until
-- JetStream acknowledges them. The row id is the Nats-Msg-Id, so a publish
-- repeated after a lost acknowledgement is stored once.
--
-- reason: execute (the reservation), redispatch (the reconciler re-sent a job
-- for a remediation that stayed queued), replay (an operator replayed a dead
-- letter).
CREATE TABLE IF NOT EXISTS remediation_dispatches (
    id TEXT PRIMARY KEY,
    remediation_id TEXT NOT NULL REFERENCES remediation_actions(id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (reason IN ('execute', 'redispatch', 'replay')),
    subject TEXT NOT NULL,
    event JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'published', 'skipped')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_remediation_dispatches_pending
    ON remediation_dispatches(next_attempt_at) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_remediation_dispatches_remediation
    ON remediation_dispatches(remediation_id, created_at DESC);
