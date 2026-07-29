-- 011_ai_retry_queue.sql
-- Generic retry queue for AI calls that failed after generate_with_rotation
-- exhausted every Gemini model AND every tier-2 provider. Kept generic
-- (kind + JSONB payload) so future callers beyond triage.triage_finding
-- can reuse the same table instead of each growing their own bespoke
-- retry mechanism - see retry_queue.py's module docstring.
--
-- Idempotent, same pattern as prior migrations.

CREATE TABLE IF NOT EXISTS ai_retry_queue (
    id              SERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    error_type      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index: only 'pending' rows are ever queried by fetch_due(),
-- and there should never be many of those at once - no reason to index
-- the (potentially large, over time) 'succeeded'/'failed' history too.
CREATE INDEX IF NOT EXISTS idx_ai_retry_queue_due
    ON ai_retry_queue (kind, next_attempt_at)
    WHERE status = 'pending';
