-- Batch 4b: scan queue.
-- Run manually on OCI after code deploy (schema changes are never
-- auto-applied on redeploy - see LESSONS LEARNED #9 in the handoff doc):
--
--   docker compose exec -T db bash -c \
--     'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/add_scan_queue.sql
--
-- (bash -c wrapper so $POSTGRES_USER/$POSTGRES_DB expand INSIDE the
-- container, not in the outer OCI shell, which doesn't have them.)

CREATE TABLE IF NOT EXISTS scan_queue (
    id           SERIAL PRIMARY KEY,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    position     INTEGER NOT NULL,
    priority     BOOLEAN NOT NULL DEFAULT false,
    status       TEXT NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'completed', 'cancelled')),
    queued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- The worker loop always looks for "what's next" via this shape:
-- WHERE status = 'queued' ORDER BY priority DESC, position ASC
CREATE INDEX IF NOT EXISTS idx_scan_queue_next
    ON scan_queue (status, priority DESC, position ASC);

-- Only one row per project can be actively queued/running at a time -
-- clicking "scan" twice on the same project shouldn't create two queue
-- entries racing each other.
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_queue_one_active_per_project
    ON scan_queue (project_id)
    WHERE status IN ('queued', 'running');
