-- "More valid bugs" pass (post-Batch 7), item 3 of 3: detective.py has
-- ~20 checks that are DELIBERATELY not auto-filed as findings - by
-- design, per each check's own docstring, because they're either
-- low-value-alone (clickjacking, missing SRI/HSTS/CSP - real gaps, but
-- almost always Informative without a demonstrated sensitive action) or
-- genuinely unconfirmed pattern matches needing a human look
-- (hardcoded-secret-shaped strings, excessive-data-exposure field
-- names, IDOR/predictable-token/deserialization candidates - a matched
-- pattern isn't confirmed exploitability).
--
-- That reasoning is sound. The bug is what happened next: pipeline.py
-- computed every one of these, correctly classified it as "not a
-- finding, needs a human look" - and then just called logger.info() and
-- moved on. Docker container logs on OCI are not a place an operator
-- ever looks. ~20 checks' worth of signal, including things like
-- "hardcoded credential pattern found in shipped JS", were being
-- computed on every scan and then permanently discarded.
--
-- This table is the fix: same "needs a human, not auto-filed as a
-- finding" design, but actually persisted and visible in the UI instead
-- of vanishing into a log line.
--
-- Run manually on OCI after code deploy:
--
--   docker compose exec -T postgres bash -c \
--     'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/add_scan_notes.sql

CREATE TABLE IF NOT EXISTS scan_notes (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id   INTEGER REFERENCES scope_targets(id) ON DELETE SET NULL,
    check_name  TEXT NOT NULL,
    -- e.g. "hardcoded_secrets_and_internal_disclosure" - which detective
    -- check produced this, so the UI can group/filter by it.
    note        TEXT NOT NULL,
    dismissed   BOOLEAN NOT NULL DEFAULT false,
    -- lets an operator clear noise from the list without deleting the
    -- row - same non-destructive pattern as findings.status, just
    -- boolean since there's no meaningful multi-state lifecycle here.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_notes_project ON scan_notes(project_id) WHERE NOT dismissed;
