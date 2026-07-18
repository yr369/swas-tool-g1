-- Batch 5: policy-gate outcome surfacing.
--
-- IMPORTANT CORRECTION to the original handoff doc's assumption: this
-- was NOT already computed-and-stored, just unexposed. triage.py's
-- prompt asks the model for "likely_program_outcome" and the raw JSON
-- parse keeps it in memory, but BOTH triage paths
-- (triage_project_findings - the batch/automatic path, and
-- triage_one_finding in main.py - the on-demand single-finding path)
-- only ever wrote `severity` back to the findings table. The
-- prediction itself, along with the reasoning behind it, was computed
-- and then thrown away every time. This migration + the accompanying
-- code changes are what actually persist it.
--
-- Run manually on OCI after code deploy (schema changes are never
-- auto-applied on redeploy):
--
--   docker compose exec -T postgres bash -c \
--     'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/add_triage_outcome_fields.sql

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS likely_program_outcome TEXT
        CHECK (likely_program_outcome IN ('accepted', 'informative', 'out_of_scope', 'duplicate')),
    ADD COLUMN IF NOT EXISTS triage_reasoning TEXT,
    ADD COLUMN IF NOT EXISTS triage_confidence REAL;

-- Findings-list views will filter/sort by this a lot (e.g. "show me
-- everything triage thinks is out_of_scope before I waste time on it")
CREATE INDEX IF NOT EXISTS idx_findings_likely_program_outcome
    ON findings (likely_program_outcome);
