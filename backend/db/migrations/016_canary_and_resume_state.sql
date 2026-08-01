-- 016_canary_and_resume_state.sql
--
-- Batch 25: synthetic canary target support.
-- Batch 26: per-project AI model override + idempotent scan resume.
--
-- Folded in from the loose batch25_26_migration.sql that used to sit at
-- repo root outside the numbered sequence (repo compaction pass).
--
-- Run manually, same as every other migration:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/migrations/016_canary_and_resume_state.sql

-- Batch 26 item 3: per-project AI model override. NULL (the default)
-- means "use the hardcoded _CHEAP_MODEL/_ESCALATION_MODEL as before" -
-- see triage.py's triage_finding docstring.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS preferred_ai_model TEXT;

-- Batch 25 item 4: synthetic canary target. A project flagged
-- is_canary=true is a known-stable, deliberately-vulnerable test
-- target (NOT a real bug bounty program) scanned like any other -
-- canary_baseline_finding_count is the expected finding count from
-- its first successful scan, used to detect pipeline regressions (a
-- code change that silently breaks a detective.py check would show up
-- as the canary's finding count suddenly dropping).
ALTER TABLE projects ADD COLUMN IF NOT EXISTS is_canary BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS canary_baseline_finding_count INTEGER;

-- Batch 26 item 4: idempotent scan resume. Snapshot of the in-memory
-- pipeline state (normally rebuilt fresh by probe/fuzz every run) so a
-- scan interrupted by a crash/redeploy can skip already-completed
-- phases on retrigger WITHOUT losing what those phases discovered -
-- see checkpoint.get_recently_completed_phases and pipeline.py's
-- _persist_pipeline_state_pooled/_load_pipeline_state.
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS state_live_hosts JSONB;
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS state_discovered_urls JSONB;
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS state_params_found JSONB;
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS state_tech_stack JSONB;
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS state_updated_at TIMESTAMPTZ;
