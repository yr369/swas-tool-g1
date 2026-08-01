-- 014_fix_phase_runs_constraint.sql
--
-- pipeline.py creates checkpoint rows with phase_name='triage', but the
-- CHECK constraint was never updated to allow it. This was silently
-- crashing every scan right as it entered the triage phase.
--
-- Folded in from the loose fix_phase_runs_constraint.sql that used to
-- sit at repo root outside the numbered sequence (repo compaction pass).
--
-- Run manually, same as every other migration:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/migrations/014_fix_phase_runs_constraint.sql

ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_phase_name_check;

ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name = ANY (ARRAY['recon'::text, 'probe'::text, 'fuzz'::text, 'scan'::text, 'triage'::text, 'notify'::text]));
