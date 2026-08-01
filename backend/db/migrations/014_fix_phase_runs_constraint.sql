-- 014_fix_phase_runs_constraint.sql
--
-- The CHECK constraint on phase_runs.phase_name had fallen behind the
-- actual set of phases the pipeline uses. checkpoint.py's _ALL_PHASES
-- is the source of truth: ["recon", "probe", "fuzz", "scan", "verify",
-- "gate", "logic_hunter", "triage", "notify"] - the constraint only
-- listed 6 of those 9, missing "verify", "gate", and "logic_hunter"
-- entirely (not just "triage" as originally thought), which meant
-- every insert for those three phases was silently violating a
-- constraint that had somehow stopped being enforced. Confirmed via
-- production data: 1189 "verify" rows, 1580 "gate" rows, 1497
-- "logic_hunter" rows already existed before this fix.
--
-- Folded in from the loose fix_phase_runs_constraint.sql that used to
-- sit at repo root outside the numbered sequence (repo compaction pass).
--
-- Run manually, same as every other migration:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/migrations/014_fix_phase_runs_constraint.sql

ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_phase_name_check;

ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name = ANY (ARRAY['recon'::text, 'probe'::text, 'fuzz'::text, 'scan'::text, 'verify'::text, 'gate'::text, 'logic_hunter'::text, 'triage'::text, 'notify'::text]));
