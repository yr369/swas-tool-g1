-- fix_phase_runs_constraint.sql
-- pipeline.py creates checkpoint rows with phase_name='triage', but the
-- CHECK constraint was never updated to allow it. This has been silently
-- crashing every scan right as it enters the triage phase.

ALTER TABLE phase_runs DROP CONSTRAINT phase_runs_phase_name_check;

ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name = ANY (ARRAY['recon'::text, 'probe'::text, 'fuzz'::text, 'scan'::text, 'triage'::text, 'notify'::text]));
