-- Migration: add 'triage' as a valid phase_name
-- Run this manually on existing databases (same pattern as prior
-- migrations - init.sql only runs on a fresh database volume).
--
-- pipeline.py now runs an automatic "triage" phase between "scan" and
-- "notify" so detective.py findings get independent AI review instead
-- of skipping triage entirely. Without this migration, the very first
-- scan after deploying that change would crash with a CHECK constraint
-- violation the moment it tried to create a phase_runs row for
-- phase_name='triage' - same failure class as the earlier
-- status-CHECK-constraint crash, just on a different column.

ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_phase_name_check;

ALTER TABLE phase_runs
    ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name IN ('recon', 'probe', 'fuzz', 'scan', 'triage', 'notify'));
