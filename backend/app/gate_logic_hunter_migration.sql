-- gate_logic_hunter_migration.sql
-- Adds the two new pipeline phases (gate, logic_hunter) and the columns
-- they read/write. Run this the same way the phase_runs 'triage' fix was
-- applied: docker cp + psql -f, against the LIVE OCI database. Safe to
-- re-run (every statement is idempotent).

-- 1. phase_runs.phase_name CHECK constraint didn't know about 'gate' or
--    'logic_hunter' - without this, the first scan run after deploying
--    the new phases will crash the same way the missing 'triage' value
--    did.
ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_phase_name_check;
ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name IN ('recon', 'probe', 'fuzz', 'scan', 'gate', 'logic_hunter', 'triage', 'notify'));

-- 2. findings.gate_status / gate_reasoning - the 7-Question Gate writes
--    these per finding. gate_status defaults 'pending' so every
--    existing row is treated as "not yet gated" rather than silently
--    excluded from triage (triage.py only ever excludes 'failed').
ALTER TABLE findings ADD COLUMN IF NOT EXISTS gate_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (gate_status IN ('pending', 'passed', 'failed'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS gate_reasoning TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_gate_status ON findings (gate_status);

-- 3. finding_clusters.logic_hunter_status - tracks whether a cluster has
--    already had an (expensive) logic_hunter reasoning pass spent on
--    it, so re-running the phase never double-spends on the same
--    cluster.
ALTER TABLE finding_clusters ADD COLUMN IF NOT EXISTS logic_hunter_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (logic_hunter_status IN ('pending', 'done'));
