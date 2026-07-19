-- 005_verify_phase.sql
-- Adds the new 'verify' pipeline phase (active confirmation - OOB
-- callback, cache-poisoning consequence check, headless-browser XSS
-- execution proof - see backend/app/verify.py) and the columns it
-- writes. Apply the same way as gate_logic_hunter_migration.sql: against
-- the LIVE OCI database. Safe to re-run (every statement is idempotent).

-- 1. phase_runs.phase_name CHECK constraint needs to know about 'verify',
--    same fix shape as the earlier gate/logic_hunter migration.
ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_phase_name_check;
ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_phase_name_check
    CHECK (phase_name IN ('recon', 'probe', 'fuzz', 'scan', 'verify', 'gate', 'logic_hunter', 'triage', 'notify'));

-- 2. findings.verification_status / verification_evidence - verify.py
--    writes these per finding. Defaults to 'pending' so every existing
--    row (and every finding from a vuln_type verify.py doesn't have a
--    technique for yet) is visibly "not yet checked," distinct from
--    'tentative' (checked, couldn't fully confirm) and 'unconfirmed'
--    (checked, did NOT reproduce - likely a false positive).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (verification_status IN ('pending', 'confirmed', 'tentative', 'unconfirmed'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification_evidence TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_verification_status ON findings (verification_status);
