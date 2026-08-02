-- 017_gate_impact_hint.sql
-- Adds impact_hint / impact_signals to findings: a cheap, regex-based
-- early warning written by gate.py's new impact scorer, BEFORE the
-- finding ever reaches the expensive triage.py pass or a human.
--
-- Deliberately not authoritative: triage.py's LLM-judged impact_evidence
-- cap (012_impact_evidence.sql) remains the real severity call. This is
-- only meant to flag, as early and cheaply as possible, findings that
-- smell like they'll come back Informative - DoS/rate-limit/resource-
-- exhaustion vuln types, unauthenticated cache purge with no poisoning
-- evidence, self-XSS, cosmetic-only changes, or a bare missing header
-- with nothing else backing it.
--
-- Nullable, no default beyond NULL: pre-existing rows and any row gate
-- hasn't touched yet simply have no hint, same pattern as
-- impact_evidence.
--
-- Idempotent, same pattern as prior migrations.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS impact_hint TEXT
    CHECK (impact_hint IN ('likely_informative', 'has_impact_signal', 'unclear') OR impact_hint IS NULL);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS impact_signals TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_impact_hint ON findings (impact_hint);
