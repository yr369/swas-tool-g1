-- 012_impact_evidence.sql
-- Adds impact_evidence to findings: the model's own concrete evidence
-- of REAL-WORLD impact (actual sensitive data shown, an actual
-- privileged action performed) as distinct from "the vulnerability
-- mechanism fires". This is the direct fix for the recurring "no real
-- impact to sensitive data" platform rejection - triage.py now caps
-- critical/high severity down to medium whenever this field is
-- missing/weak, rather than letting a confirmed-but-unproven bug
-- inherit high severity by default (see triage._apply_impact_evidence_cap).
--
-- Nullable: pre-existing findings (and cluster-triage, which doesn't
-- go through this field yet) simply have no impact_evidence rather
-- than a fabricated one.
--
-- Idempotent, same pattern as prior migrations.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS impact_evidence TEXT;
