-- 010_error_taxonomy.sql
-- Adds a structured error_type column to phase_runs, alongside the
-- existing free-text error_message. error_message stays as-is (the
-- exact exception text, still useful for a human debugging one
-- specific failure) - error_type is the new queryable field: one of a
-- fixed, small set of categories (see error_taxonomy.py's ERROR_TYPES),
-- so "how many scans failed on ai_quota_exhausted this week" becomes a
-- GROUP BY instead of grepping error_message and hoping the wording
-- never drifted.
--
-- Nullable: existing rows (and any row where the classification path
-- itself can't run for some reason) have no error_type rather than a
-- fabricated one - NULL is the honest "not classified" state, distinct
-- from the 'unknown' catch-all (which means "we DID classify it, and it
-- didn't match anything specific").
--
-- Idempotent, same pattern as prior migrations.

ALTER TABLE phase_runs ADD COLUMN IF NOT EXISTS error_type TEXT;

ALTER TABLE phase_runs DROP CONSTRAINT IF EXISTS phase_runs_error_type_check;
ALTER TABLE phase_runs ADD CONSTRAINT phase_runs_error_type_check
    CHECK (error_type IS NULL OR error_type IN (
        'ai_quota_exhausted',
        'ai_provider_error',
        'db_error',
        'network_timeout',
        'network_error',
        'tool_not_found',
        'auth_policy_denied',
        'config_error',
        'parse_error',
        'unknown'
    ));

CREATE INDEX IF NOT EXISTS idx_phase_runs_error_type ON phase_runs(error_type) WHERE error_type IS NOT NULL;
