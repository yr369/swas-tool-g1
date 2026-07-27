-- target_intelligence_migration_batch2.sql
--
-- Adds:
--   1. target_intelligence.surface_fingerprint - backs the rescan/
--      freshness trigger (target_intelligence.compute_surface_fingerprint
--      / check_and_reset_on_change).
--   2. findings.alerted_at - backs the human-in-the-loop checkpoint
--      (target_intelligence.get_unalerted_high_value_findings /
--      mark_alerted), so a high-value finding is only ever alerted on
--      once.
--
-- Manual migration - run per the project's standard process:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < target_intelligence_migration_batch2.sql

ALTER TABLE target_intelligence
    ADD COLUMN IF NOT EXISTS surface_fingerprint TEXT;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS alerted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_findings_unalerted_high_value
    ON findings (project_id, severity, likely_program_outcome)
    WHERE alerted_at IS NULL;
