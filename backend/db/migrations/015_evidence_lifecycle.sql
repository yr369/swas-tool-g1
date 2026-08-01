-- 015_evidence_lifecycle.sql
--
-- Batch 24: dead-target detection + evidence integrity tracking.
-- (Evidence archival needs no schema change - findings.raw_output_path
-- already existed in init.sql, just was never written until batch 24's
-- evidence_lifecycle.py started populating it.)
--
-- Folded in from the loose evidence_lifecycle_migration.sql that used
-- to sit at repo root outside the numbered sequence (repo compaction
-- pass).
--
-- Run manually, same as every other migration:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/migrations/015_evidence_lifecycle.sql

ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS dead_since TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_scope_targets_dead_since
    ON scope_targets (dead_since)
    WHERE dead_since IS NOT NULL;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_integrity TEXT
    CHECK (evidence_integrity IN ('reproducible', 'rotted', 'inconclusive'));
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_checked_at TIMESTAMPTZ;
