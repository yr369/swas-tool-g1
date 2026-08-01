-- 013_finding_dedup.sql
--
-- Adds dedup tracking to findings. Before this, every scan re-run
-- inserted a brand new row for a signature that hadn't changed at all
-- (e.g. the same leaked API key from nuclei showing up as 4 separate
-- "Critical" rows after 4 scans). dedup_key is a content hash of
-- (vuln_type, evidence); occurrence_count/last_seen track repeats
-- instead of spawning new rows.
--
-- NOT retroactive: existing duplicate rows in your DB (like the ones
-- in the screenshot) are backfilled with a dedup_key but NOT merged or
-- deleted here. Merging old rows means deciding what happens to
-- finding_cluster_members / finding_outcomes / triage history that
-- may reference the "duplicate" rows' ids, and that needs a manual
-- pass with eyes on it - not a blind migration. Dedup applies going
-- forward from this migration on.
--
-- Run manually, same as every other migration:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/db/migrations/013_finding_dedup.sql

ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_key TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ NOT NULL DEFAULT now();

-- Backfill dedup_key on existing rows so future repeats of old findings
-- still get recognized as repeats.
UPDATE findings
SET dedup_key = encode(sha256(convert_to(COALESCE(vuln_type, '') || '|' || COALESCE(evidence, ''), 'UTF8')), 'hex')
WHERE dedup_key IS NULL;

-- Not a UNIQUE constraint on purpose: legacy duplicate rows already
-- exist and a hard constraint would fail to apply. This index just
-- makes the app-level dedup lookup (see finding_dedup.py) fast.
CREATE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings (project_id, target_id, tool_name, dedup_key);
