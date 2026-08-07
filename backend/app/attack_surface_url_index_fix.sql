-- attack_surface_url_index_fix.sql
--
-- Plain-language: the original UNIQUE (target_id, url) constraint on
-- attack_surface_endpoints is a plain btree over the raw url TEXT
-- column. Postgres btree indexes have a hard per-tuple size limit
-- (~2704 bytes on this build) - confirmed live on OCI, several probe
-- phase runs failing with "index row size N exceeds btree version 4
-- maximum 2704" whenever a long URL (long query string, deeply nested
-- path, etc.) got inserted or upserted into this table.
--
-- Fix: drop the raw-column unique constraint and replace it with a
-- unique index on (target_id, md5(url)) instead. md5() always returns
-- a fixed 32-character hex string regardless of input length, so this
-- can never overflow no matter how long the URL is. Uniqueness
-- semantics are preserved (an md5 collision on distinct URLs for the
-- same target is not a realistic concern here).
--
-- IMPORTANT: this changes what the ON CONFLICT target must look like
-- in application code. Both persistence.py and logic_hunter.py upsert
-- into this table with "ON CONFLICT (target_id, url) DO UPDATE ..." -
-- those must be changed to "ON CONFLICT (target_id, md5(url)) DO
-- UPDATE ..." in the same deploy as this migration, or every upsert
-- into this table will start failing with "there is no unique or
-- exclusion constraint matching the ON CONFLICT specification".
--
-- Apply the same way as prior migrations:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < attack_surface_url_index_fix.sql

BEGIN;

ALTER TABLE attack_surface_endpoints
    DROP CONSTRAINT IF EXISTS attack_surface_endpoints_target_id_url_key;

CREATE UNIQUE INDEX IF NOT EXISTS attack_surface_endpoints_target_id_url_md5_key
    ON attack_surface_endpoints (target_id, md5(url));

-- Sanity check: the new index must exist and the old constraint must
-- be gone, or roll back rather than commit a half-applied migration.
DO $$
DECLARE
    new_index_exists boolean;
    old_constraint_exists boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'attack_surface_endpoints'
          AND indexname = 'attack_surface_endpoints_target_id_url_md5_key'
    ) INTO new_index_exists;

    SELECT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'attack_surface_endpoints_target_id_url_key'
    ) INTO old_constraint_exists;

    IF NOT new_index_exists THEN
        RAISE EXCEPTION 'sanity check failed: new md5-based unique index was not created';
    END IF;

    IF old_constraint_exists THEN
        RAISE EXCEPTION 'sanity check failed: old raw-url unique constraint still exists';
    END IF;
END $$;

COMMIT;
