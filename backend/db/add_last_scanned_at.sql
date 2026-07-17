-- add_last_scanned_at.sql
--
-- Adds last_scanned_at to scope_targets - lets the UI show "last
-- scanned: 3 hours ago" per host and is what the per-host rescan
-- endpoint stamps when a pipeline run finishes for that target.
--
-- Run this ONCE against the live database (init.sql only applies to a
-- brand-new/empty postgres volume, not this already-running one - same
-- reason fix_phase_runs_constraint.sql and gate_logic_hunter_migration.sql
-- had to be applied manually too).
--
-- How to run it, from the OCI server, in the swas-tool-g1 directory:
--   docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < add_last_scanned_at.sql
--
-- Safe to run more than once - IF NOT EXISTS makes it a no-op on repeat runs.

ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMPTZ;
