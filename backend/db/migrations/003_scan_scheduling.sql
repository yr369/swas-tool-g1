-- Migration: scan scheduling columns on projects
-- Run this manually on existing databases (same pattern as prior
-- migrations - init.sql only runs on a fresh database volume).
--
-- scan_interval_hours: NULL means "no recurring schedule, manual only".
-- A number means "kick off a scan again every N hours automatically".
-- next_scheduled_scan_at: when the background scheduler loop should
-- next fire a scan for this project. Recomputed after every scheduled
-- run (success or failure) as now() + scan_interval_hours.

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS scan_interval_hours INTEGER,
    ADD COLUMN IF NOT EXISTS next_scheduled_scan_at TIMESTAMPTZ;
