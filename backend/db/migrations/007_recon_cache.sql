-- 007_recon_cache.sql
-- Adds the recon-result cache columns pipeline.py's _phase_recon now
-- reads/writes (see RECON_CACHE_HOURS) - lets a repeat scan on the same
-- target reuse a recent subfinder result instead of re-querying every
-- OSINT source again. Idempotent, same pattern as prior migrations.

ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS recon_cache JSONB;
ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS recon_cached_at TIMESTAMPTZ;
