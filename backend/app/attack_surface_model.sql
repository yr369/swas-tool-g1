-- attack_surface_model.sql
--
-- Plain-language: every scan currently rediscovers a target's endpoints,
-- tech stack, and parameters from scratch, holds them in plain Python
-- lists for the duration of that one scan run, and throws all of it away
-- the moment the scan finishes - only the subdomain list gets cached
-- (scope_targets.recon_cache), and even that's a flat JSON blob with no
-- structure. Findings get saved, but the underlying MAP of the target
-- (what endpoints exist, what auth they need, what params they take,
-- what tech runs where) never persists anywhere queryable.
--
-- This migration adds that missing layer: one row per distinct URL ever
-- seen on a target, updated (not replaced) on every scan, so the surface
-- model actually accumulates knowledge over time instead of starting
-- from zero every run. This is the foundation the agentic investigation
-- loop (next phase) will read from and write into.
--
-- Apply the same way as prior migrations:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < attack_surface_model.sql

CREATE TABLE IF NOT EXISTS attack_surface_endpoints (
    id                SERIAL PRIMARY KEY,
    target_id         INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    url               TEXT NOT NULL,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    times_seen        INTEGER NOT NULL DEFAULT 1,
    last_status_code  INTEGER,
    -- NULL = never confirmed live (e.g. gau/wayback historical URL that
    -- hasn't been probed), true/false = confirmed via httpx this scan
    -- or a prior one.
    is_live           BOOLEAN,
    tech_stack        JSONB NOT NULL DEFAULT '[]'::jsonb,
    params            JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Which tools/phases have observed this URL - httpx, gau,
    -- waybackurls, arjun, detective, etc. Union'd across scans.
    sources           JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- NULL = unknown/not yet determined. This is a cheap heuristic from
    -- status codes seen during probing (401/403 => likely true), not a
    -- confirmed test - real confirmation is the authenticated-testing
    -- phase's job.
    requires_auth     BOOLEAN,
    auth_evidence     TEXT,
    notes             TEXT,
    UNIQUE (target_id, url)
);

CREATE INDEX IF NOT EXISTS idx_surface_endpoints_target ON attack_surface_endpoints (target_id);
CREATE INDEX IF NOT EXISTS idx_surface_endpoints_live ON attack_surface_endpoints (is_live);
CREATE INDEX IF NOT EXISTS idx_surface_endpoints_auth ON attack_surface_endpoints (requires_auth);

-- Per-target rollup so logic_hunter (and later phases) can pull one
-- cheap summary row instead of scanning every endpoint row every time.
CREATE OR REPLACE VIEW attack_surface_summary AS
SELECT
    target_id,
    COUNT(*) AS total_endpoints,
    COUNT(*) FILTER (WHERE is_live) AS live_endpoints,
    COUNT(*) FILTER (WHERE requires_auth = true) AS auth_required_endpoints,
    COUNT(*) FILTER (WHERE requires_auth = false) AS no_auth_endpoints,
    (
        SELECT jsonb_agg(DISTINCT tech)
        FROM attack_surface_endpoints e2, jsonb_array_elements_text(e2.tech_stack) AS tech
        WHERE e2.target_id = attack_surface_endpoints.target_id
    ) AS tech_stack_union,
    MAX(last_seen_at) AS last_scanned_at
FROM attack_surface_endpoints
GROUP BY target_id;
