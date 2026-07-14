-- correlation_schema.sql
-- Adds clustering on top of your existing findings table.
-- Assumes you already have a `findings` table from detective.py output.
-- Adjust column names to match your real schema.

CREATE TABLE IF NOT EXISTS finding_clusters (
    id              SERIAL PRIMARY KEY,
    host            TEXT NOT NULL,
    endpoint        TEXT NOT NULL,           -- normalized path, e.g. /api/v2/user/{id}
    auth_state      TEXT,                    -- unauth / user / admin / unknown
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    gate_status     TEXT DEFAULT 'pending',   -- pending / passed / failed
    triage_status   TEXT DEFAULT 'pending',   -- pending / scored / reported
    severity        TEXT,                     -- set after triage
    vrt_category    TEXT,
    llm_backend_used TEXT,                    -- which backend scored it (for cost tracking)
    UNIQUE (host, endpoint)
);

-- Join table: many findings -> one cluster
CREATE TABLE IF NOT EXISTS finding_cluster_members (
    cluster_id      INTEGER REFERENCES finding_clusters(id) ON DELETE CASCADE,
    finding_id      INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,   -- 'detective' or 'logic_hunter'
    added_at        TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (cluster_id, finding_id)
);

-- Index for the "re-trigger correlation on new finding" flow
CREATE INDEX IF NOT EXISTS idx_findings_host_endpoint ON findings (host, endpoint);
CREATE INDEX IF NOT EXISTS idx_clusters_gate_status ON finding_clusters (gate_status);
CREATE INDEX IF NOT EXISTS idx_clusters_triage_status ON finding_clusters (triage_status);

-- View: clusters with 2+ findings from different sources = highest chain potential
CREATE OR REPLACE VIEW high_potential_clusters AS
SELECT
    fc.id AS cluster_id,
    fc.host,
    fc.endpoint,
    fc.auth_state,
    COUNT(DISTINCT fcm.source) AS distinct_sources,
    COUNT(fcm.finding_id) AS total_findings
FROM finding_clusters fc
JOIN finding_cluster_members fcm ON fcm.cluster_id = fc.id
WHERE fc.gate_status != 'failed'
GROUP BY fc.id
HAVING COUNT(DISTINCT fcm.source) >= 2
    OR COUNT(fcm.finding_id) >= 2
ORDER BY total_findings DESC;
