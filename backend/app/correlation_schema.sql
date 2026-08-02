-- correlation_schema.sql
-- Finding-clustering schema: groups findings by target for cross-source
-- correlation (detective + logic_hunter) and downstream gate/triage.
--
-- Squashed from correlation_schema.sql + _fix.sql + _fix2.sql (2026-08-02).
-- This is the schema as of fix2 - keyed on target_id against scope_targets,
-- not the original host/endpoint design. Idempotent: safe to run against a
-- fresh DB, or one that already has the old host/endpoint-keyed tables from
-- pre-fix correlation_schema.sql.
--
-- DO NOT run this against a database that is already at the fix2 end state
-- (i.e. already in production) - the DROP...CASCADE will wipe existing
-- finding_clusters / finding_cluster_members rows. This file is for new
-- environments only. Existing OCI prod needs no action; it's already here.

DROP VIEW IF EXISTS high_potential_clusters;
DROP TABLE IF EXISTS finding_cluster_members CASCADE;
DROP TABLE IF EXISTS finding_clusters CASCADE;

CREATE TABLE finding_clusters (
    id               SERIAL PRIMARY KEY,
    target_id        INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now(),
    gate_status      TEXT DEFAULT 'pending',   -- pending / passed / failed
    triage_status    TEXT DEFAULT 'pending',   -- pending / scored / reported
    severity         TEXT,
    vrt_category     TEXT,
    llm_backend_used TEXT,                     -- which backend scored it (for cost tracking)
    UNIQUE (target_id)
);

-- Join table: many findings -> one cluster
CREATE TABLE finding_cluster_members (
    cluster_id  INTEGER REFERENCES finding_clusters(id) ON DELETE CASCADE,
    finding_id  INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,   -- 'detective' or 'logic_hunter'
    added_at    TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (cluster_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target_id);
CREATE INDEX IF NOT EXISTS idx_clusters_gate_status ON finding_clusters (gate_status);
CREATE INDEX IF NOT EXISTS idx_clusters_triage_status ON finding_clusters (triage_status);

-- View: clusters with 2+ findings from different sources = highest chain potential
CREATE OR REPLACE VIEW high_potential_clusters AS
SELECT
    fc.id AS cluster_id,
    fc.target_id,
    st.target AS target_name,
    st.target_type,
    COUNT(DISTINCT fcm.source) AS distinct_sources,
    COUNT(fcm.finding_id) AS total_findings
FROM finding_clusters fc
JOIN finding_cluster_members fcm ON fcm.cluster_id = fc.id
JOIN scope_targets st ON st.id = fc.target_id
WHERE fc.gate_status != 'failed'
GROUP BY fc.id, st.target, st.target_type
HAVING COUNT(DISTINCT fcm.source) >= 2
    OR COUNT(fcm.finding_id) >= 2
ORDER BY total_findings DESC;
