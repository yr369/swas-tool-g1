-- correlation_schema_fix2.sql
-- Drops the view first (it depends on both tables), then the tables
-- with CASCADE, then recreates everything keyed on target_id.

DROP VIEW IF EXISTS high_potential_clusters;
DROP TABLE IF EXISTS finding_cluster_members CASCADE;
DROP TABLE IF EXISTS finding_clusters CASCADE;

CREATE TABLE finding_clusters (
    id               SERIAL PRIMARY KEY,
    target_id        INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now(),
    gate_status      TEXT DEFAULT 'pending',
    triage_status    TEXT DEFAULT 'pending',
    severity         TEXT,
    vrt_category     TEXT,
    llm_backend_used TEXT,
    UNIQUE (target_id)
);

CREATE TABLE finding_cluster_members (
    cluster_id  INTEGER REFERENCES finding_clusters(id) ON DELETE CASCADE,
    finding_id  INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    added_at    TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (cluster_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target_id);
CREATE INDEX IF NOT EXISTS idx_clusters_gate_status ON finding_clusters (gate_status);
CREATE INDEX IF NOT EXISTS idx_clusters_triage_status ON finding_clusters (triage_status);

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
