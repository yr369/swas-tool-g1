-- logic_hunter_depth_migration.sql
--
-- Plain-language: high_potential_clusters previously required 2+ findings
-- OR 2+ distinct sources on a target before logic_hunter would ever reason
-- about it. That's a reasonable noise filter in general, but it means a
-- single high-value structural finding - an exposed GraphQL introspection
-- dump, a leaked Swagger/OpenAPI doc, an exposed Spring actuator/env,
-- a leaked source map - never gets a deep-reasoning pass by itself, even
-- though these specific finding types are exactly the ones most likely to
-- reveal an internal/admin endpoint or auth pattern worth chaining into a
-- real business-logic bug. This migration adds a second, narrower path
-- into high_potential_clusters: a single finding is enough IF its
-- vuln_type is on the allowlist below.
--
-- Apply the same way as prior migrations:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < logic_hunter_depth_migration.sql

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
JOIN findings f ON f.id = fcm.finding_id
JOIN scope_targets st ON st.id = fc.target_id
WHERE fc.gate_status != 'failed'
GROUP BY fc.id, st.target, st.target_type
HAVING COUNT(DISTINCT fcm.source) >= 2
    OR COUNT(fcm.finding_id) >= 2
    OR bool_or(
        f.vuln_type IN (
            'graphql_introspection_exposed',
            'exposed_spring_actuator_env',
            'exposed_api_documentation',
            'leaked_source_map',
            'exposed_firebase_database',
            'firebase_realtime_db_open_read',
            'exposed_docker_api',
            'exposed_docker_daemon_api',
            'exposed_kubelet_api',
            'sensitive_file_exposure',
            'exposed_heapdump',
            'exposed_couchdb',
            'couchdb_all_dbs_unauth_listing',
            'exposed_mongodb',
            'publicly_listable_azure_blob_container',
            'publicly_listable_cloud_storage_bucket'
        )
    )
ORDER BY total_findings DESC;
