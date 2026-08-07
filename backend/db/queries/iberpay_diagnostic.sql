-- Diagnostic for the Iberpay-invitation project: is the 547-unknown
-- bucket gate-failed noise (expected, correctly labeled "NOTES FOR
-- MANUAL REVIEW") or stuck-pending (a real bug where gate/triage never
-- finished)? And did logic_hunter have any eligible clusters to chain
-- from at all, or is 0 hypotheses the correct answer given what it had
-- to work with?

-- 1. The 547 unknown findings, broken down by per-finding gate_status
SELECT f.gate_status, COUNT(*) AS n
FROM findings f
JOIN scope_targets t ON t.id = f.target_id
JOIN projects p ON p.id = t.project_id
WHERE p.name = 'Iberpay-invitation' AND f.severity = 'unknown'
GROUP BY f.gate_status
ORDER BY n DESC;

-- 2. Any AI retry-queue entries for this project (triage/logic_hunter
-- calls that failed and are waiting to retry, or gave up)?
SELECT rq.kind, rq.status, COUNT(*) AS n
FROM ai_retry_queue rq
JOIN projects p ON p.id = (rq.payload->>'project_id')::int
WHERE p.name = 'Iberpay-invitation'
GROUP BY rq.kind, rq.status
ORDER BY n DESC;

-- 3. Every cluster for this project - its own cluster-level gate_status
-- and whether logic_hunter has processed it
SELECT fc.gate_status AS cluster_gate_status, fc.logic_hunter_status, COUNT(*) AS cluster_count
FROM finding_clusters fc
JOIN scope_targets t ON t.id = fc.target_id
JOIN projects p ON p.id = t.project_id
WHERE p.name = 'Iberpay-invitation'
GROUP BY fc.gate_status, fc.logic_hunter_status;

-- 4. Of those clusters, how many actually met high_potential_clusters'
-- bar (2+ sources, 2+ findings, or a single high-value structural
-- finding type) - i.e. how many were ever eligible for logic_hunter to
-- look at in the first place
SELECT COUNT(*) AS eligible_clusters, SUM(hpc.total_findings) AS findings_in_eligible_clusters
FROM high_potential_clusters hpc
JOIN scope_targets t ON t.id = hpc.target_id
JOIN projects p ON p.id = t.project_id
WHERE p.name = 'Iberpay-invitation';
