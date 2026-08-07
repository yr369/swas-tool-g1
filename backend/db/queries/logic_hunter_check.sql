-- Now that gate/triage have caught up (0 unknown findings left), did
-- logic_hunter actually save a hypothesis for any of the 5 eligible
-- clusters, or did it correctly conclude none of them chained into
-- anything - both are valid outcomes, this just tells us which one.
SELECT f.id, f.vuln_type, f.severity, f.status, LEFT(f.evidence, 200) AS evidence_preview
FROM findings f
JOIN scope_targets t ON t.id = f.target_id
JOIN projects p ON p.id = t.project_id
WHERE p.name = 'Iberpay-invitation' AND f.tool_name = 'logic_hunter';
