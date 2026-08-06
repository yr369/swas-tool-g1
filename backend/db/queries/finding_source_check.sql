-- Confirm the nuclei-bypasses-gate theory directly: break down
-- gate_status/impact_hint by tool_name, so we can see whether it's
-- specifically nuclei (and maybe other tools that self-report severity)
-- sitting outside the gate, vs detective-sourced findings also missing
-- impact_hint for some other reason.
SELECT
    tool_name,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE severity = 'unknown') AS ever_was_unknown_severity,
    COUNT(*) FILTER (WHERE impact_hint IS NOT NULL) AS has_impact_hint,
    COUNT(*) FILTER (WHERE gate_status = 'pending') AS still_pending
FROM findings
GROUP BY tool_name
ORDER BY total DESC;
