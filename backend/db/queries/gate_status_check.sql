-- Is impact_hint=0-everywhere because everything already passed through
-- gate BEFORE migration 017 existed (no backfill), or because something
-- newer isn't getting gated/scored at all? This breaks down every
-- finding by (severity, gate_status) so we can see which bucket
-- everything is actually sitting in.
SELECT severity, gate_status, COUNT(*) AS n
FROM findings
GROUP BY severity, gate_status
ORDER BY n DESC;

-- Specifically: anything currently waiting to be gated right now?
SELECT COUNT(*) AS pending_ungated
FROM findings
WHERE severity = 'unknown' AND gate_status = 'pending';

-- Findings created since impact_hint's migration landed (adjust date
-- if needed - this assumes migration 017 went in within the last ~2
-- weeks; if all of these are also NOT 'pending', the gate ran on them
-- under an older code path some other way, worth knowing).
SELECT gate_status, COUNT(*) AS n
FROM findings
WHERE created_at > now() - interval '14 days'
GROUP BY gate_status
ORDER BY n DESC;
