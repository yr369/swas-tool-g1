-- How much is impact_hint actually cutting false-positive submissions?
-- Compares real-world outcome (finding_outcomes.outcome, i.e. what
-- Bugcrowd/HackerOne actually said) against what gate.py's impact_hint
-- predicted at scan time, for every finding that has BOTH a recorded
-- outcome AND an impact_hint value (older findings pre-date migration
-- 017 and won't have impact_hint - they're excluded automatically since
-- the join requires it).

SELECT
    f.impact_hint,
    COUNT(*) AS total_outcomes,
    COUNT(*) FILTER (WHERE fo.outcome IN ('rejected', 'informative', 'not_applicable')) AS bad_outcomes,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE fo.outcome IN ('rejected', 'informative', 'not_applicable'))
        / NULLIF(COUNT(*), 0),
        1
    ) AS bad_outcome_pct,
    COUNT(*) FILTER (WHERE fo.outcome = 'accepted') AS accepted,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE fo.outcome = 'accepted') / NULLIF(COUNT(*), 0),
        1
    ) AS accepted_pct
FROM finding_outcomes fo
JOIN findings f ON f.id = fo.finding_id
WHERE f.impact_hint IS NOT NULL
GROUP BY f.impact_hint
ORDER BY bad_outcome_pct DESC;

-- Sample-size sanity check - if this is small (say under ~20-30 total),
-- the percentages above aren't statistically meaningful yet, just a
-- direction. Also shows how many findings have impact_hint but no
-- recorded outcome yet (i.e. still sitting unsubmitted or awaiting a
-- platform response) and how many predate the migration entirely.
SELECT
    COUNT(*) FILTER (WHERE impact_hint IS NOT NULL) AS findings_with_impact_hint,
    COUNT(*) FILTER (WHERE impact_hint IS NULL) AS findings_without_impact_hint_pre_migration,
    (SELECT COUNT(*) FROM finding_outcomes) AS total_outcomes_recorded
FROM findings;
