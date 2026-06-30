-- Migration: finding_outcomes table
-- Run this manually on existing databases (init.sql only runs on a fresh
-- database volume, so existing OCI deployments need this applied directly).
--
-- Plain-language: this table is the actual "learning" part of SWAS. Every
-- time you submit a finding to Bugcrowd/HackerOne and get a real-world
-- result back (accepted, duplicate, rejected, etc.), that result gets
-- logged here, tied to a "signature" describing the finding's pattern
-- (tool + vuln type + target type). Future triage can look up similar
-- past signatures to see "findings like this were rejected 4 times before"
-- before deciding how much attention a new finding deserves.

CREATE TABLE IF NOT EXISTS finding_outcomes (
    id              SERIAL PRIMARY KEY,
    finding_id      INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    -- finding_id can be NULL: outcomes should survive even if the
    -- original finding row is later deleted - the pattern is still
    -- useful to learn from even without the specific row.
    signature       TEXT NOT NULL,
    -- e.g. "nuclei:CVE-2023-48795:website" - tool + vuln_type + target_type,
    -- a stable pattern that future similar findings can be matched against.
    outcome         TEXT NOT NULL
                    CHECK (outcome IN ('accepted', 'duplicate', 'rejected', 'informative', 'not_applicable', 'no_response')),
    platform        TEXT CHECK (platform IN ('bugcrowd', 'hackerone')),
    notes           TEXT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_outcomes_signature ON finding_outcomes(signature);
CREATE INDEX IF NOT EXISTS idx_finding_outcomes_finding ON finding_outcomes(finding_id);
