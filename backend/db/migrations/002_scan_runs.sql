-- Migration: scan_runs table
-- Run this manually on existing databases (same pattern as 001_finding_outcomes.sql -
-- init.sql only runs on a fresh database volume).
--
-- Plain-language: this is a lightweight "bookmark" of when each scan
-- started for a project. It does NOT get a foreign key on findings and
-- doesn't require touching pipeline.py's insert calls at all - the
-- diff endpoint instead buckets findings by comparing their created_at
-- timestamp against consecutive scan_runs.started_at values. A finding
-- created after run N started (and before run N+1 started, if there is
-- one) belongs to run N. This is deliberately the simplest thing that
-- gives an honest run-to-run diff without a riskier schema change that
-- threads a scan_run_id through every _save_finding()/_save_nuclei_findings()
-- call site in pipeline.py.

CREATE TABLE IF NOT EXISTS scan_runs (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_project ON scan_runs(project_id);
