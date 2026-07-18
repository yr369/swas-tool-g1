-- SWAS mk-4 Phase 1 schema
-- This file runs automatically the FIRST time the postgres container starts
-- (Docker only runs init scripts on an empty database volume).

-- A bug bounty program/project the operator is working on
CREATE TABLE IF NOT EXISTS projects (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    platform        TEXT NOT NULL CHECK (platform IN ('bugcrowd', 'hackerone')),
    status          TEXT NOT NULL DEFAULT 'created'
                    CHECK (status IN ('created', 'scanning', 'completed', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Individual in-scope or out-of-scope targets belonging to a project
CREATE TABLE IF NOT EXISTS scope_targets (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target          TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (target_type IN ('website', 'api', 'mobile', 'hardware', 'unknown')),
    in_scope        BOOLEAN NOT NULL DEFAULT true,
    reward_range    TEXT,
    notes           TEXT,
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The checkpoint table. Every pipeline phase, for every target, writes its
-- status here. This is what makes the system crash-safe: on restart, the
-- app reads this table to figure out what was in progress and resume or
-- flag it, instead of losing track of state.
CREATE TABLE IF NOT EXISTS phase_runs (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id       INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    phase_name      TEXT NOT NULL
                    CHECK (phase_name IN ('recon', 'probe', 'fuzz', 'scan', 'gate', 'logic_hunter', 'triage', 'notify')),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'needs_attention')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Batch 4b: ordered queue of projects waiting for a scan slot. The
-- worker loop runs one project at a time (see _queue_worker_loop in
-- main.py) - both manual "Scan" clicks and the recurring scheduler add
-- a row here rather than kicking off _trigger_scan_for_project directly,
-- so there is exactly one execution path instead of two competing ones.
CREATE TABLE IF NOT EXISTS scan_queue (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    priority        BOOLEAN NOT NULL DEFAULT false,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'cancelled')),
    queued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_queue_next
    ON scan_queue (status, priority DESC, position ASC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_queue_one_active_per_project
    ON scan_queue (project_id)
    WHERE status IN ('queued', 'running');

-- Detective checks that are deliberately not auto-filed as findings
-- (unconfirmed pattern matches, or confirmed-but-low-value-alone gaps
-- like clickjacking/missing SRI) - previously just logged and
-- discarded, now persisted here so they're actually visible.
CREATE TABLE IF NOT EXISTS scan_notes (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id   INTEGER REFERENCES scope_targets(id) ON DELETE SET NULL,
    check_name  TEXT NOT NULL,
    note        TEXT NOT NULL,
    dismissed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_notes_project ON scan_notes(project_id) WHERE NOT dismissed;

-- A candidate vulnerability found by a scanning tool, pending human review
CREATE TABLE IF NOT EXISTS findings (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id       INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    tool_name       TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
    evidence        TEXT,
    raw_output_path TEXT,
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'reviewed', 'submitted', 'dismissed')),
    gate_status     TEXT NOT NULL DEFAULT 'pending'
                    CHECK (gate_status IN ('pending', 'passed', 'failed')),
    gate_reasoning  TEXT,
    likely_program_outcome TEXT
                    CHECK (likely_program_outcome IN ('accepted', 'informative', 'out_of_scope', 'duplicate')),
    triage_reasoning TEXT,
    triage_confidence REAL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for the lookups we'll actually do often
CREATE INDEX IF NOT EXISTS idx_scope_targets_project ON scope_targets(project_id);
CREATE INDEX IF NOT EXISTS idx_phase_runs_project ON phase_runs(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_likely_program_outcome ON findings(likely_program_outcome);
CREATE INDEX IF NOT EXISTS idx_phase_runs_status ON phase_runs(status);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
