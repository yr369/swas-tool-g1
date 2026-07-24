-- auth_policy_migration.sql
-- Default-deny gate for authenticated/multi-account testing (build-order item #3).
--
-- One row per project. No row, or status='unset', means BLOCKED - identical
-- to an explicit 'denied' row. Only status='approved' lets auth_policy.py's
-- require_approved() pass. A project only reaches 'approved' via a deliberate
-- manual call to auth_policy.set_policy(...) after a human has actually read
-- that program's policy on automated/multi-account testing - never set by a
-- pipeline phase on its own.

CREATE TABLE IF NOT EXISTS project_auth_policy (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'unset'
                    CHECK (status IN ('unset', 'approved', 'denied')),
    policy_note     TEXT,       -- e.g. "program's VDP section 4.2 permits automated multi-account
                                 -- testing; confirmed via program's own scope page 2026-08-01"
    set_by          TEXT,       -- accountability trail - who made this call
    set_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
