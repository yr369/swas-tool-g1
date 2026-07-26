-- 009_auth_policy_sessions.sql
-- Creates the tables auth_policy.py / auth_sessions.py have referenced
-- since they were written, but which no prior migration actually
-- created - every call into either module has been throwing
-- "relation does not exist" the entire time. pgcrypto is required for
-- pgp_sym_encrypt/pgp_sym_decrypt (session credential encryption at
-- rest) and was likewise never enabled.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS project_auth_policy (
    project_id  INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'unset' CHECK (status IN ('unset', 'approved', 'denied')),
    policy_note TEXT,
    set_by      TEXT,
    set_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS project_auth_sessions (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_name    TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    session_type    TEXT NOT NULL CHECK (session_type IN ('cookie', 'bearer_token', 'header')),
    header_name     TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE (project_id, session_name)
);
