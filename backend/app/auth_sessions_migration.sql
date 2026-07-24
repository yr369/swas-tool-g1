-- auth_sessions_migration.sql
-- Encrypted-at-rest storage for per-account session credentials (cookies/
-- bearer tokens), gated by project_auth_policy (see auth_policy_migration.sql
-- and auth_policy.py - every read/write here goes through that gate in code,
-- not just by convention).
--
-- Encryption is pgcrypto's pgp_sym_encrypt/pgp_sym_decrypt, keyed by a
-- passphrase that lives ONLY in the SWAS_SESSION_KEY environment variable -
-- never in this schema, never in a column, never in application code. There
-- is deliberately no key-recovery path: losing that env var makes every row
-- here permanently undecryptable.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS project_auth_sessions (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_name    TEXT NOT NULL,   -- operator-chosen label, e.g. 'user_a' - never the credential itself
    encrypted_value BYTEA NOT NULL,  -- pgp_sym_encrypt(cookie_or_token, passphrase)
    session_type    TEXT NOT NULL DEFAULT 'cookie'
                    CHECK (session_type IN ('cookie', 'bearer_token', 'header')),
    header_name     TEXT,            -- only meaningful when session_type='header', e.g. 'Authorization'
    notes           TEXT,            -- operator note (e.g. "free-tier account") - never the secret
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE (project_id, session_name)
);
