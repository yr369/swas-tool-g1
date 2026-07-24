"""
auth_sessions.py - encrypted-at-rest storage for per-account session
credentials (cookies/bearer tokens) used by authenticated/multi-account
testing (build-order item #3).

Plain-language: this is the ONLY place in the codebase allowed to
handle a real bug-bounty account's cookie or token. Two things are
enforced here IN CODE, not just described in a comment:

  1. auth_policy.require_approved() is called before store OR retrieve.
     A project that hasn't been explicitly approved for authenticated
     testing can't have a session stored for it, let alone read one
     back. This is checked on the WRITE path too, not just reads -
     there's no reason to let credentials accumulate in the database
     for a program nobody's confirmed allows this kind of testing yet.

  2. Encryption at rest via Postgres's pgcrypto (pgp_sym_encrypt /
     pgp_sym_decrypt), keyed by a passphrase that lives ONLY in the
     SWAS_SESSION_KEY environment variable - never in this codebase,
     never in the database itself. Losing that env var means every
     stored session becomes permanently unreadable. That's by design:
     there is no key-recovery path in this scheme, the same tradeoff as
     any symmetric-key-at-rest approach without a separate escrow
     system, which this project doesn't have.

What this file deliberately does NOT do:
  - Never logs a decrypted value, not even at debug level.
    get_session()'s return value is meant to be used immediately by the
    caller (attached to exactly one outbound request) and not stored
    anywhere else - not in a variable that outlives the request, not in
    a findings.evidence string. If a probe using a session needs to
    describe what it saw, it describes the RESPONSE, never the
    credential that produced it.
  - list_sessions() only ever returns session_name/session_type/
    header_name/notes/timestamps - never encrypted_value, and nothing
    in this file returns more than one decrypted secret at a time.
"""

import logging
import os

from . import auth_policy

logger = logging.getLogger("swas.auth_sessions")

_VALID_SESSION_TYPES = ("cookie", "bearer_token", "header")


def _get_passphrase() -> str:
    passphrase = os.environ.get("SWAS_SESSION_KEY")
    if not passphrase:
        raise RuntimeError(
            "SWAS_SESSION_KEY is not set - authenticated-session storage/retrieval is unavailable "
            "until it is. There is no fallback/default key; that would defeat the point of "
            "encrypting these at rest."
        )
    return passphrase


async def store_session(conn, project_id: int, session_name: str, credential_value: str,
                         session_type: str = "cookie", header_name: str | None = None,
                         notes: str | None = None) -> None:
    """
    Encrypts and stores (or overwrites) one named session for a
    project. Requires the project to already be 'approved' in
    auth_policy - raises AuthPolicyError otherwise.
    """
    await auth_policy.require_approved(conn, project_id)
    if session_type not in _VALID_SESSION_TYPES:
        raise ValueError(f"invalid session_type: {session_type!r}, must be one of {_VALID_SESSION_TYPES}")
    if session_type == "header" and not header_name:
        raise ValueError("header_name is required when session_type='header'")

    passphrase = _get_passphrase()
    await conn.execute(
        """
        INSERT INTO project_auth_sessions
            (project_id, session_name, encrypted_value, session_type, header_name, notes)
        VALUES ($1, $2, pgp_sym_encrypt($3, $4), $5, $6, $7)
        ON CONFLICT (project_id, session_name) DO UPDATE SET
            encrypted_value = pgp_sym_encrypt($3, $4),
            session_type = EXCLUDED.session_type,
            header_name = EXCLUDED.header_name,
            notes = EXCLUDED.notes
        """,
        project_id, session_name, credential_value, passphrase, session_type, header_name, notes,
    )
    logger.info(
        "auth_sessions: stored session_name=%s (type=%s) for project_id=%s - value never logged",
        session_name, session_type, project_id,
    )


async def get_session(conn, project_id: int, session_name: str) -> dict | None:
    """
    Decrypts and returns ONE session for immediate use by a caller
    about to issue exactly one authenticated request. Requires the
    project to be 'approved'. Returns None if no session with that name
    exists for this project - a missing session is not an error,
    callers should treat it the same as "nothing to attach, proceed
    anonymously" rather than failing.

    Returned dict: {session_type, header_name, credential_value}. The
    caller must use credential_value immediately and not persist it
    anywhere else.
    """
    await auth_policy.require_approved(conn, project_id)
    passphrase = _get_passphrase()
    row = await conn.fetchrow(
        """
        SELECT session_type, header_name, pgp_sym_decrypt(encrypted_value, $3) AS credential_value
        FROM project_auth_sessions
        WHERE project_id = $1 AND session_name = $2
        """,
        project_id, session_name, passphrase,
    )
    if not row:
        return None
    await conn.execute(
        "UPDATE project_auth_sessions SET last_used_at = now() WHERE project_id = $1 AND session_name = $2",
        project_id, session_name,
    )
    return dict(row)


async def list_sessions(conn, project_id: int) -> list[dict]:
    """
    Metadata only - never encrypted_value, never a decrypted
    credential. Deliberately does NOT require approval to list what
    session names exist (useful for an operator checking what's
    configured before deciding whether to approve) - store_session and
    get_session both still gate on approval independently regardless.
    """
    rows = await conn.fetch(
        """
        SELECT session_name, session_type, header_name, notes, created_at, last_used_at
        FROM project_auth_sessions
        WHERE project_id = $1
        ORDER BY session_name
        """,
        project_id,
    )
    return [dict(r) for r in rows]


async def delete_session(conn, project_id: int, session_name: str) -> None:
    await conn.execute(
        "DELETE FROM project_auth_sessions WHERE project_id = $1 AND session_name = $2",
        project_id, session_name,
    )
    logger.info("auth_sessions: deleted session_name=%s for project_id=%s", session_name, project_id)
