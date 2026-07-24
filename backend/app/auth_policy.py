"""
auth_policy.py - the default-deny gate for authenticated/multi-account testing.

Plain-language: this file's ONLY job is to answer one question - "is
authenticated testing explicitly approved for this specific project
right now" - and to make it structurally hard for any other code path
to skip asking it. Every function anywhere in this codebase that is
about to attach a real credential/session to an outbound request MUST
call `require_approved(...)` first and let it raise if the answer isn't
a plain 'approved'. There is no code path that attaches credentials
without going through this gate - credential storage/retrieval, once
built on top of this, is required to call it before ever handing back a
usable session.

Default posture is DENY, not "assume yes until told otherwise": a
project with no policy row at all, or an explicit 'unset' row, is
blocked - exactly the same as an explicit 'denied' row. Only a row whose
status is literally 'approved' passes. This mirrors the same scope-check
discipline already applied everywhere else in this codebase (verify what
a program's policy actually allows before testing something, never
assume) - applied specifically to multi-account automation, which
several bounty programs restrict or require pre-approval for even when
the underlying vuln classes themselves are in scope.

Moving a project to 'approved' is a manual, deliberate action (see
`set_policy` below), meant to be invoked once by a human operator after
actually reading the relevant program's policy on automated/multi-account
testing - not something any pipeline phase ever sets on its own.
"""

import logging

logger = logging.getLogger("swas.auth_policy")

_VALID_STATUSES = ("unset", "approved", "denied")


class AuthPolicyError(Exception):
    """
    Raised by require_approved() when a project isn't explicitly
    approved for authenticated testing. Deliberately an exception, not
    a bool return value - a caller can't accidentally `if not
    require_approved(...): pass` their way past the gate; they have to
    either handle it or let it propagate and stop the operation.
    """


async def get_policy(conn, project_id: int) -> dict:
    row = await conn.fetchrow(
        "SELECT status, policy_note, set_by, set_at FROM project_auth_policy WHERE project_id = $1",
        project_id,
    )
    if not row:
        return {"status": "unset", "policy_note": None, "set_by": None, "set_at": None}
    return dict(row)


async def require_approved(conn, project_id: int) -> None:
    """
    The gate. Call this before anything that would attach a stored
    credential/session to an outbound request against this project's
    targets. Raises AuthPolicyError for anything other than an explicit
    'approved' status - including 'unset' (the default for every new
    project) and 'denied'.
    """
    policy = await get_policy(conn, project_id)
    if policy["status"] != "approved":
        raise AuthPolicyError(
            f"authenticated/multi-account testing is not approved for project_id={project_id} "
            f"(status={policy['status']!r}). Call auth_policy.set_policy(...) after confirming "
            f"the program's actual policy on automated multi-account testing before retrying."
        )


async def set_policy(conn, project_id: int, status: str, policy_note: str, set_by: str) -> None:
    """
    The only way a project moves out of the default-deny state. This is
    a data-layer primitive meant to be called from a deliberate operator
    action (a CLI command or admin endpoint - not built here) - never
    automatically by a pipeline phase, and never with a placeholder
    policy_note; the point is a real accountability trail for a real
    decision, not a rubber stamp.
    """
    if status not in _VALID_STATUSES:
        raise ValueError(f"invalid policy status: {status!r}, must be one of {_VALID_STATUSES}")
    await conn.execute(
        """
        INSERT INTO project_auth_policy (project_id, status, policy_note, set_by, set_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (project_id) DO UPDATE SET
            status = EXCLUDED.status,
            policy_note = EXCLUDED.policy_note,
            set_by = EXCLUDED.set_by,
            set_at = now()
        """,
        project_id, status, policy_note, set_by,
    )
    logger.info("auth_policy: project_id=%s set to status=%s by %s", project_id, status, set_by)
