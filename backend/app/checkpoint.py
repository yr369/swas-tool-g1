"""
checkpoint.py - the resilience layer. Every pipeline phase, for every
target, MUST go through this module to record its progress.

Plain-language explanation: think of this as a logbook. Before doing any
scanning work, we write "starting recon on target X" to the database.
When it finishes, we write "done" or "failed: <reason>". If the whole
app crashes mid-scan, the logbook still has the last entry - so on
restart, we can look at the logbook and know exactly what was happening,
instead of guessing or silently losing track.

This is the module that makes the "self-healing" / "crash-safe" behavior
actually work. Nothing about scan progress should ever live only in
Python memory - it goes through here, into Postgres, every time.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import asyncpg

from . import ws_manager

logger = logging.getLogger("swas.checkpoint")

# Phases that don't improve by being retried blindly forever - cap retries
# so a permanently broken target doesn't loop forever.
MAX_RETRIES = 1


async def create_pending_run(
    conn: asyncpg.Connection, project_id: int, target_id: int, phase_name: str
) -> int:
    """
    Creates a 'pending' row for a phase before any work starts. Returns
    the new phase_run's id, which the caller uses to update it later.
    """
    row = await conn.fetchrow(
        """
        INSERT INTO phase_runs (project_id, target_id, phase_name, status)
        VALUES ($1, $2, $3, 'pending')
        RETURNING id
        """,
        project_id,
        target_id,
        phase_name,
    )
    await ws_manager.manager.broadcast(
        project_id,
        {"type": "phase_update", "phase_run_id": row["id"], "target_id": target_id,
         "phase_name": phase_name, "status": "pending"},
    )
    return row["id"]


@asynccontextmanager
async def run_phase(
    pool: asyncpg.Pool, phase_run_id: int, project_id: int, target_id: int, phase_name: str
):
    """
    A context manager that wraps the ACTUAL scanning work for one phase,
    on one target. Use it like this:

        async with run_phase(pool, phase_run_id, project_id, target_id, phase_name):
            result = await run_subfinder(target)
            ...

    What it does automatically:
      - Marks the row 'in_progress' with a start time, right before your
        code runs
      - If your code finishes without raising an exception, marks the
        row 'completed' with an end time
      - If your code raises ANY exception, it is caught here, logged with
        the real error message (never silently swallowed), the row is
        marked 'failed', and the exception is then re-raised so the
        caller (the pipeline orchestrator) knows this phase didn't
        succeed and can decide whether to retry or move on.
      - Broadcasts every one of these transitions over ws_manager, so any
        browser tab watching this project's page gets the update the
        instant it happens rather than waiting for its next poll.

    This is the single place that implements "never silently lose a
    failure" - every phase, no matter what tool it's running, gets this
    same safety net.

    Takes `pool`, not a pre-acquired `conn` - only acquires a connection
    for the two brief status-update writes (entry and exit), never while
    your code is actually running. A previous version held one
    connection open for the whole yielded block, which for phases doing
    many slow outbound HTTP calls (subdomain takeover checks, the ~130
    detective.py checks) meant a connection sat idle-but-checked-out for
    minutes at a time - confirmed live on OCI to saturate the pool and
    block the rest of the app, including a plain health check, on any
    project with several targets scanning concurrently.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE phase_runs
            SET status = 'in_progress', started_at = $2
            WHERE id = $1
            """,
            phase_run_id,
            datetime.now(timezone.utc),
        )
    await ws_manager.manager.broadcast(
        project_id,
        {"type": "phase_update", "phase_run_id": phase_run_id, "target_id": target_id,
         "phase_name": phase_name, "status": "in_progress"},
    )

    try:
        yield
    except Exception as exc:
        # Log the REAL error - this is the fix for the known "silent
        # exception swallowing" bug from earlier versions of this tool.
        logger.exception("Phase run %s failed", phase_run_id)

        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE phase_runs
                SET status = 'failed',
                    completed_at = $2,
                    error_message = $3,
                    retry_count = retry_count + 1
                WHERE id = $1
                """,
                phase_run_id,
                datetime.now(timezone.utc),
                str(exc)[:2000],  # cap length so one giant error can't bloat the row
            )
        await ws_manager.manager.broadcast(
            project_id,
            {"type": "phase_update", "phase_run_id": phase_run_id, "target_id": target_id,
             "phase_name": phase_name, "status": "failed"},
        )
        # Re-raise so the orchestrator (pipeline.py) knows this failed and
        # can apply retry/skip logic. We never swallow the error here.
        raise
    else:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE phase_runs
                SET status = 'completed', completed_at = $2
                WHERE id = $1
                """,
                phase_run_id,
                datetime.now(timezone.utc),
            )
        await ws_manager.manager.broadcast(
            project_id,
            {"type": "phase_update", "phase_run_id": phase_run_id, "target_id": target_id,
             "phase_name": phase_name, "status": "completed"},
        )


async def mark_needs_attention(
    conn: asyncpg.Connection, phase_run_id: int, reason: str,
    project_id: int | None = None, target_id: int | None = None, phase_name: str | None = None,
) -> None:
    """
    Used when a phase has failed and already used up its retries. Instead
    of trying again and again, we flag it for a human to look at and move
    the pipeline on to the next target - this is what stops one broken
    target from blocking the whole queue.

    project_id/target_id/phase_name are optional so the startup recovery
    path (recover_interrupted_runs, which doesn't have live browser tabs
    watching anyway) doesn't need to look them up just to call this.
    """
    await conn.execute(
        """
        UPDATE phase_runs
        SET status = 'needs_attention', error_message = $2
        WHERE id = $1
        """,
        phase_run_id,
        reason[:2000],
    )
    if project_id is not None:
        await ws_manager.manager.broadcast(
            project_id,
            {"type": "phase_update", "phase_run_id": phase_run_id, "target_id": target_id,
             "phase_name": phase_name, "status": "needs_attention"},
        )


# Phases listed here so this module doesn't need to import pipeline.py
# (which would create a circular import - pipeline.py imports checkpoint).
_ALL_PHASES = ["recon", "probe", "fuzz", "scan", "gate", "logic_hunter", "triage", "notify"]


async def mark_remaining_phases_skipped(
    conn: asyncpg.Connection, project_id: int, target_id: int, after_phase: str
) -> None:
    """
    Signal-based budgeting: when a target shows zero signal (e.g. probe
    found no live hosts), running fuzz/scan against it would just waste
    time and compute for no benefit. Rather than silently doing nothing,
    we explicitly create 'completed' rows for the skipped phases with a
    clear error_message explaining why - so this shows up honestly in
    phase-runs as "skipped, here's why" rather than looking like it never
    ran or like something crashed.

    There's no separate 'skipped' status in the schema (avoiding a
    migration for Phase 2) - 'completed' + an explanatory message is the
    honest, queryable choice here.
    """
    remaining = _ALL_PHASES[_ALL_PHASES.index(after_phase) + 1:]
    now = datetime.now(timezone.utc)

    for phase_name in remaining:
        await conn.execute(
            """
            INSERT INTO phase_runs
                (project_id, target_id, phase_name, status, started_at, completed_at, error_message)
            VALUES ($1, $2, $3, 'completed', $4, $4, $5)
            """,
            project_id,
            target_id,
            phase_name,
            now,
            f"Skipped: no live hosts found in probe phase (signal-based budgeting)",
        )


async def get_interrupted_runs(conn: asyncpg.Connection) -> list[asyncpg.Record]:
    """
    Called once when the app starts up. Finds any phase_runs that were
    left 'in_progress' the last time the app ran - meaning the app
    crashed or was restarted mid-scan, and that phase never got a chance
    to mark itself completed or failed.

    These get flagged 'needs_attention' rather than silently resumed,
    because we can't be sure how much of the tool's work actually
    finished before the crash - it's safer to have a human glance at it
    than to guess.
    """
    rows = await conn.fetch(
        "SELECT id, project_id, target_id, phase_name FROM phase_runs WHERE status = 'in_progress'"
    )
    return rows


async def recover_interrupted_runs(conn: asyncpg.Connection) -> int:
    """
    Marks any leftover 'in_progress' rows as 'needs_attention' on
    startup. Returns how many were found, so the app can log a clear
    message like "found 2 interrupted scans from before a restart."
    """
    interrupted = await get_interrupted_runs(conn)
    for row in interrupted:
        await mark_needs_attention(
            conn,
            row["id"],
            "Interrupted: app restarted while this phase was in progress",
        )
    return len(interrupted)
