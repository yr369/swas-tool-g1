"""
scan_orchestration.py - the background-task machinery: the
per-project scan trigger, the app-wide concurrent-scan semaphore,
the scan-queue/scheduler/daily-digest/stale-flag/ai-retry-queue
background loops, and the helpers that finalize a project's status
once every target's pipeline finishes. Split out of the former
monolithic main.py (batch: main.py split) into its own module
(rather than a routers/ file) specifically because main.py's own
lifespan() function starts these loops directly - keeping this
separate from routers/ avoids lifespan importing from a router
module, which would invert the natural app -> routers dependency
direction for no reason.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from . import auth_policy, checkpoint, config, database, gemini_rotation, logic_hunter, pipeline, retry_queue, tools, ws_manager

logger = logging.getLogger("swas.main")

_TARGET_SCAN_SEMAPHORE = asyncio.Semaphore(int(os.environ.get("MAX_CONCURRENT_TARGET_SCANS", "4")))


async def _run_target_pipeline_limited(pool, project_id: int, target_id: int, target: str) -> None:
    """Wraps pipeline.run_target_pipeline with the app-wide concurrency
    cap above. ALL calls to run_target_pipeline should go through this,
    not the pipeline function directly, or the cap does nothing."""
    async with _TARGET_SCAN_SEMAPHORE:
        await pipeline.run_target_pipeline(pool, project_id, target_id, target)


async def _trigger_scan_for_project(project_id: int) -> dict:
    """
    Core scan-kickoff logic: validates the project has in-scope targets
    and isn't denylisted, marks it 'scanning', bookmarks a scan_runs row,
    and schedules the actual per-target pipeline work.

    Shared by two callers: the manual POST /scan endpoint below, and the
    scheduled-scan loop (_run_due_scheduled_scans). Raises HTTPException
    on problems - the manual endpoint lets that propagate as a normal API
    error, while the scheduler loop catches it and just logs + moves on,
    so a single misconfigured project (e.g. someone cleared its scope)
    can't take down the whole scheduling loop.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT id, status FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if project["status"] == "scanning":
            raise HTTPException(
                status_code=409,
                detail="A scan is already in progress for this project",
            )

        targets = await conn.fetch(
            "SELECT id, target, reward_range FROM scope_targets WHERE project_id = $1 AND in_scope = true",
            project_id,
        )
        # Highest-payout targets first: with MAX_CONCURRENT_TARGET_SCANS
        # bounding concurrency, order determines which targets actually
        # get worked on first rather than sitting in the queue behind
        # lower-value ones. See target_intelligence.compute_payout_priority.
        targets = target_intelligence.order_target_rows(targets)

        if not targets:
            raise HTTPException(
                status_code=400,
                detail="No in-scope targets found for this project - add scope first",
            )

        denylist_raw = os.environ.get("DENYLIST_DOMAINS", "")
        denylist = [d.strip().lower() for d in denylist_raw.split(",") if d.strip()]
        if denylist:
            blocked = [t for t in targets if any(d in t["target"].lower() for d in denylist)]
            if blocked:
                blocked_names = ", ".join(t["target"] for t in blocked)
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Refusing to scan: {blocked_names} matches DENYLIST_DOMAINS. "
                        f"These are explicitly excluded even if marked in-scope - "
                        f"remove them from scope or check your program's exclusion list."
                    ),
                )

        await conn.execute(
            "UPDATE projects SET status = 'scanning' WHERE id = $1", project_id
        )
        await conn.execute(
            "INSERT INTO scan_runs (project_id) VALUES ($1)", project_id
        )

    tasks = [
        asyncio.create_task(
            _run_target_pipeline_limited(pool, project_id, target_row["id"], target_row["target"])
        )
        for target_row in targets
    ]
    asyncio.create_task(_finalize_scan_status(pool, project_id, tasks))

    return {
        "message": f"Scan started for {len(targets)} target(s)",
        "target_count": len(targets),
    }


# Tasks fired via asyncio.create_task() are only weakly referenced by the
# event loop - if nothing else holds a reference, the task can be garbage
# collected mid-run (a documented asyncio gotcha), and even when it isn't,
# an exception raised inside it is swallowed except for an
# "Task exception was never retrieved" log line nobody's watching. This set
# holds a strong reference until each task finishes, and logs failures the
# same way _finalize_scan_status does for the batch-scan path below.
_background_tasks: set[asyncio.Task] = set()


def _spawn_background_task(coro, *, description: str) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def _on_done(t: asyncio.Task) -> None:
        _background_tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            logger.error("background task failed (%s): %r", description, exc, exc_info=exc)

    task.add_done_callback(_on_done)
    return task


async def _finalize_scan_status(pool, project_id: int, tasks: list) -> None:
    """Waits for every per-target pipeline task from a single scan kickoff
    to finish, then flips the project out of 'scanning'.

    Without this, `status` sticks on 'scanning' forever (targets run as
    fire-and-forget asyncio tasks - nothing else ever writes a terminal
    status), which also silently breaks the scheduler loop and the
    duplicate-scan guard above, since both gate on status != 'scanning'.

    Always resolves to 'completed', even if some targets raised - the
    projects table's CHECK constraint only allows
    created/scanning/completed/archived, there is no 'error'/'failed'
    value at this level. Per-target/per-phase failures are already
    tracked with proper granularity in phase_runs (which does have a
    'failed' status), so that's the right place to look for what
    actually went wrong; this just logs a warning here for visibility.
    """
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failures = [r for r in results if isinstance(r, Exception)]
    if failures:
        for i, exc in enumerate(failures):
            logger.error(
                "scan failure detail (%d/%d) for project %s: %r",
                i + 1, len(failures), project_id, exc,
                exc_info=exc,
            )
        logger.warning(
            "scan for project %s: %d of %d target(s) raised an error - "
            "project status still resolves to 'completed' (no 'error' "
            "value exists in projects.status); check phase_runs for detail",
            project_id, len(failures), len(results),
        )
    new_status = "completed"
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE projects SET status = $1 WHERE id = $2", new_status, project_id
        )


async def _run_due_scheduled_scans() -> None:
    """One pass of the scheduler: find every project whose schedule is
    due - recurring (scan_interval_hours set) OR one-time (Batch 6:
    run_at was set with no interval) - kick each one off, and push its
    next-run time forward (recurring) or clear it (one-time) regardless
    of whether the kickoff succeeded - a project that's misconfigured
    (e.g. its scope got cleared) shouldn't be retried every 60 seconds
    forever, just tried again next interval (or, for one-time, not
    retried at all - it already had its one shot)."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        due = await conn.fetch(
            """
            SELECT id, scan_interval_hours FROM projects
            WHERE next_scheduled_scan_at IS NOT NULL
              AND next_scheduled_scan_at <= now()
              AND status != 'scanning'
            """
        )

    for row in due:
        project_id = row["id"]
        try:
            await _enqueue_project(project_id, priority=False)
            logger.info("scheduler: added scheduled scan for project %s to the queue", project_id)
        except HTTPException as exc:
            # 409 here just means it's already queued/running from a
            # previous trigger - not an error, nothing else to do.
            logger.warning("scheduler: skipped project %s (%s)", project_id, exc.detail)
        except Exception:
            logger.exception("scheduler: unexpected error enqueueing project %s", project_id)
        finally:
            async with pool.acquire() as conn:
                if row["scan_interval_hours"] is None:
                    # One-time run_at, no recurrence - clear it so this
                    # project goes back to manual-only, not an infinite
                    # "next run is right now" loop firing every pass.
                    await conn.execute(
                        "UPDATE projects SET next_scheduled_scan_at = NULL WHERE id = $1",
                        project_id,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE projects
                        SET next_scheduled_scan_at = now() + make_interval(hours => scan_interval_hours)
                        WHERE id = $1
                        """,
                        project_id,
                    )


async def _scheduler_loop() -> None:
    """Runs for the lifetime of the app, checking for due scheduled
    scans once a minute. 60s is frequent enough that a schedule set to
    'every 6 hours' fires within a minute of its target time, without
    hammering the database - this is a single-process, in-memory loop,
    matching the same single-container assumption ws_manager.py already
    documents (no --workers flag in the Dockerfile CMD)."""
    logger.info("scan scheduler loop started (checks every 60s)")
    while True:
        try:
            await _run_due_scheduled_scans()
        except Exception:
            logger.exception("scheduler loop iteration failed - will retry in 60s")
        await asyncio.sleep(60)


# #4: daily activity digest. In-memory "last sent" tracker is fine for
# the same reason the scheduler loop's in-memory state is fine - single
# process, no --workers flag. A restart just means today's digest might
# fire again if it's still the target hour, which is harmless (worst
# case: one duplicate digest after a redeploy).
_digest_last_sent_date: str | None = None


async def _send_daily_digest() -> None:
    global _digest_last_sent_date
    digest_hour = int(os.environ.get("DIGEST_HOUR_UTC", "8"))
    now = datetime.now(timezone.utc)
    today_str = now.date().isoformat()
    if now.hour != digest_hour or _digest_last_sent_date == today_str:
        return
    if not os.environ.get("NOTIFY_WEBHOOK_URL"):
        return

    pool = database.get_pool()
    async with pool.acquire() as conn:
        new_findings = await conn.fetchrow(
            """
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) AS high_value
            FROM findings WHERE created_at >= now() - interval '24 hours'
            """
        )
        scans_run = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_runs WHERE started_at >= now() - interval '24 hours'"
        )
        stale_flags = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_notes WHERE check_name = 'stale_project' AND NOT dismissed "
            "AND created_at >= now() - interval '24 hours'"
        )

    msg = (
        f"[DAILY DIGEST] {new_findings['total']} new finding(s) in the last 24h "
        f"({new_findings['high_value']} critical/high) · {scans_run} scan(s) run · "
        f"{stale_flags} project(s) newly flagged stale"
    )
    result = await tools.run_notify(msg)
    if not result.success:
        logger.info("daily digest send failed (non-fatal): %s", result.error)
    _digest_last_sent_date = today_str


async def _digest_loop() -> None:
    logger.info("daily digest loop started (checks hourly)")
    while True:
        try:
            await _send_daily_digest()
        except Exception:
            logger.exception("digest loop iteration failed - will retry in 1h")
        await asyncio.sleep(3600)


# #6: flag (not auto-archive) projects with no recent activity. Reuses
# scan_notes - the same dismissable-note mechanism already shown in the
# UI for scan-quality issues - rather than inventing a new notification
# surface. "Activity" here means the same signal Chronology uses:
# created, target added, project scanned, or target rescanned.
async def _flag_stale_projects() -> None:
    stale_days = int(os.environ.get("STALE_PROJECT_DAYS", "30"))
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name,
                   GREATEST(
                       p.created_at,
                       COALESCE((SELECT MAX(created_at) FROM scope_targets WHERE project_id = p.id), p.created_at),
                       COALESCE((SELECT MAX(last_scanned_at) FROM scope_targets WHERE project_id = p.id), p.created_at),
                       COALESCE((SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id), p.created_at)
                   ) AS last_activity_at
            FROM projects p
            WHERE p.status != 'archived'
            """
        )
        for r in rows:
            if r["last_activity_at"] >= datetime.now(timezone.utc) - timedelta(days=stale_days):
                continue
            already_flagged = await conn.fetchval(
                "SELECT 1 FROM scan_notes WHERE project_id = $1 AND check_name = 'stale_project' AND NOT dismissed",
                r["id"],
            )
            if already_flagged:
                continue
            await conn.execute(
                """
                INSERT INTO scan_notes (project_id, check_name, note)
                VALUES ($1, 'stale_project', $2)
                """,
                r["id"],
                f"No activity in {stale_days}+ days (last activity {r['last_activity_at'].date().isoformat()}) - "
                f"consider archiving if this program is done, or scanning again if it's still live.",
            )
            logger.info("Flagged project_id=%s (%s) as stale", r["id"], r["name"])


async def _stale_flag_loop() -> None:
    logger.info("stale-project flag loop started (checks daily)")
    while True:
        try:
            await _flag_stale_projects()
        except Exception:
            logger.exception("stale-flag loop iteration failed - will retry in 24h")
        await asyncio.sleep(86400)


async def _enqueue_project(project_id: int, priority: bool = False) -> dict:
    """Adds a project to the scan queue instead of triggering it directly.
    Both the manual POST /scan endpoint and the scheduler loop now call
    this instead of _trigger_scan_for_project - the queue worker loop
    below is the ONLY thing that ever calls _trigger_scan_for_project, so
    there is one execution path, not two competing ones.

    Position is per-lane (priority items are ordered among themselves,
    normal items among themselves) - the worker always drains all
    priority items before touching a normal one, regardless of position
    number, via ORDER BY priority DESC, position ASC.

    Raises HTTPException(409) if this project already has an active
    (queued or running) queue entry - matches the DB's partial unique
    index, so this is a friendly pre-check, not the only guard.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        existing = await conn.fetchrow(
            "SELECT id FROM scan_queue WHERE project_id = $1 AND status IN ('queued', 'running')",
            project_id,
        )
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="This project already has an active queue entry",
            )

        next_position = await conn.fetchval(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM scan_queue WHERE priority = $1 AND status = 'queued'",
            priority,
        )
        row = await conn.fetchrow(
            """
            INSERT INTO scan_queue (project_id, position, priority)
            VALUES ($1, $2, $3)
            RETURNING id, project_id, position, priority, status, queued_at, started_at, completed_at
            """,
            project_id, next_position, priority,
        )
    return dict(row)


async def _run_due_queue_item() -> None:
    """One pass of the queue worker: first, reconcile any 'running' queue
    row whose project has already left 'scanning' (the scan finished,
    but nothing told the queue) - then, if nothing is running, start the
    next queued item.

    Deliberately serial - only one 'running' row at a time, project-wide,
    not per-project. This matches the plan's "queue position + estimated
    start time" requirement, which only makes sense if items actually
    wait their turn instead of all running concurrently.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        running = await conn.fetchrow(
            """
            SELECT sq.id, sq.project_id, p.status AS project_status
            FROM scan_queue sq JOIN projects p ON p.id = sq.project_id
            WHERE sq.status = 'running'
            """
        )
        if running is not None:
            if running["project_status"] != "scanning":
                await conn.execute(
                    "UPDATE scan_queue SET status = 'completed', completed_at = now() WHERE id = $1",
                    running["id"],
                )
            else:
                return  # still running, nothing else to do this pass

        next_item = await conn.fetchrow(
            """
            SELECT id, project_id FROM scan_queue
            WHERE status = 'queued'
            ORDER BY priority DESC, position ASC
            LIMIT 1
            """
        )
        if next_item is None:
            return

    try:
        await _trigger_scan_for_project(next_item["project_id"])
    except HTTPException as exc:
        logger.warning(
            "queue: skipping project %s (%s) - marking queue entry cancelled",
            next_item["project_id"], exc.detail,
        )
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE scan_queue SET status = 'cancelled', completed_at = now() WHERE id = $1",
                next_item["id"],
            )
        return
    except Exception:
        logger.exception("queue: unexpected error starting project %s", next_item["project_id"])
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE scan_queue SET status = 'cancelled', completed_at = now() WHERE id = $1",
                next_item["id"],
            )
        return

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE scan_queue SET status = 'running', started_at = now() WHERE id = $1",
            next_item["id"],
        )


async def _queue_worker_loop() -> None:
    """Runs for the lifetime of the app, checking the queue every 10s.
    Faster than the 60s scheduler loop since queue turnaround is meant
    to feel responsive (an operator watching the queue after a manual
    enqueue shouldn't wait up to a minute for it to start)."""
    logger.info("scan queue worker started (checks every 10s)")
    while True:
        try:
            await _run_due_queue_item()
        except Exception:
            logger.exception("queue worker iteration failed - will retry in 10s")
        await asyncio.sleep(10)


async def _ai_retry_queue_worker_loop() -> None:
    """Runs for the lifetime of the app, checking ai_retry_queue every
    5 minutes. Slower than the 10s scan queue worker on purpose - retry
    items already carry their own exponential backoff (2min-4h, see
    retry_queue._BACKOFF_SCHEDULE_MINUTES), so there is rarely anything
    due; a tight poll loop would just be near-constant no-op DB round
    trips."""
    logger.info("AI retry queue worker started (checks every 5m)")
    while True:
        try:
            processed = await triage.retry_pending_ai_failures(database.get_pool())
            if processed:
                logger.info("AI retry queue: processed %d due item(s)", processed)
        except Exception:
            logger.exception("AI retry queue worker iteration failed - will retry in 5m")
        await asyncio.sleep(300)

