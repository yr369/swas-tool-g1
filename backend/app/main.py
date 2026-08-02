"""
main.py - the FastAPI application entry point.

This is what actually runs when the backend container starts. It:
  1. Connects to Postgres on startup, disconnects cleanly on shutdown
     (this matters for the "crash-safe" requirement - the pool is the one
     thing that must exist before anything else touches the database)
  2. On startup, checks for any scans that were interrupted by a crash
     or restart, and flags them rather than silently ignoring them
  3. Exposes the Phase 1 API endpoints: create/list projects, add scope
     targets, list findings, and trigger/monitor a scan
"""

import asyncio
import csv
import io
import logging
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
import os

from . import auth_policy, auth_sessions, checkpoint, config, database, evidence_lifecycle, gate, gemini_rotation, logic_hunter, oob, pipeline, readiness, report_writer, retry_queue, scope_parser, screenshots, target_intelligence, tools, triage, vrt, ws_manager
from .models import (
    Project,
    ProjectCreate,
    ProjectUpdate,
    AuthPolicy,
    AuthSessionMeta,
    ProjectBulkActionRequest,
    ProjectBulkActionResult,
    ScheduleUpdateRequest,
    ProjectDeleteRequest,
    ScanNote,
    QueueEnqueueRequest,
    QueueReorderRequest,
    ScanQueueItem,
    ScopeTarget,
    ScopeTargetCreate,
    ScopeTargetUpdate,
    BulkScopeTargetsCreate,
    BulkScopeTargetsResult,
    ScopeParseRequest,
    ScopeParsePreview,
    ScopeConfirmRequest,
    Finding,
    FindingWithProject,
    FindingBulkStatusRequest,
    FindingBulkStatusResult,
    ReportDraft,
    PhaseRun,
    ScanRun,
    OutcomeLogRequest,
    OutcomeRecord,
    SignatureStats,
    ReadinessResponse,
    DiffResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("swas.main")

# Long-term fix for a real production incident (OCI, this session): a
# scan kicked off one asyncio task PER scope target with NO limit on how
# many ran concurrently. A project with dozens of scope targets - not
# unusual for an org-wide bug bounty scope - would fire off dozens of
# full pipelines (recon/probe/fuzz/scan, each spawning subfinder,
# httpx, nuclei, ffuf, dalfox, sqlmap, arjun subprocesses) all at once.
# Confirmed live: load average of 83 on a 4-OCPU box, one container at
# 389% CPU with 245 PIDs. This wasn't a database problem at all - the
# earlier connection-pool fixes were real and worth keeping, but this
# is the actual root cause of the CPU/host-level meltdown.
#
# MAX_CONCURRENT_TARGET_SCANS caps how many scope targets can have an
# active pipeline running at once, app-wide - not per-project, since
# the scan queue (Batch 4b) already caps concurrent PROJECTS at one,
# but a single project's dozens of targets were still all racing each
# other under that one project slot. Default of 4 matches this OCI
# instance's OCPU count; override via env var if the instance is
# resized. Tune down further if load still climbs with the new cap in
# place - each target's own scan phase also runs its ~130 detective
# checks with internal concurrency, so total CPU pressure isn't purely
# linear in this number.
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs once when the app starts up. Config sanity check comes FIRST,
    # before even the DB connection - a missing GEMINI_API_KEY or a
    # nuclei binary that never made it into the image should surface as
    # one clear crash-on-boot, not a cryptic KeyError/FileNotFoundError
    # three phases into someone's first real scan.
    config_warnings = config.check_startup_config()
    for w in config_warnings:
        logger.warning("STARTUP CONFIG WARNING: %s", w)

    await database.connect_db()

    # Crash-safety check: if the app was restarted while scans were mid-
    # flight, those phase_runs are stuck "in_progress" with no one ever
    # going to mark them finished. We flag them now rather than letting
    # them sit there silently forever.
    pool = database.get_pool()
    async with pool.acquire() as conn:
        recovered_count = await checkpoint.recover_interrupted_runs(conn)

        # The scan-status fix relies on an in-memory supervisor task
        # (_finalize_scan_status) to flip a project out of 'scanning'
        # once every target's pipeline finishes. That task lives only in
        # this process - a restart kills it along with everything else,
        # leaving the project stuck on 'scanning' with nothing left to
        # ever resolve it, same symptom as the original bug but from a
        # different cause. Any project still 'scanning' at startup time
        # is, by definition, orphaned from a previous process.
        #
        # Resets to 'created', not 'completed' - the projects table's
        # CHECK constraint only allows created/scanning/completed/
        # archived (no 'error'/'failed' value exists at this level, see
        # _finalize_scan_status's docstring for the same constraint).
        # 'created' is the honest choice here: the scan never reached a
        # real verdict, so claiming 'completed' would be misleading.
        # Any findings/phase_runs already written before the interruption
        # are untouched - this only resets the top-level status marker.
        stuck_project_rows = await conn.fetch(
            "SELECT id, name FROM projects WHERE status = 'scanning'"
        )
        if stuck_project_rows:
            await conn.execute("UPDATE projects SET status = 'created' WHERE status = 'scanning'")

        # Same orphaning problem, one level up: a queue row left
        # 'running' from a killed process now points at a project that
        # was just reset to 'created' above - the worker loop would see
        # project_status != 'scanning' and mark it 'completed' (a lie,
        # it never finished). Put it back at the front of its lane
        # instead so the worker retries it for real.
        stuck_queue_rows = await conn.fetch("SELECT id, project_id FROM scan_queue WHERE status = 'running'")
        if stuck_queue_rows:
            await conn.execute(
                "UPDATE scan_queue SET status = 'queued', position = 0, started_at = NULL WHERE status = 'running'"
            )

    if recovered_count > 0:
        logger.warning(
            "Found and flagged %d scan phase(s) interrupted by a previous "
            "restart - check phase_runs with status='needs_attention'",
            recovered_count,
        )
    if stuck_project_rows:
        logger.warning(
            "Reset %d project(s) stuck on 'scanning' from a previous restart "
            "back to 'created' (orphaned by process restart, not a real "
            "failure - safe to re-trigger a scan): %s",
            len(stuck_project_rows),
            ", ".join(f"{r['id']}:{r['name']}" for r in stuck_project_rows),
        )

    if stuck_queue_rows:
        logger.warning(
            "Reset %d scan_queue row(s) stuck on 'running' from a previous restart "
            "back to 'queued' at the front of their lane: %s",
            len(stuck_queue_rows),
            ", ".join(f"{r['id']}:project {r['project_id']}" for r in stuck_queue_rows),
        )

    scheduler_task = asyncio.create_task(_scheduler_loop())
    queue_worker_task = asyncio.create_task(_queue_worker_loop())
    digest_task = asyncio.create_task(_digest_loop())
    stale_flag_task = asyncio.create_task(_stale_flag_loop())
    ai_retry_task = asyncio.create_task(_ai_retry_queue_worker_loop())

    yield
    # Runs once when the app shuts down (e.g. container stopping)
    scheduler_task.cancel()
    queue_worker_task.cancel()
    digest_task.cancel()
    stale_flag_task.cancel()
    ai_retry_task.cancel()
    await database.disconnect_db()


app = FastAPI(title="SWAS API", version="0.1.0", lifespan=lifespan)

# Allow the frontend (running on a different origin during local dev) to
# call this API. In production, Caddy proxies both under the same domain,
# but this stays useful for local development.
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in allowed_origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health_check():
    """Simple endpoint to confirm the API is up and can reach the database."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return {"status": "ok"}


@app.get("/api/health/dashboard")
async def health_dashboard():
    """
    Batch 25 item 1. Everything /api/health doesn't tell you: AI model
    rotation health (circuit breaker state + today's usage - items 2/3),
    whether every required tool binary is present AND at the pinned
    version (batch 26 item 2), whether nuclei's template set is stale
    (batch 26 item 1), whether OOB/interactsh confirmation is even
    possible on this deployment, how many phase runs have failed/needed
    attention in the last 24h across all projects, and - if any project
    is flagged as a synthetic canary - whether its latest scan's finding
    count has drifted from its baseline (batch 25 item 4: a silent sign
    something in the pipeline itself broke, independent of any real
    target's actual results).

    Deliberately read-only and side-effect-free - safe to poll from a
    dashboard on a timer. Each section fails independently (wrapped so
    one broken check, e.g. a tool binary genuinely missing, can't take
    the whole dashboard down) - a section reporting an error is itself
    useful signal, not a 500.
    """
    pool = database.get_pool()

    async def _safe(coro):
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001 - a broken health CHECK is itself a health signal, not a crash
            return {"error": str(exc)}

    async with pool.acquire() as conn:
        db_ok = True
        try:
            await conn.fetchval("SELECT 1")
        except Exception:
            db_ok = False

        recent_failures = await conn.fetch(
            """
            SELECT phase_name, status, count(*) AS n
            FROM phase_runs
            WHERE started_at > now() - interval '24 hours'
              AND status IN ('failed', 'needs_attention')
            GROUP BY phase_name, status
            ORDER BY n DESC
            """
        )

        canary_rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.canary_baseline_finding_count,
                   (SELECT count(*) FROM findings f
                    JOIN scope_targets t ON t.id = f.target_id
                    WHERE t.project_id = p.id) AS current_finding_count
            FROM projects p
            WHERE p.is_canary = true
            """
        )

        # Batch 27: retry queue depth (batch 20) and evidence-lifecycle
        # signals (batch 24) weren't visible anywhere before this - both
        # only existed as DB state a worker consumed silently. Surfacing
        # them here means "AI calls are backed up" or "evidence is rotting
        # faster than usual" shows up on the same dashboard as everything
        # else, instead of requiring a manual SQL query to notice.
        retry_queue_rows = await conn.fetch(
            """
            SELECT kind,
                   count(*) FILTER (WHERE status = 'pending') AS pending,
                   count(*) FILTER (WHERE status = 'failed'
                                     AND updated_at > now() - interval '24 hours') AS failed_24h,
                   min(next_attempt_at) FILTER (WHERE status = 'pending') AS oldest_pending_due_at
            FROM ai_retry_queue
            GROUP BY kind
            ORDER BY pending DESC
            """
        )

        evidence_rot_row = await conn.fetchrow(
            """
            SELECT
                count(*) FILTER (WHERE evidence_integrity = 'rotted'
                                  AND evidence_checked_at > now() - interval '7 days') AS rotted_7d,
                count(*) FILTER (WHERE evidence_integrity = 'reproducible'
                                  AND evidence_checked_at > now() - interval '7 days') AS reproducible_7d
            FROM findings
            """
        )

        dead_target_rows = await conn.fetch(
            """
            SELECT t.id, t.target, t.dead_since, p.id AS project_id, p.name AS project_name
            FROM scope_targets t
            JOIN projects p ON p.id = t.project_id
            WHERE t.dead_since IS NOT NULL
            ORDER BY t.dead_since DESC
            LIMIT 10
            """
        )

    canaries = []
    for row in canary_rows:
        baseline = row["canary_baseline_finding_count"]
        current = row["current_finding_count"]
        canaries.append({
            "project_id": row["id"],
            "project_name": row["name"],
            "baseline_finding_count": baseline,
            "current_finding_count": current,
            "drifted": (baseline is not None and current != baseline),
        })

    tool_versions = await _safe(tools.check_tool_version_drift())

    dead_targets = [
        {
            "target_id": r["id"],
            "target": r["target"],
            "project_id": r["project_id"],
            "project_name": r["project_name"],
            "dead_since": r["dead_since"].isoformat() if r["dead_since"] else None,
        }
        for r in dead_target_rows
    ]

    return {
        "database_ok": db_ok,
        "ai": {
            "circuit_breaker": gemini_rotation.get_circuit_breaker_status(),
            "usage_today": gemini_rotation.get_usage_stats(),
        },
        "tools": {
            "binaries_present": {name: shutil.which(name) is not None for name in config._REQUIRED_BINARIES},
            "version_drift": tool_versions,
            "nuclei_templates": tools.check_nuclei_template_freshness(),
        },
        "oob_available": oob.is_available(),
        "recent_phase_failures_24h": [
            {"phase": r["phase_name"], "status": r["status"], "count": r["n"]} for r in recent_failures
        ],
        "canary_targets": canaries,
        "retry_queue": [
            {
                "kind": r["kind"],
                "pending": r["pending"],
                "failed_24h": r["failed_24h"],
                "oldest_pending_due_at": r["oldest_pending_due_at"].isoformat() if r["oldest_pending_due_at"] else None,
            }
            for r in retry_queue_rows
        ],
        "evidence": {
            "rotted_7d": evidence_rot_row["rotted_7d"] if evidence_rot_row else 0,
            "reproducible_7d": evidence_rot_row["reproducible_7d"] if evidence_rot_row else 0,
            "dead_targets": dead_targets,
        },
    }


# ---------- Projects ----------

@app.post("/api/projects", response_model=Project)
async def create_project(payload: ProjectCreate):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO projects (name, platform)
            VALUES ($1, $2)
            RETURNING id, name, platform, status, scan_interval_hours, next_scheduled_scan_at, created_at
            """,
            payload.name,
            payload.platform,
        )
    return dict(row)


@app.get("/api/projects", response_model=List[Project])
async def list_projects():
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count
            FROM projects p
            ORDER BY p.created_at DESC
            """
        )
    return [dict(row) for row in rows]


@app.get("/api/projects/chronology")
async def project_chronology():
    """
    Every project, ranked by most recent activity - not creation date.
    "Activity" is whichever of these happened most recently: the
    project was created, a target was added, the whole project was
    (re)scanned, or a single target was rescanned. This is what powers
    the sidebar's Chronology view: the project you touched five minutes
    ago sits at the top, not buried under whatever was created first.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.platform, p.status, p.created_at,
                   COUNT(st.id) AS target_count,
                   COUNT(*) FILTER (WHERE st.target LIKE '*.%') AS wildcard_count,
                   MAX(st.created_at) AS last_target_added_at,
                   (SELECT st2.target FROM scope_targets st2 WHERE st2.project_id = p.id
                        ORDER BY st2.created_at DESC LIMIT 1) AS latest_target_added,
                   MAX(st.last_scanned_at) AS last_target_scan_at,
                   (SELECT st3.target FROM scope_targets st3 WHERE st3.project_id = p.id
                        ORDER BY st3.last_scanned_at DESC NULLS LAST LIMIT 1) AS latest_scanned_target,
                   (SELECT MAX(sr.started_at) FROM scan_runs sr WHERE sr.project_id = p.id) AS last_project_scan_at,
                   (SELECT COUNT(*) FROM scan_runs sr WHERE sr.project_id = p.id) AS scan_run_count
            FROM projects p
            LEFT JOIN scope_targets st ON st.project_id = p.id
            GROUP BY p.id
            """
        )

    items = []
    for row in rows:
        r = dict(row)
        candidates = [
            ("created", r["created_at"]),
            ("target_added", r["last_target_added_at"]),
            ("scanned", r["last_project_scan_at"]),
            ("target_rescanned", r["last_target_scan_at"]),
        ]
        candidates = [(k, v) for k, v in candidates if v is not None]
        activity_type, activity_at = max(candidates, key=lambda kv: kv[1])
        items.append({
            "id": r["id"], "name": r["name"], "platform": r["platform"], "status": r["status"],
            "target_count": r["target_count"], "wildcard_count": r["wildcard_count"],
            "scan_run_count": r["scan_run_count"],
            "activity_type": activity_type, "activity_at": activity_at,
            "latest_target_added": r["latest_target_added"],
            "latest_scanned_target": r["latest_scanned_target"],
        })
    items.sort(key=lambda x: x["activity_at"], reverse=True)
    return items


@app.get("/api/projects/{project_id}", response_model=Project)
async def get_project(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count
            FROM projects p WHERE p.id = $1
            """,
            project_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


@app.patch("/api/projects/{project_id}", response_model=Project)
async def update_project(project_id: int, payload: ProjectUpdate):
    """
    Renames a project and/or moves it to a different platform/folder,
    and/or (batch 26) sets a per-project AI model override, and/or
    (batch 25) flags/configures it as a synthetic canary target. Doesn't
    touch scope, findings, or scan history - this is metadata only.

    preferred_ai_model: pass "" (empty string) to explicitly clear an
    existing override back to the hardcoded default - None/omitted
    leaves whatever's currently set unchanged, same COALESCE pattern as
    name/platform.
    """
    if all(
        v is None for v in (
            payload.name, payload.platform, payload.preferred_ai_model,
            payload.is_canary, payload.canary_baseline_finding_count,
        )
    ):
        raise HTTPException(status_code=400, detail="Provide at least one field to update")
    if payload.name is not None and not payload.name.strip():
        raise HTTPException(status_code=400, detail="name can't be empty")

    pool = database.get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Project not found")

        # "" means "clear the override" (NULL), distinct from None/omitted
        # ("leave whatever's currently set unchanged") - COALESCE alone
        # can't express that distinction, so it's handled explicitly.
        preferred_ai_model_value = (
            None if payload.preferred_ai_model == "" else payload.preferred_ai_model
        )
        clear_model_override = payload.preferred_ai_model == ""

        await conn.execute(
            """
            UPDATE projects
            SET name = COALESCE($2, name),
                platform = COALESCE($3, platform),
                preferred_ai_model = CASE WHEN $6 THEN NULL ELSE COALESCE($4, preferred_ai_model) END,
                is_canary = COALESCE($5, is_canary),
                canary_baseline_finding_count = COALESCE($7, canary_baseline_finding_count)
            WHERE id = $1
            """,
            project_id, payload.name, payload.platform, preferred_ai_model_value,
            payload.is_canary, clear_model_override, payload.canary_baseline_finding_count,
        )
        row = await conn.fetchrow(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count
            FROM projects p WHERE p.id = $1
            """,
            project_id,
        )
    return dict(row)


# ---------- Authenticated / multi-account testing ----------
# Web-facing surface over auth_policy.py / auth_sessions.py. Every rule
# (default-deny, encryption at rest, never returning a decrypted secret)
# is already enforced in those modules - these routes are a thin,
# deliberately narrow pass-through, not a new place for logic.

# ---------- Authenticated / multi-account testing (read-only) ----------
# auth_cli.py is explicit and deliberate that approving a project and
# handling session credentials stays CLI-only - this box is on the
# public internet with no login layer in front of the API, and this is
# the one feature whose entire point is protecting real bug-bounty
# account credentials. Adding a write path here would undo that
# decision for no real gain. What WAS missing is any way to even see
# the current status without SSHing in - these two read-only routes
# fix that without touching the write-path decision at all.

@app.get("/api/projects/{project_id}/auth-policy", response_model=AuthPolicy)
async def get_auth_policy(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        return await auth_policy.get_policy(conn, project_id)


@app.get("/api/projects/{project_id}/auth-sessions", response_model=List[AuthSessionMeta])
async def list_auth_sessions(project_id: int):
    """Metadata only - matches auth_sessions.list_sessions exactly, never a credential value."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        return await auth_sessions.list_sessions(conn, project_id)


@app.post("/api/projects/bulk-action", response_model=ProjectBulkActionResult)
async def bulk_project_action(payload: ProjectBulkActionRequest):
    """
    Archives or unarchives several projects at once from the project
    list, or deletes them - meant for cleaning up test/duplicate
    projects without clicking into each one individually.

    Archive/unarchive are always safe (just flips status, keeps
    everything). Unarchive sets status back to 'completed' rather than
    trying to guess whether it should be 'created' or 'scanning' - both
    of those imply an active/pending scan state that isn't true right
    after unarchiving, and 'completed' is what every archived project
    actually was immediately before archiving in practice (you archive
    finished work, not projects mid-scan). Delete is guarded the same
    way scope-target delete is guarded: projects cascade to
    scope_targets/findings/phase_runs/scan_runs on delete, so any
    project with at least one finding is skipped rather than silently
    destroyed - it shows up in "blocked" instead, with the finding
    count, so a bulk click can't accidentally erase real results.
    Nonexistent project ids are silently ignored (already gone is fine).
    """
    pool = database.get_pool()
    succeeded: list[int] = []
    blocked: list[dict] = []

    async with pool.acquire() as conn:
        for project_id in payload.project_ids:
            project = await conn.fetchrow(
                "SELECT id, name FROM projects WHERE id = $1", project_id
            )
            if project is None:
                continue

            if payload.action == "archive":
                await conn.execute(
                    "UPDATE projects SET status = 'archived' WHERE id = $1", project_id
                )
                succeeded.append(project_id)
                continue

            if payload.action == "unarchive":
                await conn.execute(
                    "UPDATE projects SET status = 'completed' WHERE id = $1", project_id
                )
                succeeded.append(project_id)
                continue

            # action == "delete"
            finding_count = await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE project_id = $1", project_id
            )
            if finding_count > 0:
                blocked.append({
                    "project_id": project_id,
                    "name": project["name"],
                    "reason": f"{finding_count} finding(s) attached",
                })
                continue

            await conn.execute("DELETE FROM projects WHERE id = $1", project_id)
            succeeded.append(project_id)

    return {"action": payload.action, "succeeded": succeeded, "blocked": blocked}


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: int, payload: ProjectDeleteRequest):
    """
    Permanently deletes a single project (Batch 6) - cascades to
    scope_targets/findings/phase_runs/scan_runs/scan_queue, same as
    bulk-action's delete path. Unlike bulk-action, this does NOT block
    on the project having findings attached - typing the exact project
    name out (checked below) is the deliberate-intent gate here instead,
    matching GitHub's "type the repo name to delete" pattern. If you
    want a reversible option instead, use POST /projects/bulk-action
    with action=archive on this single project id.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT id, name FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        if payload.confirm_name != project["name"]:
            raise HTTPException(
                status_code=400,
                detail="Typed name does not match the project name exactly - nothing was deleted",
            )

        await conn.execute("DELETE FROM projects WHERE id = $1", project_id)

    return {"deleted": True, "id": project_id}


# ---------- Scope targets ----------

@app.post("/api/projects/{project_id}/scope", response_model=ScopeTarget)
async def add_scope_target(project_id: int, payload: ScopeTargetCreate):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        # Confirm the project actually exists before attaching a target to it -
        # gives a clear 404 instead of a confusing foreign-key error.
        project_exists = await conn.fetchval(
            "SELECT 1 FROM projects WHERE id = $1", project_id
        )
        if not project_exists:
            raise HTTPException(status_code=404, detail="Project not found")

        row = await conn.fetchrow(
            """
            INSERT INTO scope_targets
                (project_id, target, target_type, in_scope, reward_range, notes)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, project_id, target, target_type, in_scope,
                      reward_range, notes, last_scanned_at, created_at
            """,
            project_id,
            payload.target,
            payload.target_type,
            payload.in_scope,
            payload.reward_range,
            payload.notes,
        )
    return dict(row)


@app.get("/api/projects/{project_id}/scope", response_model=List[ScopeTarget])
async def list_scope_targets(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, project_id, target, target_type, in_scope,
                   reward_range, notes, last_scanned_at, created_at
            FROM scope_targets
            WHERE project_id = $1
            ORDER BY created_at ASC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


@app.patch("/api/projects/{project_id}/scope/{target_id}", response_model=ScopeTarget)
async def update_scope_target(project_id: int, target_id: int, payload: ScopeTargetUpdate):
    """
    Edits a scope target in place - fixing a typo'd hostname, changing
    its type, or flipping in_scope. Only the fields actually present in
    the request body are touched (PATCH semantics), so a partial update
    like {"in_scope": false} doesn't accidentally clobber the target
    string or notes.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id FROM scope_targets WHERE id = $1 AND project_id = $2",
            target_id, project_id,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Scope target not found")

        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            row = await conn.fetchrow(
                """
                SELECT id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at
                FROM scope_targets WHERE id = $1
                """,
                target_id,
            )
            return dict(row)

        # Field names here come from ScopeTargetUpdate's fixed set of
        # attributes, never from arbitrary user input, so building the
        # SET clause from these keys carries no injection risk - the
        # VALUES are still fully parameterized.
        set_clauses = []
        params = []
        for key, value in updates.items():
            params.append(value)
            set_clauses.append(f"{key} = ${len(params)}")
        params.append(target_id)

        row = await conn.fetchrow(
            f"""
            UPDATE scope_targets
            SET {", ".join(set_clauses)}
            WHERE id = ${len(params)}
            RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at
            """,
            *params,
        )
    return dict(row)

@app.post("/api/projects/{project_id}/scope/{target_id}/rescan")
async def rescan_target(project_id: int, target_id: int):
    """
    Reruns the pipeline for exactly one host, without touching recon or
    any other host in the project - for when a fix just went out and
    you want to confirm it, or a host errored/timed out and you want to
    retry just that one instead of rerunning the whole project.

    Deliberately does NOT flip projects.status to 'scanning' the way a
    full project scan does - that status/the scheduler loop are about
    whole-project runs, and a single-host rescan is a lighter-weight,
    independent action that shouldn't block or interact with either.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        target_row = await conn.fetchrow(
            "SELECT id, target, in_scope FROM scope_targets WHERE id = $1 AND project_id = $2",
            target_id, project_id,
        )
        if target_row is None:
            raise HTTPException(status_code=404, detail="Scope target not found")
        if not target_row["in_scope"]:
            raise HTTPException(
                status_code=400,
                detail="This target is marked out-of-scope - flip it back in-scope before rescanning",
            )

        denylist_raw = os.environ.get("DENYLIST_DOMAINS", "")
        denylist = [d.strip().lower() for d in denylist_raw.split(",") if d.strip()]
        if denylist and any(d in target_row["target"].lower() for d in denylist):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Refusing to scan: {target_row['target']} matches DENYLIST_DOMAINS. "
                    f"This is explicitly excluded even if marked in-scope."
                ),
            )

        in_progress = await conn.fetchval(
            "SELECT 1 FROM phase_runs WHERE target_id = $1 AND status = 'in_progress' LIMIT 1",
            target_id,
        )
        if in_progress:
            raise HTTPException(
                status_code=409,
                detail="This host already has a scan in progress - wait for it to finish before rescanning",
            )

    _spawn_background_task(
        _run_target_pipeline_limited(pool, project_id, target_id, target_row["target"]),
        description=f"rescan target_id={target_id} project_id={project_id}",
    )

    return {
        "message": f"Rescan started for {target_row['target']}",
        "target_id": target_id,
    }


@app.delete("/api/projects/{project_id}/scope/{target_id}")
async def delete_scope_target(project_id: int, target_id: int):
    """
    Removes a scope target - but only if it has no findings attached.
    scope_targets cascades to findings on delete, so removing a target
    that's already been scanned would silently wipe out real findings
    data along with it. For a target with history, flip in_scope to
    false instead (via PATCH) - that keeps the record and its findings
    while excluding it from future scans.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id FROM scope_targets WHERE id = $1 AND project_id = $2",
            target_id, project_id,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Scope target not found")

        finding_count = await conn.fetchval(
            "SELECT COUNT(*) FROM findings WHERE target_id = $1", target_id
        )
        if finding_count > 0:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"This target has {finding_count} finding(s) attached - deleting it would "
                    f"delete those findings too. Set it out of scope instead if you want to "
                    f"exclude it from future scans without losing existing results."
                ),
            )

        await conn.execute("DELETE FROM scope_targets WHERE id = $1", target_id)
    return {"deleted": True, "id": target_id}


@app.post("/api/projects/{project_id}/scope/bulk", response_model=BulkScopeTargetsResult)
async def bulk_add_scope_targets(project_id: int, payload: BulkScopeTargetsCreate):
    """
    Adds many targets at once from a pasted list - the common case when
    copying a program's scope table straight from Bugcrowd/HackerOne.
    All targets in the batch share the same type/in_scope/reward_range/
    notes; blank lines are dropped, and anything already in this
    project's scope (exact string match) is skipped rather than
    duplicated, with the skipped list returned so the operator can see
    what didn't get re-added.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project_exists = await conn.fetchval("SELECT 1 FROM projects WHERE id = $1", project_id)
        if not project_exists:
            raise HTTPException(status_code=404, detail="Project not found")

        existing_rows = await conn.fetch(
            "SELECT target FROM scope_targets WHERE project_id = $1", project_id
        )
        existing_targets = {row["target"] for row in existing_rows}

        cleaned: list[str] = []
        seen_in_batch = set()
        for raw in payload.targets:
            t = raw.strip()
            if not t or t in seen_in_batch:
                continue
            seen_in_batch.add(t)
            cleaned.append(t)

        if not cleaned:
            raise HTTPException(status_code=400, detail="No valid targets found in the pasted list")

        skipped = [t for t in cleaned if t in existing_targets]
        to_insert = [t for t in cleaned if t not in existing_targets]

        created = []
        for t in to_insert:
            row = await conn.fetchrow(
                """
                INSERT INTO scope_targets
                    (project_id, target, target_type, in_scope, reward_range, notes)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at
                """,
                project_id, t, payload.target_type, payload.in_scope, payload.reward_range, payload.notes,
            )
            created.append(dict(row))

    return {"created": created, "skipped_duplicates": skipped}


@app.get("/api/projects/{project_id}/scope/overlaps")
async def get_scope_overlaps(project_id: int):
    """
    #1: flags targets already covered by an existing wildcard in this
    project's scope - e.g. adding "api.example.com" when "*.example.com"
    is already in scope. Advisory only, never blocks adding a target
    (a program might still want the narrower entry tracked separately
    for its own reward_range/notes) - see scope_parser.find_covering_wildcard.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, target FROM scope_targets WHERE project_id = $1 AND in_scope = true",
            project_id,
        )
    targets = [r["target"] for r in rows]
    overlaps = []
    for row in rows:
        covering = scope_parser.find_covering_wildcard(targets, row["target"])
        if covering:
            overlaps.append({"target_id": row["id"], "target": row["target"], "covered_by": covering})
    return overlaps


@app.get("/api/projects/{project_id}/scope/duration-estimates")
async def get_scope_duration_estimates(project_id: int):
    """
    #3: rough expected scan duration per target, based on this
    project's own phase_runs history (falls back to a global average
    across all projects if this specific target has never completed a
    full run yet - a brand new target still gets a useful number
    instead of nothing). Sums the average completed-start gap per phase
    across the standard 9-phase pipeline.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT st.id AS target_id, st.target,
                   COALESCE(per_target.estimated_seconds, global_avg.estimated_seconds) AS estimated_seconds
            FROM scope_targets st
            LEFT JOIN (
                SELECT target_id, SUM(avg_phase_seconds) AS estimated_seconds
                FROM (
                    SELECT target_id, phase_name,
                           AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) AS avg_phase_seconds
                    FROM phase_runs
                    WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
                    GROUP BY target_id, phase_name
                ) per_phase
                GROUP BY target_id
            ) per_target ON per_target.target_id = st.id
            CROSS JOIN (
                SELECT SUM(avg_phase_seconds) AS estimated_seconds
                FROM (
                    SELECT phase_name, AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) AS avg_phase_seconds
                    FROM phase_runs
                    WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
                    GROUP BY phase_name
                ) global_per_phase
            ) global_avg
            WHERE st.project_id = $1
            """,
            project_id,
        )
    return [
        {"target_id": r["target_id"], "target": r["target"],
         "estimated_seconds": round(r["estimated_seconds"]) if r["estimated_seconds"] else None}
        for r in rows
    ]


@app.get("/api/targets/{target_id}/screenshot")
async def get_target_screenshot(target_id: int):
    """
    #7: serves the most recent screenshot captured for this target, if
    screenshot capture is enabled and one exists (see screenshots.py).
    404 covers both "capture is disabled" and "capture is enabled but
    hasn't run for this target yet" - the frontend treats both the same
    way (don't show an image), so there's no need to distinguish them
    in the response.
    """
    path = screenshots.screenshot_path(target_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="No screenshot available for this target")
    return FileResponse(path, media_type="image/png")


# ---------- Scope intake (AI-assisted parsing) ----------
#
# This is a two-step flow:
#   1. Parse: operator submits raw text or a file -> Gemini extracts
#      structured targets -> a PREVIEW is returned. Nothing is saved yet.
#   2. Confirm: operator reviews/edits the preview and submits the final
#      list -> THIS is what actually writes to the database, either
#      creating a new project or attaching to an existing one.

@app.post("/api/scope/parse-text", response_model=ScopeParsePreview)
async def parse_scope_from_text(payload: ScopeParseRequest):
    """Parses pasted scope text into a preview. Does not touch the database."""
    try:
        items = await scope_parser.parse_scope_text(payload.platform, payload.raw_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ScopeParsePreview(platform=payload.platform, items=items)


@app.post("/api/scope/parse-file", response_model=ScopeParsePreview)
async def parse_scope_from_file(
    platform: str,
    file: UploadFile = File(...),
):
    """
    Parses an uploaded scope file (plain text or CSV work well; PDFs and
    Excel files are NOT extracted in Phase 1 - the operator should copy
    the relevant text out and use parse-text instead for those formats).
    Does not touch the database.
    """
    valid_platforms = ("bugcrowd", "hackerone", "intigriti", "yeswehack", "openbugbounty", "private")
    if platform not in valid_platforms:
        raise HTTPException(status_code=400, detail=f"platform must be one of {', '.join(valid_platforms)}")

    raw_bytes = await file.read()
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail=(
                "Could not read this file as plain text. Phase 1 supports "
                ".txt and .csv files - for PDF or Excel scope exports, "
                "copy the relevant text and paste it instead."
            ),
        )

    try:
        items = await scope_parser.parse_scope_text(platform, raw_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ScopeParsePreview(platform=platform, items=items)


@app.post("/api/scope/confirm", response_model=Project)
async def confirm_scope(payload: ScopeConfirmRequest):
    """
    Saves the operator-reviewed scope list. If project_id is given, items
    are attached to that existing project. Otherwise, a new project is
    created (project_name is required in that case) and items are
    attached to it. Returns the project either way.
    """
    if not payload.items:
        raise HTTPException(status_code=400, detail="No scope items to save")

    pool = database.get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            if payload.project_id is not None:
                project_row = await conn.fetchrow(
                    "SELECT id, name, platform, status, scan_interval_hours, next_scheduled_scan_at, created_at FROM projects WHERE id = $1",
                    payload.project_id,
                )
                if project_row is None:
                    raise HTTPException(status_code=404, detail="Project not found")
            else:
                if not payload.project_name:
                    raise HTTPException(
                        status_code=400,
                        detail="project_name is required when creating a new project",
                    )
                project_row = await conn.fetchrow(
                    """
                    INSERT INTO projects (name, platform)
                    VALUES ($1, $2)
                    RETURNING id, name, platform, status, scan_interval_hours, next_scheduled_scan_at, created_at
                    """,
                    payload.project_name,
                    payload.platform,
                )

            project_id = project_row["id"]

            for item in payload.items:
                await conn.execute(
                    """
                    INSERT INTO scope_targets
                        (project_id, target, target_type, in_scope, reward_range, notes)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    project_id,
                    item.target,
                    item.target_type,
                    item.in_scope,
                    item.reward_range,
                    item.notes,
                )

    return dict(project_row)


# ---------- Findings (read-only for now - the pipeline will write these) ----------

@app.get("/api/projects/{project_id}/findings", response_model=List[Finding])
async def list_findings(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT f.id, f.project_id, f.target_id, f.tool_name, f.vuln_type, f.severity,
                   f.evidence, f.raw_output_path, f.status,
                   f.likely_program_outcome, f.triage_reasoning, f.triage_confidence,
                   f.occurrence_count,
                   f.created_at,
                   EXISTS (SELECT 1 FROM finding_outcomes fo WHERE fo.finding_id = f.id) AS has_logged_outcome
            FROM findings f
            WHERE f.project_id = $1
            ORDER BY f.created_at DESC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


@app.get("/api/projects/{project_id}/notes", response_model=List[ScanNote])
async def list_scan_notes(project_id: int, include_dismissed: bool = False):
    """
    Detective checks that were deliberately not auto-filed as findings -
    unconfirmed pattern matches needing a manual look (hardcoded
    secrets, excessive data exposure field names, IDOR candidates, ...)
    or confirmed-but-usually-informative-alone gaps (clickjacking,
    missing SRI/HSTS, ...). Separate from GET /findings on purpose - see
    add_scan_notes.sql - so these don't affect severity counts or
    trigger AI triage calls on speculative matches. Previously these
    were computed and immediately discarded to a log line; this is what
    actually surfaces them.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, project_id, target_id, check_name, note, dismissed, created_at
            FROM scan_notes
            WHERE project_id = $1 {"" if include_dismissed else "AND NOT dismissed"}
            ORDER BY created_at DESC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


@app.patch("/api/notes/{note_id}/dismiss")
async def dismiss_scan_note(note_id: int):
    """Marks a scan note reviewed/not useful - hides it from the default
    list without deleting the row (matches findings.status's
    non-destructive pattern)."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("UPDATE scan_notes SET dismissed = true WHERE id = $1", note_id)
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Scan note not found")
    return {"dismissed": True, "id": note_id}
@app.patch("/api/findings/bulk-status", response_model=FindingBulkStatusResult)
async def bulk_update_finding_status(payload: FindingBulkStatusRequest):
    """
    Sets the status field (new/reviewed/submitted/dismissed) on many
    findings at once - the operator's own workflow tracking, separate
    from severity/triage. Lets you select a batch of low-value findings
    (e.g. a run of near-identical info-level results) and mark them
    dismissed in one action instead of opening each one individually.
    Ids that don't exist are silently skipped; the response lists which
    ids were actually updated.
    """
    if not payload.finding_ids:
        raise HTTPException(status_code=400, detail="No finding ids provided")

    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            UPDATE findings
            SET status = $1
            WHERE id = ANY($2::int[])
            RETURNING id
            """,
            payload.status,
            payload.finding_ids,
        )
    updated = [row["id"] for row in rows]
    return {"status": payload.status, "updated": updated}


@app.post("/api/findings/{finding_id}/triage")
async def triage_one_finding(finding_id: int):
    """
    Runs AI triage on a single finding (tiered: cheap model first,
    escalates only if confidence is low) and updates its severity.
    Kept as an explicit, on-demand call rather than automatic during
    scanning, so triage cost/time never slows down the live scan.

    Before scoring, looks up past outcomes for this finding's signature
    (tool + vuln_type) and feeds that history into the prompt - this is
    the actual retrieval step that makes triage "learn" from prior
    accept/reject results over time.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        finding = await conn.fetchrow(
            "SELECT id, tool_name, vuln_type, evidence FROM findings WHERE id = $1", finding_id
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        signature = triage.build_signature(finding["tool_name"], finding["vuln_type"])
        outcome_stats = await _fetch_signature_stats(conn, signature)
        vrt_entries = await vrt.get_vrt_entries()

        result = await triage.triage_finding(
            finding["tool_name"], finding["evidence"] or "",
            outcome_stats=outcome_stats, vrt_entries=vrt_entries,
        )

        outcome = result.get("likely_program_outcome")
        await conn.execute(
            """
            UPDATE findings
            SET severity = $1,
                likely_program_outcome = $2,
                triage_reasoning = $3,
                triage_confidence = $4,
                impact_evidence = $6
            WHERE id = $5
            """,
            result["severity"] if result["severity"] in
            ("critical", "high", "medium", "low", "info") else "unknown",
            outcome if outcome in ("accepted", "informative", "out_of_scope", "duplicate") else None,
            result.get("reasoning"),
            result.get("confidence"),
            finding_id,
            (result.get("impact_evidence") or "").strip() or None,
        )

    return {"finding_id": finding_id, "signature": signature, **result}


@app.get("/api/findings/{finding_id}/report-draft")
async def draft_finding_report(finding_id: int):
    """
    Generates a platform-tailored report draft for an already-triaged
    finding (#11 on the roadmap). Requires the finding to have a real
    severity already (not 'unknown') - report drafting reasons FROM the
    triage judgment, it doesn't replace it, so drafting before triage
    would just be asking the model to guess twice. This is explicitly a
    DRAFT (see report_writer.py) - review before submitting anywhere.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        finding = await conn.fetchrow(
            """
            SELECT f.id, f.tool_name, f.vuln_type, f.severity, f.evidence, f.impact_evidence,
                   f.triage_reasoning, st.target, p.id AS project_id, p.name AS project_name, p.platform
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            JOIN projects p ON p.id = f.project_id
            WHERE f.id = $1
            """,
            finding_id,
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        if finding["severity"] in (None, "unknown"):
            raise HTTPException(
                status_code=400,
                detail="Finding hasn't been triaged yet - run /triage first so there's a real severity to draft a report against.",
            )

        # Batch 24: evidence integrity re-check. A finding's evidence
        # proves the bug was real AT SCAN TIME - time passes before a
        # report actually gets drafted/submitted, and the target may
        # have been patched since. One targeted re-check right before
        # drafting, not a full re-scan - see evidence_lifecycle.py's
        # own docstring for the full reasoning.
        integrity_status = await evidence_lifecycle.check_and_record_evidence_integrity(
            conn, finding_id, finding["evidence"]
        )

        result = await report_writer.draft_report(
            platform=finding["platform"], target=finding["target"], vuln_type=finding["vuln_type"],
            severity=finding["severity"], evidence=finding["evidence"] or "",
            triage_reasoning=finding["triage_reasoning"],
            impact_evidence=finding["impact_evidence"],
        )
        if "error" in result:
            raise HTTPException(status_code=502, detail=f"Report drafting failed: {result['error']}")

    return {
        "finding_id": finding_id, "vuln_type": finding["vuln_type"], "severity": finding["severity"],
        "target": finding["target"], "tool_name": finding["tool_name"], "evidence": finding["evidence"],
        "project_id": finding["project_id"], "project_name": finding["project_name"], "platform": finding["platform"],
        "evidence_integrity": integrity_status,
        **result,
    }


async def _fetch_signature_stats(conn, signature: str) -> dict | None:
    """Shared helper: looks up aggregated outcome history for one signature."""
    row = await conn.fetchrow(
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted,
            COUNT(*) FILTER (WHERE outcome = 'duplicate') AS duplicate,
            COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected,
            COUNT(*) FILTER (WHERE outcome = 'informative') AS informative,
            COUNT(*) FILTER (WHERE outcome = 'not_applicable') AS not_applicable
        FROM finding_outcomes
        WHERE signature = $1
        """,
        signature,
    )
    return dict(row) if row and row["total"] else None


@app.post("/api/projects/{project_id}/triage-all")
async def triage_all_findings(project_id: int):
    """
    Triages every 'unknown'-severity finding in a project. Now also runs
    automatically at the end of every scan (pipeline.py's "triage"
    phase) - this endpoint stays for re-running on demand, e.g. after
    tuning triage.py's prompt or after outcome history has changed.
    Both share the exact same logic via triage.triage_project_findings,
    so they can never drift out of sync.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        triaged = await triage.triage_project_findings(conn, project_id)

    return {"message": f"Triaged {triaged} finding(s)", "count": triaged}


@app.post("/api/projects/{project_id}/gate-all")
async def gate_all_findings(project_id: int):
    """
    Runs the 7-Question Gate on-demand for every finding still pending
    gate review. Also runs automatically as the "gate" phase right
    after scan - this stays for re-running after tuning gate.py's
    prompt. Shares gate.gate_project_findings with the automatic phase.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        gated = await gate.gate_project_findings(conn, project_id)

    return {"message": f"Gated {gated} finding(s)", "count": gated}


@app.post("/api/projects/{project_id}/logic-hunter-all")
async def logic_hunter_all(project_id: int):
    """
    Runs logic_hunter's business-logic/auth-bypass reasoning on-demand
    over every not-yet-hunted high-potential cluster in a project. Also
    runs automatically as the "logic_hunter" phase. Shares
    logic_hunter.hunt_project with the automatic phase.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        hunted = await logic_hunter.hunt_project(conn, project_id)

    return {"message": f"Saved {hunted} hypothesis/hypotheses", "count": hunted}


@app.post("/api/projects/{project_id}/cluster-triage-all")
async def cluster_triage_all(project_id: int):
    """
    Runs cluster-aware triage on-demand over every not-yet-scored high-
    potential cluster in a project (reasons about the COMBINATION of a
    target's findings, not each in isolation - see
    triage.triage_project_clusters). Also runs automatically as the
    second half of the "triage" phase, after individual findings are
    scored.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        scored = await triage.triage_project_clusters(conn, project_id)

    return {"message": f"Scored {scored} cluster(s)", "count": scored}


# ---------- Outcome tracking (the learning loop) ----------

@app.post("/api/outcomes", response_model=OutcomeRecord)
async def log_outcome(payload: OutcomeLogRequest):
    """
    Records a real-world result for a finding (accepted/duplicate/
    rejected/etc. from Bugcrowd or HackerOne). This is the actual
    training signal for the learning loop - logged by the operator after
    a program responds to a submission.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO finding_outcomes (finding_id, signature, outcome, platform, notes)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, finding_id, signature, outcome, platform, notes, recorded_at
            """,
            payload.finding_id,
            payload.signature,
            payload.outcome,
            payload.platform,
            payload.notes,
        )
    return dict(row)


@app.get("/api/outcomes/signature-stats", response_model=List[SignatureStats])
async def get_signature_stats(signature: str = None):
    """
    Returns aggregated outcome history per signature. If a specific
    signature is passed, returns just that one; otherwise returns all
    signatures with at least one logged outcome. This is what future
    triage logic will query before scoring a new finding - "have we
    seen this pattern before, and what happened?"
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        if signature:
            rows = await conn.fetch(
                """
                SELECT
                    signature,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted,
                    COUNT(*) FILTER (WHERE outcome = 'duplicate') AS duplicate,
                    COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected,
                    COUNT(*) FILTER (WHERE outcome = 'informative') AS informative,
                    COUNT(*) FILTER (WHERE outcome = 'not_applicable') AS not_applicable,
                    COUNT(*) FILTER (WHERE outcome = 'no_response') AS no_response
                FROM finding_outcomes
                WHERE signature = $1
                GROUP BY signature
                """,
                signature,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT
                    signature,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted,
                    COUNT(*) FILTER (WHERE outcome = 'duplicate') AS duplicate,
                    COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected,
                    COUNT(*) FILTER (WHERE outcome = 'informative') AS informative,
                    COUNT(*) FILTER (WHERE outcome = 'not_applicable') AS not_applicable,
                    COUNT(*) FILTER (WHERE outcome = 'no_response') AS no_response
                FROM finding_outcomes
                GROUP BY signature
                ORDER BY total DESC
                """
            )
    return [dict(row) for row in rows]


# ---------- Scanning pipeline ----------

@app.post("/api/projects/{project_id}/scan")
async def start_scan(project_id: int, priority: bool = False):
    """
    Adds this project to the scan queue (Batch 4b) rather than kicking
    off scanning immediately - the queue worker loop is now the single
    execution path for both manual and scheduled scans, so a click here
    behaves identically to a scheduled trigger arriving, just in the
    "priority" lane by default request or the normal lane depending on
    the `priority` query param.

    Returns the created queue entry rather than a scan-started message -
    check GET /api/queue for position, or /api/projects/{id}/phase-runs
    once it actually starts running.
    """
    return await _enqueue_project(project_id, priority=priority)


# ---------- Scan queue (Batch 4b) ----------

async def _queue_row_to_item(conn, row) -> dict:
    """Attaches project_name and a rough estimated_start_at to a raw
    scan_queue row - estimated_start_at is (# active items ahead of this
    one in its lane, including a currently-running item) * the average
    duration of the last 5 completed queue items, or None if there's no
    history yet to estimate from."""
    avg_seconds = await conn.fetchval(
        """
        SELECT AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
        FROM (
            SELECT completed_at, started_at FROM scan_queue
            WHERE status = 'completed' AND started_at IS NOT NULL
            ORDER BY completed_at DESC LIMIT 5
        ) recent
        """
    )
    avg_seconds = float(avg_seconds) if avg_seconds is not None else None
    estimated_start_at = None
    if row["status"] == "queued" and avg_seconds:
        ahead = await conn.fetchval(
            """
            SELECT COUNT(*) FROM scan_queue
            WHERE status = 'running'
               OR (status = 'queued' AND priority = $1 AND position < $2)
               OR (status = 'queued' AND priority = true AND $1 = false)
            """,
            row["priority"], row["position"],
        )
        estimated_start_at = datetime.now(timezone.utc).timestamp() + ahead * avg_seconds
        estimated_start_at = datetime.fromtimestamp(estimated_start_at, tz=timezone.utc)

    item = dict(row)
    item["estimated_start_at"] = estimated_start_at
    return item


@app.get("/api/queue", response_model=List[ScanQueueItem])
async def list_queue():
    """Everything still queued or running, in the order the worker will
    (or is) process them: priority lane fully drained first, each lane
    FIFO by position."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT sq.id, sq.project_id, p.name AS project_name, sq.position,
                   sq.priority, sq.status, sq.queued_at, sq.started_at, sq.completed_at
            FROM scan_queue sq JOIN projects p ON p.id = sq.project_id
            WHERE sq.status IN ('queued', 'running')
            ORDER BY sq.status = 'running' DESC, sq.priority DESC, sq.position ASC
            """
        )
        return [await _queue_row_to_item(conn, row) for row in rows]


@app.post("/api/queue", response_model=ScanQueueItem)
async def enqueue(payload: QueueEnqueueRequest):
    """Manual enqueue, separate from POST /scan's convenience shortcut -
    useful for the UI's queue view (e.g. an "add to queue" action that
    doesn't live on the project page itself)."""
    pool = database.get_pool()
    row = await _enqueue_project(payload.project_id, priority=payload.priority)
    async with pool.acquire() as conn:
        full_row = await conn.fetchrow(
            """
            SELECT sq.id, sq.project_id, p.name AS project_name, sq.position,
                   sq.priority, sq.status, sq.queued_at, sq.started_at, sq.completed_at
            FROM scan_queue sq JOIN projects p ON p.id = sq.project_id
            WHERE sq.id = $1
            """,
            row["id"],
        )
        return await _queue_row_to_item(conn, full_row)


@app.patch("/api/queue/{queue_id}/reorder", response_model=ScanQueueItem)
async def reorder_queue_item(queue_id: int, payload: QueueReorderRequest):
    """Drag-to-reorder within a queued item's own lane (priority items
    only reorder among priority items, same for normal). Only 'queued'
    items can move - a 'running' item is, by definition, already first."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        item = await conn.fetchrow("SELECT * FROM scan_queue WHERE id = $1", queue_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Queue entry not found")
        if item["status"] != "queued":
            raise HTTPException(status_code=400, detail="Only queued (not running/completed) entries can be reordered")

        lane_ids = [
            r["id"] for r in await conn.fetch(
                "SELECT id FROM scan_queue WHERE status = 'queued' AND priority = $1 ORDER BY position ASC",
                item["priority"],
            )
        ]
        lane_ids.remove(queue_id)
        new_index = max(0, min(payload.new_position - 1, len(lane_ids)))
        lane_ids.insert(new_index, queue_id)

        for i, row_id in enumerate(lane_ids, start=1):
            await conn.execute("UPDATE scan_queue SET position = $1 WHERE id = $2", i, row_id)

        full_row = await conn.fetchrow(
            """
            SELECT sq.id, sq.project_id, p.name AS project_name, sq.position,
                   sq.priority, sq.status, sq.queued_at, sq.started_at, sq.completed_at
            FROM scan_queue sq JOIN projects p ON p.id = sq.project_id
            WHERE sq.id = $1
            """,
            queue_id,
        )
        return await _queue_row_to_item(conn, full_row)


@app.delete("/api/queue/{queue_id}")
async def cancel_queue_item(queue_id: int):
    """Cancels a queued (not yet running) item. A running item can't be
    cancelled through this endpoint - there's no scan-abort mechanism
    yet, so 'cancel' would be a lie for anything already in flight."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        item = await conn.fetchrow("SELECT status FROM scan_queue WHERE id = $1", queue_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Queue entry not found")
        if item["status"] != "queued":
            raise HTTPException(status_code=400, detail="Only queued (not yet running) entries can be cancelled")
        await conn.execute(
            "UPDATE scan_queue SET status = 'cancelled', completed_at = now() WHERE id = $1",
            queue_id,
        )
    return {"message": "Cancelled", "id": queue_id}


@app.put("/api/projects/{project_id}/schedule", response_model=Project)
async def set_project_schedule(project_id: int, payload: ScheduleUpdateRequest):
    """
    Sets or clears a recurring scan schedule for this project, and/or a
    one-time run_at (Batch 6 - see ScheduleUpdateRequest's docstring for
    how the two combine). interval_hours=None with run_at=None disables
    scheduling entirely and goes back to manual-only scanning.
    """
    if payload.interval_hours is not None and payload.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be at least 1")
    if payload.run_at is not None and payload.run_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="run_at must be in the future")

    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        if payload.interval_hours is None and payload.run_at is None:
            await conn.execute(
                """
                UPDATE projects
                SET scan_interval_hours = NULL, next_scheduled_scan_at = NULL
                WHERE id = $1
                """,
                project_id,
            )
        elif payload.run_at is not None:
            # One-time run_at wins as the next trigger time regardless of
            # whether a recurring interval is also set/being set - it's
            # the FIRST run either way. scan_interval_hours still gets
            # saved (or cleared) so recurrence after that first run
            # behaves however the caller asked for.
            await conn.execute(
                """
                UPDATE projects
                SET scan_interval_hours = $2, next_scheduled_scan_at = $3
                WHERE id = $1
                """,
                project_id, payload.interval_hours, payload.run_at,
            )
        else:
            await conn.execute(
                """
                UPDATE projects
                SET scan_interval_hours = $2,
                    next_scheduled_scan_at = now() + make_interval(hours => $2)
                WHERE id = $1
                """,
                project_id,
                payload.interval_hours,
            )

        row = await conn.fetchrow(
            """
            SELECT id, name, platform, status, scan_interval_hours, next_scheduled_scan_at, created_at
            FROM projects WHERE id = $1
            """,
            project_id,
        )
    return dict(row)


@app.get("/api/projects/{project_id}/phase-runs", response_model=List[PhaseRun])
async def list_phase_runs(project_id: int):
    """
    Shows the live status of every phase, for every target, in this
    project - this is what a 'live logs' view in the frontend polls.
    Status will be one of: pending, in_progress, completed, failed,
    needs_attention.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, project_id, target_id, phase_name, status,
                   started_at, completed_at, error_message, retry_count, created_at
            FROM phase_runs
            WHERE project_id = $1
            ORDER BY created_at DESC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


@app.get("/api/projects/{project_id}/scan-runs", response_model=List[ScanRun])
async def list_scan_runs(project_id: int):
    """
    Full scan-run history for this project - one row per time a scan was
    kicked off (manual, scheduled, or recurring). This is what the "scan
    history" list in the project view shows; phase-runs above is the
    live per-phase detail, this is the higher-level timeline.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, project_id, started_at FROM scan_runs WHERE project_id = $1 ORDER BY started_at DESC",
            project_id,
        )
    return [dict(row) for row in rows]

@app.get("/api/findings/{finding_id}/readiness", response_model=ReadinessResponse)
async def get_finding_readiness(finding_id: int):
    """
    Runs the submission readiness checklist against a finding - catches
    common, avoidable rejection reasons (untriaged severity, thin
    evidence, stale scope, info-level findings rarely worth submitting)
    before the operator spends time writing up a report.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        finding = await conn.fetchrow(
            "SELECT id, severity, evidence, status, target_id FROM findings WHERE id = $1",
            finding_id,
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        target = await conn.fetchrow(
            "SELECT in_scope FROM scope_targets WHERE id = $1", finding["target_id"]
        )
        target_in_scope = bool(target["in_scope"]) if target else False

    result = readiness.check_finding_readiness(dict(finding), target_in_scope)
    return {
        "finding_id": finding_id,
        "ready": result.ready,
        "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in result.checks],
    }


# ---------- Run-to-run diff ----------

@app.get("/api/projects/{project_id}/outcome-trend")
async def get_outcome_trend(project_id: int, weeks: int = 12):
    """
    #2: weekly accept-rate trend for this project, so you can see
    whether a program's actually-accepted rate is drifting up or down
    over time, not just today's snapshot. Only counts outcomes tied to
    a finding still linked to THIS project (finding_outcomes.finding_id
    can be NULL after a finding is deleted - those rows are excluded
    here since we can't attribute them to a project anymore, though
    they're still used project-agnostically elsewhere, e.g. triage's
    signature stats).
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('week', fo.recorded_at) AS week,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE fo.outcome = 'accepted') AS accepted
            FROM finding_outcomes fo
            JOIN findings f ON f.id = fo.finding_id
            WHERE f.project_id = $1 AND fo.recorded_at >= now() - ($2 * interval '1 week')
            GROUP BY week
            ORDER BY week ASC
            """,
            project_id, weeks,
        )
    return [
        {"week": r["week"], "total": r["total"], "accepted": r["accepted"],
         "accept_rate": round(r["accepted"] / r["total"], 3) if r["total"] else None}
        for r in rows
    ]


@app.get("/api/projects/{project_id}/diff", response_model=DiffResponse)
async def diff_latest_scans(project_id: int):
    """
    Compares the two most recent scans for this project: what's newly
    showing up, and what's no longer showing up (fixed, taken down, or
    just not detected this time - the tool can't tell you which, but it
    can tell you it's worth a second look either way).

    Identity for matching is (target_id, tool_name, vuln_type) - NOT the
    full row, since evidence text can shift slightly between runs (a
    cert expiry date, a response timestamp) without it being a genuinely
    different finding.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project_exists = await conn.fetchval("SELECT 1 FROM projects WHERE id = $1", project_id)
        if not project_exists:
            raise HTTPException(status_code=404, detail="Project not found")

        runs = await conn.fetch(
            "SELECT id, project_id, started_at FROM scan_runs WHERE project_id = $1 ORDER BY started_at DESC LIMIT 2",
            project_id,
        )
        if len(runs) < 2:
            raise HTTPException(
                status_code=400,
                detail="Need at least 2 scans on this project to diff - run a scan again once you have a baseline.",
            )

        latest_run, baseline_run = runs[0], runs[1]

        latest_findings = await conn.fetch(
            """
            SELECT id, target_id, tool_name, vuln_type, severity, evidence
            FROM findings
            WHERE project_id = $1 AND created_at >= $2
            """,
            project_id, latest_run["started_at"],
        )
        baseline_findings = await conn.fetch(
            """
            SELECT id, target_id, tool_name, vuln_type, severity, evidence
            FROM findings
            WHERE project_id = $1 AND created_at >= $2 AND created_at < $3
            """,
            project_id, baseline_run["started_at"], latest_run["started_at"],
        )

    def identity(row):
        return (row["target_id"], row["tool_name"], row["vuln_type"])

    baseline_by_identity = {identity(r): r for r in baseline_findings}
    latest_by_identity = {identity(r): r for r in latest_findings}

    new_findings = [dict(r) for k, r in latest_by_identity.items() if k not in baseline_by_identity]
    resolved_findings = [dict(r) for k, r in baseline_by_identity.items() if k not in latest_by_identity]
    unchanged_count = len(set(baseline_by_identity) & set(latest_by_identity))

    return {
        "project_id": project_id,
        "baseline_run": dict(baseline_run),
        "latest_run": dict(latest_run),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_count": unchanged_count,
    }


# ---------- CSV export ----------

_VALID_EXPORT_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def _parse_severities_param(severities: Optional[str]) -> Optional[list[str]]:
    """Parses a comma-separated severities query param, e.g.
    'critical,high'. Returns None (meaning "no filter, everything") if
    the param wasn't given at all - unfiltered stays the default so
    old links/bookmarks to the export URL keep working. Unknown values
    are dropped rather than raising, so a typo just narrows the filter
    instead of 500ing the export."""
    if severities is None:
        return None
    requested = {s.strip().lower() for s in severities.split(",") if s.strip()}
    valid = [s for s in requested if s in _VALID_EXPORT_SEVERITIES]
    return valid or None


def _parse_csv_param(value: Optional[str]) -> Optional[list[str]]:
    """Same shape as _parse_severities_param but for tool_name/vuln_type,
    which aren't a fixed enum - no allowlist to check against, so
    anything given through is passed to the query as-is (parameterized,
    not interpolated, so this is not an injection risk)."""
    if value is None:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


@app.get("/api/projects/{project_id}/findings/export")
async def export_findings_csv(
    project_id: int,
    severities: Optional[str] = None,
    tools: Optional[str] = None,
    vuln_types: Optional[str] = None,
):
    """
    Exports findings for this project as CSV - meant for pasting into a
    submission draft or archiving outside the tool, not as a
    replacement for the readiness checklist.

    All three filters are optional and comma-separated
    (e.g. severities="critical,high", tools="nuclei,sqlmap"). Omit any
    of them to not filter on that dimension - omitting all three
    exports everything, same as before these params existed.
    """
    sev_filter = _parse_severities_param(severities)
    tool_filter = _parse_csv_param(tools)
    vuln_filter = _parse_csv_param(vuln_types)
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT name FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        rows = await conn.fetch(
            """
            SELECT f.id, st.target, f.tool_name, f.vuln_type, f.severity, f.status, f.evidence, f.created_at
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            WHERE f.project_id = $1
              AND ($2::text[] IS NULL OR f.severity = ANY($2::text[]))
              AND ($3::text[] IS NULL OR f.tool_name = ANY($3::text[]))
              AND ($4::text[] IS NULL OR f.vuln_type = ANY($4::text[]))
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
                END,
                f.created_at DESC
            """,
            project_id, sev_filter, tool_filter, vuln_filter,
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "target", "tool", "vuln_type", "severity", "status", "evidence", "created_at"])
    for row in rows:
        writer.writerow([
            row["id"], row["target"], row["tool_name"], row["vuln_type"],
            _SEVERITY_DISPLAY.get(row["severity"], row["severity"]),
            row["status"], (row["evidence"] or "").replace("\n", " "), row["created_at"],
        ])
    buffer.seek(0)

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])
    filename = f"swas_findings_{safe_name}_{project_id}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- Markdown report ----------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

# "unknown" severity means the finding hasn't been triaged into a real
# severity yet (raw tool output, e.g. sqlmap) - not a severity level a
# reviewer should read past without noticing, hence the loud label
# instead of just "Unknown" in both CSV and the report.
_SEVERITY_DISPLAY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "NOTES FOR MANUAL REVIEW",
}


_IMPACT_TEMPLATES = {
    "critical": "If exploited, this could allow an attacker to fully compromise the affected system, "
                "access or modify sensitive data at scale, or take actions with the highest level of "
                "privilege available in this application.",
    "high": "If exploited, this could allow an attacker to access or modify sensitive data, escalate "
            "privileges, or otherwise significantly impact the confidentiality, integrity, or "
            "availability of the affected system.",
    "medium": "If exploited, this could allow an attacker to access limited sensitive data or "
              "otherwise negatively impact users of the affected system, typically requiring specific "
              "conditions or user interaction.",
    "low": "The direct impact is limited, but this weakens the overall security posture of the "
           "affected system and may be combined with other issues for greater effect.",
    "info": "No direct security impact on its own, but worth documenting as a hardening opportunity "
            "or as supporting evidence for a related finding.",
}

# Coarse, substring-matched starting points - not exhaustive, just enough
# that the operator is editing a real first draft instead of a blank
# textarea. vuln_type strings vary by detector, so this matches loosely.
_REMEDIATION_HINTS = [
    (("sql injection", "sqli"), "Use parameterized queries / prepared statements for all database "
                                  "access; never build SQL via string concatenation with user input."),
    (("xss", "cross-site scripting"), "Encode output for the destination context (HTML, attribute, "
                                        "JS, URL) and apply a restrictive Content-Security-Policy."),
    (("ssrf",), "Validate and allowlist outbound destinations server-side; block requests to "
                 "internal/link-local address ranges and cloud metadata endpoints."),
    (("idor", "broken access control", "authorization"), "Enforce object-level authorization checks "
                                                            "server-side on every request, not just in the UI."),
    (("xxe", "xml external entity"), "Disable external entity resolution and DTD processing in the "
                                       "XML parser."),
    (("open redirect",), "Validate redirect targets against an allowlist rather than trusting a "
                          "user-supplied URL parameter."),
    (("cache poisoning",), "Ensure cache keys account for every header/parameter that changes the "
                             "response, and strip or normalize unkeyed inputs before they reach the origin."),
    (("subdomain takeover",), "Remove the dangling DNS record, or reclaim the resource at the "
                                "third-party provider before an attacker can."),
    (("exposed", "disclosure", "misconfiguration"), "Restrict access to this resource (authentication, "
                                                       "network ACL, or removal from the public-facing "
                                                       "deployment) and rotate any credentials it exposed."),
]


def _guess_remediation(vuln_type: str) -> str:
    lowered = vuln_type.lower()
    for keywords, hint in _REMEDIATION_HINTS:
        if any(k in lowered for k in keywords):
            return hint
    return "Describe the specific fix once confirmed - generally: validate/sanitize the relevant " \
           "input server-side and apply the principle of least privilege to the affected component."


@app.get("/api/findings/{finding_id}/report-draft", response_model=ReportDraft)
async def get_report_draft(finding_id: int):
    """
    A structured starting draft for ONE finding, for the Report Builder.
    Deliberately per-finding rather than per-project - most programs
    want one report per vulnerability, not a bundled dump (that's what
    GET /projects/{id}/report.md is for, as an overview/backup).
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT f.id, f.severity, f.tool_name, f.vuln_type, f.evidence, f.triage_reasoning,
                   f.project_id, st.target,
                   p.name AS project_name, p.platform AS project_platform
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            JOIN projects p ON p.id = f.project_id
            WHERE f.id = $1
            """,
            finding_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    sev = row["severity"] if row["severity"] in _SEVERITY_ORDER else "unknown"
    title = f"{row['vuln_type']} on {row['target']}"
    summary = (
        row["triage_reasoning"].strip()
        if row["triage_reasoning"]
        else f"A {sev} severity {row['vuln_type']} issue was identified on {row['target']}, "
             f"detected via {row['tool_name']}."
    )
    steps = (
        f"1. Navigate to / send a request to: {row['target']}\n"
        f"2. (describe the exact request/action that triggers the issue)\n"
        f"3. Observe: (describe the vulnerable behavior)\n"
        f"\nSee evidence below for the raw output that supports this."
    )
    impact = _IMPACT_TEMPLATES.get(sev, _IMPACT_TEMPLATES["info"])
    remediation = _guess_remediation(row["vuln_type"])

    return {
        "finding_id": row["id"],
        "title": title,
        "severity": sev,
        "vuln_type": row["vuln_type"],
        "tool_name": row["tool_name"],
        "target": row["target"],
        "project_id": row["project_id"],
        "project_name": row["project_name"],
        "platform": row["project_platform"],
        "summary": summary,
        "steps_to_reproduce": steps,
        "impact": impact,
        "remediation": remediation,
        "evidence": row["evidence"],
    }


@app.get("/api/projects/{project_id}/report.md")
async def generate_markdown_report(
    project_id: int,
    severities: Optional[str] = None,
    tools: Optional[str] = None,
    vuln_types: Optional[str] = None,
):
    """
    A submission-ready Markdown report: scope table, then findings
    grouped by severity with evidence in code blocks. Markdown rather
    than PDF deliberately - most Bugcrowd/HackerOne submission forms and
    note fields render Markdown directly, and it avoids adding a PDF-
    rendering dependency (weasyprint/wkhtmltopdf) to the Docker image
    just for this. Paste-and-go for a report body, or open in any editor.

    All three filters are optional and comma-separated
    (severities="critical,high", tools="nuclei,sqlmap",
    vuln_types="sqli,xss"). Omit any of them to skip filtering on that
    dimension - omitting all three exports everything, same as before
    these params existed.
    """
    sev_filter = _parse_severities_param(severities)
    tool_filter = _parse_csv_param(tools)
    vuln_filter = _parse_csv_param(vuln_types)
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow(
            "SELECT name, platform, created_at FROM projects WHERE id = $1", project_id
        )
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        scope_rows = await conn.fetch(
            """
            SELECT target, target_type, in_scope
            FROM scope_targets WHERE project_id = $1
            ORDER BY created_at ASC
            """,
            project_id,
        )
        finding_rows = await conn.fetch(
            """
            SELECT f.severity, f.tool_name, f.vuln_type, f.evidence, f.status, st.target
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            WHERE f.project_id = $1
              AND ($2::text[] IS NULL OR f.severity = ANY($2::text[]))
              AND ($3::text[] IS NULL OR f.tool_name = ANY($3::text[]))
              AND ($4::text[] IS NULL OR f.vuln_type = ANY($4::text[]))
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
                END,
                f.created_at DESC
            """,
            project_id, sev_filter, tool_filter, vuln_filter,
        )

    lines: list[str] = []
    lines.append(f"# {project['name']} - Security Assessment Report")
    lines.append("")
    lines.append(f"**Platform:** {project['platform'].title()}  ")
    lines.append(f"**Report generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Project created:** {project['created_at'].strftime('%Y-%m-%d')}")
    lines.append("")

    lines.append("## Scope")
    lines.append("")
    if not scope_rows:
        lines.append("_No scope targets recorded._")
    else:
        lines.append("| Target | Type | In Scope |")
        lines.append("|---|---|---|")
        for s in scope_rows:
            lines.append(f"| {s['target']} | {s['target_type']} | {'Yes' if s['in_scope'] else 'No'} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not finding_rows:
        lines.append("_No findings recorded for this project._")
    else:
        by_severity: dict[str, list] = {}
        for f in finding_rows:
            sev = f["severity"] if f["severity"] in _SEVERITY_ORDER else "unknown"
            by_severity.setdefault(sev, []).append(f)

        for sev in _SEVERITY_ORDER:
            rows_for_sev = by_severity.get(sev)
            if not rows_for_sev:
                continue
            lines.append(f"### {_SEVERITY_DISPLAY.get(sev, sev.title())} ({len(rows_for_sev)})")
            lines.append("")
            for f in rows_for_sev:
                lines.append(f"- **{f['target']}** — `{f['tool_name']}` / {f['vuln_type']} _{f['status']}_")
                if f["evidence"]:
                    # Indent so it renders as a nested code block under
                    # the bullet, rather than breaking out to top level.
                    evidence_indented = f["evidence"].strip().replace("\n", "\n  ")
                    lines.append(f"  ```\n  {evidence_indented}\n  ```")
            lines.append("")

    content = "\n".join(lines)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])
    filename = f"swas_report_{safe_name}_{project_id}.md"
    return StreamingResponse(
        iter([content]),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- Cross-project findings dashboard ----------

@app.get("/api/findings", response_model=List[FindingWithProject])
async def list_all_findings(
    severity: Optional[str] = None,
    tool_name: Optional[str] = None,
    q: Optional[str] = None,
    likely_program_outcome: Optional[str] = None,
    status: Optional[str] = None,
    sort: str = "recent",
    limit: int = 500,
):
    """
    Findings across EVERY project, for the cross-project dashboard and
    the triage queue - the per-project view (GET /api/projects/{id}/findings)
    stays as-is for the project detail page. Filters are all optional
    and combine with AND. `q` does a simple substring search over
    evidence and vuln_type.

    status: comma-separated list (e.g. "new,reviewed") - lets the triage
    queue pull everything actionable in one call instead of one request
    per status.

    sort: "recent" (default, newest first), "confidence" (lowest
    triage_confidence first - the ones the AI was least sure about,
    which is where operator attention matters most), or "severity"
    (critical first).

    likely_program_outcome (Batch 5): filter by triage's predicted
    program outcome - e.g. ?likely_program_outcome=out_of_scope to see
    (and skip) everything triage already flagged as a policy-exclusion
    risk, or =accepted to focus on the findings most worth writing up.
    """
    pool = database.get_pool()
    conditions = []
    params: list = []

    if severity:
        params.append(severity)
        conditions.append(f"f.severity = ${len(params)}")
    if tool_name:
        params.append(tool_name)
        conditions.append(f"f.tool_name = ${len(params)}")
    if q:
        params.append(f"%{q}%")
        conditions.append(f"(f.evidence ILIKE ${len(params)} OR f.vuln_type ILIKE ${len(params)})")
    if likely_program_outcome:
        params.append(likely_program_outcome)
        conditions.append(f"f.likely_program_outcome = ${len(params)}")
    if status:
        status_list = [s.strip() for s in status.split(",") if s.strip()]
        params.append(status_list)
        conditions.append(f"f.status = ANY(${len(params)}::text[])")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    order_clause = {
        "confidence": "f.triage_confidence ASC NULLS FIRST, f.created_at DESC",
        "severity": """
            CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
            END, f.created_at DESC
        """,
        "recent": "f.created_at DESC",
    }.get(sort, "f.created_at DESC")

    params.append(min(limit, 2000))  # hard ceiling regardless of what's requested

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT f.id, f.project_id, f.target_id, f.tool_name, f.vuln_type, f.severity,
                   f.evidence, f.raw_output_path, f.status,
                   f.likely_program_outcome, f.triage_reasoning, f.triage_confidence,
                   f.created_at,
                   p.name AS project_name, p.platform AS project_platform,
                   EXISTS (SELECT 1 FROM finding_outcomes fo WHERE fo.finding_id = f.id) AS has_logged_outcome
            FROM findings f
            JOIN projects p ON p.id = f.project_id
            {where_clause}
            ORDER BY {order_clause}
            LIMIT ${len(params)}
            """,
            *params,
        )
    return [dict(row) for row in rows]


# ---------- Live scan progress (WebSocket) ----------

@app.websocket("/ws/projects/{project_id}")
async def project_progress_socket(websocket: WebSocket, project_id: int):
    """
    Pushes phase status changes for this project the instant checkpoint.py
    records them, instead of making the frontend wait for its next poll.
    This is purely additive - ProjectDetail.jsx keeps its 5s polling as a
    fallback, so a dropped or never-established connection here just
    means slightly-delayed updates, never lost ones.
    """
    await ws_manager.manager.connect(project_id, websocket)
    try:
        while True:
            # We don't expect the frontend to send anything meaningful -
            # this just blocks until the client disconnects, which is
            # what actually triggers cleanup below.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.manager.disconnect(project_id, websocket)
