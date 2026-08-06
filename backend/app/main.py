"""
main.py - the FastAPI application entry point.

This is what actually runs when the backend container starts. It:
  1. Connects to Postgres on startup, disconnects cleanly on shutdown
     (this matters for the "crash-safe" requirement - the pool is the one
     thing that must exist before anything else touches the database)
  2. On startup, checks for any scans that were interrupted by a crash
     or restart, and flags them rather than silently ignoring them
  3. Starts the background loops (scheduler, scan-queue worker, daily
     digest, stale-project flagging, AI retry queue) defined in
     scan_orchestration.py
  4. Wires up every route via routers/ - each file there is one
     APIRouter covering one area (projects, scope, findings, scanning,
     reports, health, live/websocket)

Batch: main.py split. This file was 2,972 lines - every route handler
for every area of the app in one file. The routes themselves now live
in routers/*.py as APIRouters (same content, @app.X decorators became
@router.X), the background-task machinery lives in
scan_orchestration.py, and this file is left with just what actually
has to happen at the app level: startup/shutdown, CORS, and wiring
routers together. Nothing here changes route paths, request/response
shapes, or behavior - this is a pure reorganization, verified by a
real runtime import (`import app.main`) plus a route-count check
against the pre-split file before delivery.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import checkpoint, config, database
from .scan_orchestration import (
    _ai_retry_queue_worker_loop, _digest_loop, _queue_worker_loop,
    _scheduler_loop, _stale_flag_loop,
)
from .routers import findings, health, live, projects, reports, scanning, scope

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("swas.main")


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




# Every route lives in routers/ now - see that package for what each
# file covers. Prefixes are already baked into each router's own
# @router.<method>("/api/...") paths (unchanged from when they were
# @app.<method>(...) in this file), so no prefix= is passed here.
app.include_router(health.router)
app.include_router(projects.router)
app.include_router(scope.router)
app.include_router(findings.router)
app.include_router(scanning.router)
app.include_router(reports.router)
app.include_router(live.router)
