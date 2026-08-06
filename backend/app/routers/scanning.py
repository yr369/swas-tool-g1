"""
routers/scanning.py - triggering a scan, the scan queue (list/
enqueue/reorder/cancel), scheduling, phase-run/scan-run history,
finding readiness, and run-to-run diff. Split out of the former
monolithic main.py.
"""

import asyncio
import csv
import io
import logging
import shutil
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse

from .. import auth_policy, auth_sessions, checkpoint, config, database, evidence_lifecycle, gate, gemini_rotation, logic_hunter, oob, pipeline, readiness, report_writer, retry_queue, scope_parser, screenshots, target_intelligence, tools, triage, vrt, ws_manager
from ..models import (
    Project,
    ProjectCreate,
    ProjectUpdate,
    AuthPolicy,
    AuthSessionMeta,
    AuthPolicyUpdateRequest,
    AuthSessionUpsertRequest,
    AuthSessionTestResult,
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
from ..scan_orchestration import _enqueue_project, _trigger_scan_for_project

logger = logging.getLogger("swas.main")

router = APIRouter()


# ---------- Scanning pipeline ----------

@router.post("/api/projects/{project_id}/scan")
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


@router.get("/api/queue", response_model=List[ScanQueueItem])
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


@router.post("/api/queue", response_model=ScanQueueItem)
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


@router.patch("/api/queue/{queue_id}/reorder", response_model=ScanQueueItem)
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


@router.delete("/api/queue/{queue_id}")
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


@router.put("/api/projects/{project_id}/schedule", response_model=Project)
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


@router.get("/api/projects/{project_id}/phase-runs", response_model=List[PhaseRun])
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


@router.get("/api/projects/{project_id}/scan-runs", response_model=List[ScanRun])
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

@router.get("/api/findings/{finding_id}/readiness", response_model=ReadinessResponse)
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

@router.get("/api/projects/{project_id}/outcome-trend")
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


@router.get("/api/projects/{project_id}/diff", response_model=DiffResponse)
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


