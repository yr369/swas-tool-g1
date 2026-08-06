"""
routers/scope.py - scope target CRUD/bulk-add/rescan and the
AI-assisted scope-intake (parse-text/parse-file/confirm) endpoints.
Split out of the former monolithic main.py.
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
from ..scan_orchestration import _run_target_pipeline_limited, _spawn_background_task

logger = logging.getLogger("swas.main")

router = APIRouter()


# ---------- Scope targets ----------

@router.post("/api/projects/{project_id}/scope", response_model=ScopeTarget)
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


@router.get("/api/projects/{project_id}/scope", response_model=List[ScopeTarget])
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


@router.patch("/api/projects/{project_id}/scope/{target_id}", response_model=ScopeTarget)
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

@router.post("/api/projects/{project_id}/scope/{target_id}/rescan")
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


@router.delete("/api/projects/{project_id}/scope/{target_id}")
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


@router.post("/api/projects/{project_id}/scope/bulk", response_model=BulkScopeTargetsResult)
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


@router.get("/api/projects/{project_id}/scope/overlaps")
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


@router.get("/api/projects/{project_id}/scope/duration-estimates")
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


@router.get("/api/targets/{target_id}/screenshot")
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

@router.post("/api/scope/parse-text", response_model=ScopeParsePreview)
async def parse_scope_from_text(payload: ScopeParseRequest):
    """Parses pasted scope text into a preview. Does not touch the database."""
    try:
        items = await scope_parser.parse_scope_text(payload.platform, payload.raw_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ScopeParsePreview(platform=payload.platform, items=items)


@router.post("/api/scope/parse-file", response_model=ScopeParsePreview)
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


@router.post("/api/scope/confirm", response_model=Project)
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


