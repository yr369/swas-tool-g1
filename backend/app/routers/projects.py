"""
routers/projects.py - project CRUD, bulk-action, delete, and the
per-project authenticated-testing (auth-policy/auth-sessions)
endpoints, since those are project-scoped. Split out of the former
monolithic main.py.
"""

import asyncio
import csv
import io
import json
import logging
import shutil
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse

from .. import auth_policy, auth_sessions, checkpoint, config, database, evidence_lifecycle, gate, gemini_rotation, logic_hunter, oob, pipeline, policy_gate, readiness, report_writer, retry_queue, scope_parser, screenshots, target_intelligence, tools, triage, vrt, ws_manager
from ..models import (
    Project,
    ProjectCreate,
    ProjectUpdate,
    AuthPolicy,
    AuthSessionMeta,
    AuthPolicyUpdateRequest,
    AuthSessionUpsertRequest,
    AuthSessionTestResult,
    ProjectPolicyUpdateRequest,
    ProjectPolicy,
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

logger = logging.getLogger("swas.main")

router = APIRouter()


# ---------- Projects ----------

@router.post("/api/projects", response_model=Project)
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


@router.get("/api/projects", response_model=List[Project])
async def list_projects():
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count, p.agent_loop_max_steps,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count,
                   (SELECT COUNT(*) FROM findings WHERE project_id = p.id AND severity != 'info') AS open_findings_count,
                   (SELECT COUNT(*) FROM projects p2 WHERE p2.id <= p.id) AS current_number
            FROM projects p
            ORDER BY p.created_at DESC
            """
        )
    return [dict(row) for row in rows]


@router.get("/api/projects/chronology")
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


@router.get("/api/projects/{project_id}", response_model=Project)
async def get_project(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count, p.agent_loop_max_steps,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count,
                   (SELECT COUNT(*) FROM findings WHERE project_id = p.id AND severity != 'info') AS open_findings_count,
                   (SELECT COUNT(*) FROM projects p2 WHERE p2.id <= p.id) AS current_number
            FROM projects p WHERE p.id = $1
            """,
            project_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


@router.patch("/api/projects/{project_id}", response_model=Project)
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
            payload.agent_loop_max_steps,
        )
    ):
        raise HTTPException(status_code=400, detail="Provide at least one field to update")
    if payload.name is not None and not payload.name.strip():
        raise HTTPException(status_code=400, detail="name can't be empty")
    if payload.agent_loop_max_steps is not None and not (0 <= payload.agent_loop_max_steps <= 25):
        raise HTTPException(status_code=400, detail="agent_loop_max_steps must be 0 (clear override) or 1-25")

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

        # Same clear-sentinel pattern for agent_loop_max_steps, using 0
        # instead of "" since this field is an int (see ProjectUpdate).
        agent_loop_max_steps_value = (
            None if payload.agent_loop_max_steps == 0 else payload.agent_loop_max_steps
        )
        clear_max_steps_override = payload.agent_loop_max_steps == 0

        await conn.execute(
            """
            UPDATE projects
            SET name = COALESCE($2, name),
                platform = COALESCE($3, platform),
                preferred_ai_model = CASE WHEN $6 THEN NULL ELSE COALESCE($4, preferred_ai_model) END,
                is_canary = COALESCE($5, is_canary),
                canary_baseline_finding_count = COALESCE($7, canary_baseline_finding_count),
                agent_loop_max_steps = CASE WHEN $9 THEN NULL ELSE COALESCE($8, agent_loop_max_steps) END
            WHERE id = $1
            """,
            project_id, payload.name, payload.platform, preferred_ai_model_value,
            payload.is_canary, clear_model_override, payload.canary_baseline_finding_count,
            agent_loop_max_steps_value, clear_max_steps_override,
        )
        row = await conn.fetchrow(
            """
            SELECT p.id, p.name, p.platform, p.status, p.scan_interval_hours,
                   p.next_scheduled_scan_at, p.created_at,
                   p.preferred_ai_model, p.is_canary, p.canary_baseline_finding_count, p.agent_loop_max_steps,
                   (SELECT MAX(started_at) FROM scan_runs WHERE project_id = p.id) AS last_scan_at,
                   (SELECT COUNT(*) FROM scan_runs WHERE project_id = p.id) AS scan_count,
                   (SELECT COUNT(*) FROM findings WHERE project_id = p.id AND severity != 'info') AS open_findings_count,
                   (SELECT COUNT(*) FROM projects p2 WHERE p2.id <= p.id) AS current_number
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

@router.get("/api/projects/{project_id}/auth-policy", response_model=AuthPolicy)
async def get_auth_policy(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        return await auth_policy.get_policy(conn, project_id)


@router.get("/api/projects/{project_id}/auth-sessions", response_model=List[AuthSessionMeta])
async def list_auth_sessions(project_id: int):
    """Metadata only - matches auth_sessions.list_sessions exactly, never a credential value."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        return await auth_sessions.list_sessions(conn, project_id)


# --- Write paths for auth policy / sessions (project-card UI) ---
#
# Originally this was deliberately CLI-only (see auth_cli.py's docstring):
# the reasoning was that an HTTP endpoint managing live bug-bounty
# credentials is new attack surface on a box with "no login layer in
# front of the API". That premise no longer holds - docker/caddy/Caddyfile
# gates the entire site (UI + /api/* + /ws/*) behind basic_auth, so this
# endpoint sits behind exactly the same auth boundary as every other
# project-management route already in this file. Given that, requiring
# SSH+CLI just to swap a dead credential mid-hunt was pure friction with
# no remaining security benefit, so the write path moved here instead.
#
# What's still enforced, unchanged from the CLI path:
#   - auth_policy.require_approved() still gates every session write/read
#     (via auth_sessions.store_session/get_session, called as-is).
#   - Credential values still only ever pass through auth_sessions.py's
#     pgcrypto encrypt/decrypt - this file never sees a value at rest, and
#     never logs one.
#   - A decrypted credential_value returned by test_auth_session's one
#     GET request is discarded the moment that function returns - it's
#     used to build headers for exactly one outbound call and nothing
#     else references it.

@router.put("/api/projects/{project_id}/auth-policy", response_model=AuthPolicy)
async def update_auth_policy(project_id: int, payload: AuthPolicyUpdateRequest):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        proj = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        await auth_policy.set_policy(conn, project_id, payload.status, payload.policy_note, payload.set_by)
        return await auth_policy.get_policy(conn, project_id)


@router.post("/api/projects/{project_id}/auth-sessions", response_model=AuthSessionMeta)
async def upsert_auth_session(project_id: int, payload: AuthSessionUpsertRequest):
    """
    Add a new session or overwrite an existing one by session_name - the
    same upsert store_session() already did for the CLI path, which is
    exactly what "swap a dead credential mid-hunt" needs: re-add with the
    same session_name and the new value replaces the old one in place,
    nothing else (finding references, agent_loop history) has to change
    since they only ever hold the session NAME, never the value.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        proj = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        try:
            await auth_sessions.store_session(
                conn,
                project_id,
                payload.session_name,
                payload.credential_value,
                session_type=payload.session_type,
                header_name=payload.header_name,
                notes=payload.notes,
            )
        except auth_policy.AuthPolicyError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        rows = await auth_sessions.list_sessions(conn, project_id)
        match = next((r for r in rows if r["session_name"] == payload.session_name), None)
        if match is None:
            raise HTTPException(status_code=500, detail="session stored but not found on re-read")
        return match


@router.delete("/api/projects/{project_id}/auth-sessions/{session_name}")
async def remove_auth_session(project_id: int, session_name: str):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        await auth_sessions.delete_session(conn, project_id, session_name)
    return {"deleted": session_name}


@router.post("/api/projects/{project_id}/auth-sessions/{session_name}/test", response_model=AuthSessionTestResult)
async def test_auth_session(project_id: int, session_name: str):
    """
    Fires exactly one authenticated GET at the project's first in-scope
    target and reports pass/fail, so a stale/wrong credential is caught
    here instead of burning one of agent_loop's limited steps on it.
    Header-building logic intentionally duplicated (not imported) from
    agent_loop._build_credential_headers - that function is a private
    helper local to the agent loop's own request path, not a shared
    utility, and this endpoint has no other reason to import agent_loop.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        try:
            session = await auth_sessions.get_session(conn, project_id, session_name)
        except auth_policy.AuthPolicyError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        if session is None:
            raise HTTPException(status_code=404, detail=f"no session named {session_name!r} for this project")
        target_row = await conn.fetchrow(
            "SELECT target FROM scope_targets WHERE project_id = $1 AND in_scope = true ORDER BY id LIMIT 1",
            project_id,
        )

    if not target_row:
        return AuthSessionTestResult(session_name=session_name, ok=False, detail="no in-scope target to test against")

    url = target_row["target"]
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    session_type = session["session_type"]
    value = session["credential_value"]
    if session_type == "cookie":
        headers = {"Cookie": value}
    elif session_type == "bearer_token":
        headers = {"Authorization": f"Bearer {value}"}
    else:
        headers = {session["header_name"]: value}

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
        return AuthSessionTestResult(
            session_name=session_name,
            ok=resp.status_code < 400,
            status_code=resp.status_code,
            detail=f"{resp.status_code} {resp.reason_phrase}",
        )
    except Exception as exc:
        return AuthSessionTestResult(session_name=session_name, ok=False, detail=str(exc))


# --- Program-specific policy exclusions (see policy_gate.py) ---
#
# Separate from the auth-testing endpoints above, but same project-card
# UI section philosophy: paste something in once, it augments every
# scan/triage from then on without needing to be repeated per finding.

@router.get("/api/projects/{project_id}/policy", response_model=ProjectPolicy)
async def get_project_policy(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT policy_raw_text, policy_exclusions, policy_parsed_at FROM projects WHERE id = $1",
            project_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    exclusions = json.loads(row["policy_exclusions"]) if row["policy_exclusions"] else []
    return ProjectPolicy(raw_text=row["policy_raw_text"], exclusions=exclusions, parsed_at=row["policy_parsed_at"])


@router.put("/api/projects/{project_id}/policy", response_model=ProjectPolicy)
async def update_project_policy(project_id: int, payload: ProjectPolicyUpdateRequest):
    """
    Stores the pasted policy text and re-parses it with Gemini via
    policy_gate.parse_policy_exclusions - synchronous in this request
    (not backgrounded) since it's one cheap-model call, same latency
    class as a single triage call, and the person pasting this in wants
    to see the extracted list immediately to sanity-check it, not poll
    for a background job to finish.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        proj = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")

        exclusions = await policy_gate.parse_policy_exclusions(payload.raw_text)

        row = await conn.fetchrow(
            """
            UPDATE projects
            SET policy_raw_text = $2, policy_exclusions = $3, policy_parsed_at = now()
            WHERE id = $1
            RETURNING policy_raw_text, policy_exclusions, policy_parsed_at
            """,
            project_id, payload.raw_text, json.dumps(exclusions),
        )
    parsed_exclusions = json.loads(row["policy_exclusions"]) if row["policy_exclusions"] else []
    return ProjectPolicy(raw_text=row["policy_raw_text"], exclusions=parsed_exclusions, parsed_at=row["policy_parsed_at"])


@router.post("/api/projects/bulk-action", response_model=ProjectBulkActionResult)
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


@router.delete("/api/projects/{project_id}")
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


