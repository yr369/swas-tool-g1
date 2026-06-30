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
import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import os

from . import checkpoint, database, pipeline, scope_parser, triage
from .models import (
    Project,
    ProjectCreate,
    ScopeTarget,
    ScopeTargetCreate,
    ScopeParseRequest,
    ScopeParsePreview,
    ScopeConfirmRequest,
    Finding,
    PhaseRun,
    OutcomeLogRequest,
    OutcomeRecord,
    SignatureStats,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("swas.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs once when the app starts up
    await database.connect_db()

    # Crash-safety check: if the app was restarted while scans were mid-
    # flight, those phase_runs are stuck "in_progress" with no one ever
    # going to mark them finished. We flag them now rather than letting
    # them sit there silently forever.
    pool = database.get_pool()
    async with pool.acquire() as conn:
        recovered_count = await checkpoint.recover_interrupted_runs(conn)
    if recovered_count > 0:
        logger.warning(
            "Found and flagged %d scan phase(s) interrupted by a previous "
            "restart - check phase_runs with status='needs_attention'",
            recovered_count,
        )

    yield
    # Runs once when the app shuts down (e.g. container stopping)
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


# ---------- Projects ----------

@app.post("/api/projects", response_model=Project)
async def create_project(payload: ProjectCreate):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO projects (name, platform)
            VALUES ($1, $2)
            RETURNING id, name, platform, status, created_at
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
            "SELECT id, name, platform, status, created_at FROM projects ORDER BY created_at DESC"
        )
    return [dict(row) for row in rows]


@app.get("/api/projects/{project_id}", response_model=Project)
async def get_project(project_id: int):
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name, platform, status, created_at FROM projects WHERE id = $1",
            project_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


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
                      reward_range, notes, created_at
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
                   reward_range, notes, created_at
            FROM scope_targets
            WHERE project_id = $1
            ORDER BY created_at ASC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


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
    if platform not in ("bugcrowd", "hackerone"):
        raise HTTPException(status_code=400, detail="platform must be 'bugcrowd' or 'hackerone'")

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
                    "SELECT id, name, platform, status, created_at FROM projects WHERE id = $1",
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
                    RETURNING id, name, platform, status, created_at
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
            SELECT id, project_id, target_id, tool_name, vuln_type, severity,
                   evidence, raw_output_path, status, created_at
            FROM findings
            WHERE project_id = $1
            ORDER BY created_at DESC
            """,
            project_id,
        )
    return [dict(row) for row in rows]


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

        result = await triage.triage_finding(
            finding["tool_name"], finding["evidence"] or "", outcome_stats=outcome_stats
        )

        await conn.execute(
            "UPDATE findings SET severity = $1 WHERE id = $2",
            result["severity"] if result["severity"] in
            ("critical", "high", "medium", "low", "info") else "unknown",
            finding_id,
        )

    return {"finding_id": finding_id, "signature": signature, **result}


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
    """Triages every 'unknown'-severity finding in a project, one at a time,
    looking up past outcome history per signature before each call."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, tool_name, vuln_type, evidence FROM findings WHERE project_id = $1 AND severity = 'unknown'",
            project_id,
        )

        triaged = 0
        for row in rows:
            signature = triage.build_signature(row["tool_name"], row["vuln_type"])
            outcome_stats = await _fetch_signature_stats(conn, signature)
            result = await triage.triage_finding(
                row["tool_name"], row["evidence"] or "", outcome_stats=outcome_stats
            )
            await conn.execute(
                "UPDATE findings SET severity = $1 WHERE id = $2",
                result["severity"] if result["severity"] in
                ("critical", "high", "medium", "low", "info") else "unknown",
                row["id"],
            )
            triaged += 1

    return {"message": f"Triaged {triaged} finding(s)", "count": triaged}


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
async def start_scan(project_id: int, background_tasks: BackgroundTasks):
    """
    Kicks off scanning for every in-scope target in this project. Runs in
    the background - this endpoint returns immediately rather than
    making the operator's browser wait for scans that can take a long
    time. Progress can be checked via GET /api/projects/{id}/phase-runs.

    Phase 1 keeps this simple: every in-scope target starts its pipeline
    concurrently (no queue/concurrency cap yet - that's a later phase).
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT id FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        targets = await conn.fetch(
            "SELECT id, target FROM scope_targets WHERE project_id = $1 AND in_scope = true",
            project_id,
        )

        if not targets:
            raise HTTPException(
                status_code=400,
                detail="No in-scope targets found for this project - add scope first",
            )

        await conn.execute(
            "UPDATE projects SET status = 'scanning' WHERE id = $1", project_id
        )

    for target_row in targets:
        background_tasks.add_task(
            pipeline.run_target_pipeline,
            pool,
            project_id,
            target_row["id"],
            target_row["target"],
        )

    return {
        "message": f"Scan started for {len(targets)} target(s)",
        "target_count": len(targets),
    }


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
