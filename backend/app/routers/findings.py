"""
routers/findings.py - findings CRUD/bulk-status, scan notes, per-
finding and per-project triage/gate/logic-hunter-all/cluster-triage-
all endpoints, the outcome-tracking (learning loop) endpoints, and
the cross-project findings dashboard. Split out of the former
monolithic main.py; kept together since they're all reads/writes
against the findings table with no orchestration-loop dependency.
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

logger = logging.getLogger("swas.main")

router = APIRouter()


# ---------- Findings (read-only for now - the pipeline will write these) ----------

@router.get("/api/projects/{project_id}/findings", response_model=List[Finding])
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


@router.get("/api/projects/{project_id}/notes", response_model=List[ScanNote])
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


@router.patch("/api/notes/{note_id}/dismiss")
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
@router.patch("/api/findings/bulk-status", response_model=FindingBulkStatusResult)
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


@router.post("/api/findings/{finding_id}/triage")
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


@router.get("/api/findings/{finding_id}/report-draft")
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


@router.post("/api/projects/{project_id}/triage-all")
async def triage_all_findings(project_id: int):
    """
    Triages every 'unknown'-severity finding in a project. Now also runs
    automatically at the end of every scan (pipeline.py's "triage"
    phase) - this endpoint stays for re-running on demand, e.g. after
    tuning triage.py's prompt or after outcome history has changed.
    Both share the exact same logic via triage.triage_project_findings,
    so they can never drift out of sync.

    include_gate_failed=True here (unlike the automatic scan-time
    phase): a manual click is an explicit request to resolve every
    'unknown', including the ones the cheap gate already screened out
    as noise - those were previously silently skipped forever, which is
    exactly the "some unknowns never get triaged" symptom.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        triaged = await triage.triage_project_findings(conn, project_id, include_gate_failed=True)

    return {"message": f"Triaged {triaged} finding(s)", "count": triaged}


@router.post("/api/findings/triage-all")
async def triage_all_findings_everywhere():
    """
    Home page's "Triage all untriaged findings" button - sweeps every
    project's 'unknown' findings in one click instead of opening each
    project to hit its own triage-all button. Same include_gate_failed
    reasoning as the per-project endpoint above: a manual click is an
    explicit "resolve everything, spend the AI calls" signal.
    """
    pool = database.get_pool()
    result = await triage.triage_all_projects_findings(pool, include_gate_failed=True)
    project_count = len(result["per_project"])
    return {
        "message": f"Triaged {result['total']} finding(s) across {project_count} project(s)",
        **result,
    }


@router.post("/api/projects/{project_id}/gate-all")
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


@router.post("/api/projects/{project_id}/logic-hunter-all")
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


@router.post("/api/projects/{project_id}/cluster-triage-all")
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

@router.post("/api/outcomes", response_model=OutcomeRecord)
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


@router.get("/api/outcomes/signature-stats", response_model=List[SignatureStats])
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


# ---------- Cross-project findings dashboard ----------

@router.get("/api/findings", response_model=List[FindingWithProject])
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


