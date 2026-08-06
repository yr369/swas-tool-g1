"""
routers/health.py - /api/health and /api/health/dashboard. Split out
of the former monolithic main.py (batch: main.py split).
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


@router.get("/api/health")
async def health_check():
    """Simple endpoint to confirm the API is up and can reach the database."""
    pool = database.get_pool()
    async with pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return {"status": "ok"}


@router.get("/api/health/dashboard")
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
        # Separate count query since the row fetch above caps at 10 for
        # display - without this the panel's header count and the list
        # underneath silently disagree the moment there are more than 10
        # dead targets (header says "10", there could really be 40).
        dead_targets_total = await conn.fetchval(
            "SELECT count(*) FROM scope_targets WHERE dead_since IS NOT NULL"
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
            "dead_targets_total": dead_targets_total,
        },
    }


