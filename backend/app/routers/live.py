"""
routers/live.py - the /ws/projects/{project_id} WebSocket endpoint
for live scan-progress updates. Split out of the former monolithic
main.py.
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


# ---------- Live scan progress (WebSocket) ----------

@router.websocket("/ws/projects/{project_id}")
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
