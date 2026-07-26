"""
models.py - defines the "shape" of data flowing through the API.

These use Pydantic, which means FastAPI automatically validates incoming
requests against these shapes and rejects anything malformed BEFORE it
reaches our actual logic - e.g. if someone sends "target_type": "banana",
it gets rejected automatically instead of silently causing a bug later.

Each table in init.sql has a matching set of models here:
  - a "Create" model (what's needed to create a new row)
  - a plain model (what gets returned when reading a row back)
"""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel

# Program platform the project/target belongs to. "private" covers
# invite-only or non-listed programs that don't run on any of the named
# platforms. Kept as one shared alias so every model that references
# platform stays in sync - see migration 008_platform_target_expansion.sql
# for the matching DB CHECK constraint update.
PlatformType = Literal["bugcrowd", "hackerone", "intigriti", "yeswehack", "openbugbounty", "private"]

# Asset/target type. Older rows may still carry the original
# website/api/mobile/hardware/unknown values (kept valid below, never
# force-migrated) - new scope entries should use the more specific set.
TargetType = Literal[
    "website", "api", "mobile", "hardware", "unknown",  # legacy values, kept valid
    "domain", "wildcard", "url", "hardware_iot", "other",
    "android_play_store", "ios_app_store", "smart_contract",
    "source_code", "executable",
]


# ---------- Projects ----------

class ProjectCreate(BaseModel):
    name: str
    platform: PlatformType


class ProjectUpdate(BaseModel):
    # Both optional - a rename shouldn't force a platform re-pick and
    # vice versa. At least one must be set (checked in the endpoint).
    name: Optional[str] = None
    platform: Optional[PlatformType] = None


# ---------- Authenticated / multi-account testing ----------
# Read-only web-facing surface over auth_policy.py / auth_sessions.py.
# Approving a project and creating/deleting sessions stays CLI-only by
# deliberate design (see auth_cli.py's docstring) - this only exposes
# visibility into current status, nothing that can move a project out
# of default-deny or handle a credential.

class AuthPolicy(BaseModel):
    status: Literal["unset", "approved", "denied"]
    policy_note: Optional[str] = None
    set_by: Optional[str] = None
    set_at: Optional[datetime] = None


class AuthSessionMeta(BaseModel):
    session_name: str
    session_type: Literal["cookie", "bearer_token", "header"]
    header_name: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None


class Project(BaseModel):
    id: int
    name: str
    platform: PlatformType
    status: Literal["created", "scanning", "completed", "archived"]
    scan_interval_hours: Optional[int] = None
    next_scheduled_scan_at: Optional[datetime] = None
    created_at: datetime
    last_scan_at: Optional[datetime] = None
    scan_count: int = 0


class ScheduleUpdateRequest(BaseModel):
    """interval_hours=None disables the recurring schedule for this
    project - it goes back to manual-only scanning.

    run_at (Batch 6, optional): schedules a single one-time scan at a
    specific future timestamp, using the SAME scheduler loop as the
    recurring path (_run_due_scheduled_scans) rather than a second
    mechanism - it just sets next_scheduled_scan_at directly instead of
    deriving it from now() + interval_hours. Can be combined with
    interval_hours (the one-time run becomes the FIRST run, recurrence
    continues normally after); or given alone for a single scan with no
    recurrence, in which case next_scheduled_scan_at is cleared (not
    recomputed) once that one run fires - see _run_due_scheduled_scans.
    """
    interval_hours: Optional[int] = None
    run_at: Optional[datetime] = None


class ProjectDeleteRequest(BaseModel):
    """confirm_name must exactly match the project's current name -
    the same typed-confirmation friction GitHub uses for repo deletion.
    This is deliberately a stronger, less-guarded delete than
    ProjectBulkActionRequest's: bulk-action silently blocks deleting any
    project with findings (a safety net for an accidental bulk click),
    but THIS endpoint allows it, on the theory that correctly typing the
    full project name out is itself informed, deliberate intent - the
    same tradeoff GitHub makes for repos with commit history."""
    confirm_name: str


class ProjectBulkActionRequest(BaseModel):
    project_ids: list[int]
    action: Literal["archive", "unarchive", "delete"]


class ProjectBulkBlocked(BaseModel):
    """Why a project was skipped during a bulk delete - always because
    it has findings attached, since projects.id cascades to findings on
    delete and we don't want a bulk selection accidentally wiping out
    real scan results."""
    project_id: int
    name: str
    reason: str


class ProjectBulkActionResult(BaseModel):
    action: Literal["archive", "unarchive", "delete"]
    succeeded: list[int]
    blocked: list[ProjectBulkBlocked]


# ---------- Scan queue (Batch 4b) ----------

class QueueEnqueueRequest(BaseModel):
    """priority=True jumps ahead of all normal (non-priority) items, but
    still queues FIFO behind any other priority items already waiting -
    it's a separate lane, not a "run this right now" override."""
    project_id: int
    priority: bool = False


class QueueReorderRequest(BaseModel):
    """new_position is 1-indexed, counted within the item's own lane
    (priority items only reorder among priority items, normal items only
    among normal items) - matches a drag-and-drop list per lane in the UI."""
    new_position: int


class ScanQueueItem(BaseModel):
    id: int
    project_id: int
    project_name: str
    position: int
    priority: bool
    status: Literal["queued", "running", "completed", "cancelled"]
    queued_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_start_at: Optional[datetime] = None


# ---------- Scope targets ----------

class ScopeTargetCreate(BaseModel):
    target: str
    target_type: TargetType = "unknown"
    in_scope: bool = True
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class ScopeTarget(BaseModel):
    id: int
    project_id: int
    target: str
    target_type: TargetType
    in_scope: bool
    reward_range: Optional[str]
    notes: Optional[str]
    last_scanned_at: Optional[datetime] = None
    created_at: datetime


class ScopeTargetUpdate(BaseModel):
    """All fields optional - PATCH semantics. Only fields the caller
    actually sets get touched; everything else on the row is left alone.
    This is what backs the "edit" action in the Scope section (fixing a
    typo, changing type, or flipping in_scope) as distinct from the
    "delete" action, which is guarded separately below."""
    target: Optional[str] = None
    target_type: Optional[TargetType] = None
    in_scope: Optional[bool] = None
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class BulkScopeTargetsCreate(BaseModel):
    """One shared target_type/in_scope/reward_range/notes applied to a
    whole pasted batch - matches how program scope lists are usually
    copy-pasted (a block of same-type hosts), rather than needing the
    operator to fill out a form per line."""
    targets: list[str]
    target_type: TargetType = "unknown"
    in_scope: bool = True
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class BulkScopeTargetsResult(BaseModel):
    created: list[ScopeTarget]
    skipped_duplicates: list[str]


# ---------- Phase runs (the checkpoint table) ----------

class PhaseRun(BaseModel):
    id: int
    project_id: int
    target_id: int
    phase_name: Literal["recon", "probe", "fuzz", "scan", "verify", "gate", "logic_hunter", "triage", "notify"]
    status: Literal["pending", "in_progress", "completed", "failed", "needs_attention"]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    retry_count: int
    created_at: datetime


class ScanRun(BaseModel):
    id: int
    project_id: int
    started_at: datetime


# ---------- Findings ----------

class ScanNote(BaseModel):
    """A detective.py signal that's deliberately NOT a formal finding -
    either an unconfirmed pattern match needing a human look, or a
    confirmed-but-usually-informative-alone gap (clickjacking, missing
    SRI, etc.) - see add_scan_notes.sql for the full reasoning. Kept
    separate from Finding so these don't affect severity counts or
    trigger AI triage calls on speculative matches."""
    id: int
    project_id: int
    target_id: Optional[int] = None
    check_name: str
    note: str
    dismissed: bool
    created_at: datetime


class Finding(BaseModel):
    id: int
    project_id: int
    target_id: int
    tool_name: str
    vuln_type: str
    severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    evidence: Optional[str]
    raw_output_path: Optional[str]
    status: Literal["new", "reviewed", "submitted", "dismissed"]
    likely_program_outcome: Optional[Literal["accepted", "informative", "out_of_scope", "duplicate"]] = None
    triage_reasoning: Optional[str] = None
    triage_confidence: Optional[float] = None
    has_logged_outcome: bool = False
    created_at: datetime


class FindingBulkStatusRequest(BaseModel):
    finding_ids: list[int]
    status: Literal["new", "reviewed", "submitted", "dismissed"]


class FindingBulkStatusResult(BaseModel):
    status: Literal["new", "reviewed", "submitted", "dismissed"]
    updated: list[int]


class ReportDraft(BaseModel):
    """
    A structured starting point for a single-finding submission report -
    fields the operator edits in the Report Builder before copying/
    downloading. Pre-filled from what triage already collected
    (evidence, reasoning, severity) rather than left blank, but every
    field is meant to be edited, not submitted verbatim.
    """
    finding_id: int
    title: str
    severity: str
    vuln_type: str
    tool_name: str
    target: str
    project_id: int
    project_name: str
    platform: PlatformType
    summary: str
    steps_to_reproduce: str
    impact: str
    remediation: str
    evidence: Optional[str] = None


# ---------- Scope parsing (AI-assisted intake) ----------

class ScopeParseRequest(BaseModel):
    """What the operator submits: raw, loosely-structured scope text/notes
    they pasted or extracted from a program brief."""
    platform: PlatformType
    raw_text: str


class ParsedScopeItem(BaseModel):
    """What the Gemini-powered parser is expected to return, per target,
    BEFORE the operator confirms it. This is the preview shown to the user
    - nothing gets written to the database until they confirm."""
    target: str
    target_type: TargetType
    in_scope: bool
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class ScopeParsePreview(BaseModel):
    """The full response sent back to the operator after parsing - the
    list of items to review, plus the original platform so the confirm
    step knows what to attach."""
    platform: PlatformType
    items: list[ParsedScopeItem]


class ScopeConfirmRequest(BaseModel):
    """What the operator sends back after reviewing the preview - the
    (possibly edited) list of items they actually want saved. If
    project_id is omitted, a new project is created; if provided, items
    are attached to that existing project instead."""
    project_id: Optional[int] = None
    project_name: Optional[str] = None  # required if project_id is omitted
    platform: PlatformType
    items: list[ParsedScopeItem]


# ---------- Outcome tracking (the learning loop) ----------

class OutcomeLogRequest(BaseModel):
    """What the operator submits after a real Bugcrowd/HackerOne result
    comes back for a finding they reported."""
    finding_id: Optional[int] = None
    signature: str  # e.g. "nuclei:CVE-2023-48795:website"
    outcome: Literal["accepted", "duplicate", "rejected", "informative", "not_applicable", "no_response"]
    platform: Optional[PlatformType] = None
    notes: Optional[str] = None


class OutcomeRecord(BaseModel):
    id: int
    finding_id: Optional[int]
    signature: str
    outcome: str
    platform: Optional[str]
    notes: Optional[str]
    recorded_at: datetime


class SignatureStats(BaseModel):
    """Aggregated history for a signature - what triage can look up to
    see 'findings like this were rejected 4 times before'."""
    signature: str
    total: int
    accepted: int
    duplicate: int
    rejected: int
    informative: int
    not_applicable: int
    no_response: int


# ---------- Submission readiness ----------

class ReadinessCheckResult(BaseModel):
    name: str
    passed: bool
    detail: str


class ReadinessResponse(BaseModel):
    finding_id: int
    ready: bool
    checks: list[ReadinessCheckResult]


# ---------- Scan history / run-to-run diff ----------

class ScanRun(BaseModel):
    id: int
    project_id: int
    started_at: datetime


class DiffFinding(BaseModel):
    """A finding identity used for diffing - deliberately NOT the full
    Finding model. Two findings are "the same" for diff purposes if they
    share (target_id, tool_name, vuln_type), even if the exact evidence
    text differs slightly between runs (e.g. a cert expiry date moving
    forward by a day is still 'the same finding', not a new one)."""
    id: int
    target_id: int
    tool_name: str
    vuln_type: str
    severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    evidence: Optional[str]


class DiffResponse(BaseModel):
    project_id: int
    baseline_run: ScanRun
    latest_run: ScanRun
    new_findings: list[DiffFinding]
    resolved_findings: list[DiffFinding]
    unchanged_count: int


# ---------- Cross-project findings (dashboard) ----------

class FindingWithProject(Finding):
    project_name: str
    project_platform: PlatformType


