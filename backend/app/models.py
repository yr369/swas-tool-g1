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


# ---------- Projects ----------

class ProjectCreate(BaseModel):
    name: str
    platform: Literal["bugcrowd", "hackerone"]


class Project(BaseModel):
    id: int
    name: str
    platform: Literal["bugcrowd", "hackerone"]
    status: Literal["created", "scanning", "completed", "archived"]
    created_at: datetime


# ---------- Scope targets ----------

class ScopeTargetCreate(BaseModel):
    target: str
    target_type: Literal["website", "api", "mobile", "hardware", "unknown"] = "unknown"
    in_scope: bool = True
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class ScopeTarget(BaseModel):
    id: int
    project_id: int
    target: str
    target_type: Literal["website", "api", "mobile", "hardware", "unknown"]
    in_scope: bool
    reward_range: Optional[str]
    notes: Optional[str]
    created_at: datetime


# ---------- Phase runs (the checkpoint table) ----------

class PhaseRun(BaseModel):
    id: int
    project_id: int
    target_id: int
    phase_name: Literal["recon", "probe", "fuzz", "scan", "notify"]
    status: Literal["pending", "in_progress", "completed", "failed", "needs_attention"]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    retry_count: int
    created_at: datetime


# ---------- Findings ----------

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
    created_at: datetime


# ---------- Scope parsing (AI-assisted intake) ----------

class ScopeParseRequest(BaseModel):
    """What the operator submits: raw, loosely-structured scope text/notes
    they pasted or extracted from a program brief."""
    platform: Literal["bugcrowd", "hackerone"]
    raw_text: str


class ParsedScopeItem(BaseModel):
    """What the Gemini-powered parser is expected to return, per target,
    BEFORE the operator confirms it. This is the preview shown to the user
    - nothing gets written to the database until they confirm."""
    target: str
    target_type: Literal["website", "api", "mobile", "hardware", "unknown"]
    in_scope: bool
    reward_range: Optional[str] = None
    notes: Optional[str] = None


class ScopeParsePreview(BaseModel):
    """The full response sent back to the operator after parsing - the
    list of items to review, plus the original platform so the confirm
    step knows what to attach."""
    platform: Literal["bugcrowd", "hackerone"]
    items: list[ParsedScopeItem]


class ScopeConfirmRequest(BaseModel):
    """What the operator sends back after reviewing the preview - the
    (possibly edited) list of items they actually want saved. If
    project_id is omitted, a new project is created; if provided, items
    are attached to that existing project instead."""
    project_id: Optional[int] = None
    project_name: Optional[str] = None  # required if project_id is omitted
    platform: Literal["bugcrowd", "hackerone"]
    items: list[ParsedScopeItem]

