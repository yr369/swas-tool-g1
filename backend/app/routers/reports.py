"""
routers/reports.py - CSV export and the Markdown/JSON report-draft
generation endpoints. Split out of the former monolithic main.py.
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


# ---------- CSV export ----------

_VALID_EXPORT_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def _parse_severities_param(severities: Optional[str]) -> Optional[list[str]]:
    """Parses a comma-separated severities query param, e.g.
    'critical,high'. Returns None (meaning "no filter, everything") if
    the param wasn't given at all - unfiltered stays the default so
    old links/bookmarks to the export URL keep working. Unknown values
    are dropped rather than raising, so a typo just narrows the filter
    instead of 500ing the export."""
    if severities is None:
        return None
    requested = {s.strip().lower() for s in severities.split(",") if s.strip()}
    valid = [s for s in requested if s in _VALID_EXPORT_SEVERITIES]
    return valid or None


def _parse_csv_param(value: Optional[str]) -> Optional[list[str]]:
    """Same shape as _parse_severities_param but for tool_name/vuln_type,
    which aren't a fixed enum - no allowlist to check against, so
    anything given through is passed to the query as-is (parameterized,
    not interpolated, so this is not an injection risk)."""
    if value is None:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


@router.get("/api/projects/{project_id}/findings/export")
async def export_findings_csv(
    project_id: int,
    severities: Optional[str] = None,
    tools: Optional[str] = None,
    vuln_types: Optional[str] = None,
):
    """
    Exports findings for this project as CSV - meant for pasting into a
    submission draft or archiving outside the tool, not as a
    replacement for the readiness checklist.

    All three filters are optional and comma-separated
    (e.g. severities="critical,high", tools="nuclei,sqlmap"). Omit any
    of them to not filter on that dimension - omitting all three
    exports everything, same as before these params existed.
    """
    sev_filter = _parse_severities_param(severities)
    tool_filter = _parse_csv_param(tools)
    vuln_filter = _parse_csv_param(vuln_types)
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow("SELECT name FROM projects WHERE id = $1", project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        rows = await conn.fetch(
            """
            SELECT f.id, st.target, f.tool_name, f.vuln_type, f.severity, f.status, f.evidence, f.created_at
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            WHERE f.project_id = $1
              AND ($2::text[] IS NULL OR f.severity = ANY($2::text[]))
              AND ($3::text[] IS NULL OR f.tool_name = ANY($3::text[]))
              AND ($4::text[] IS NULL OR f.vuln_type = ANY($4::text[]))
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
                END,
                f.created_at DESC
            """,
            project_id, sev_filter, tool_filter, vuln_filter,
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "target", "tool", "vuln_type", "severity", "status", "evidence", "created_at"])
    for row in rows:
        writer.writerow([
            row["id"], row["target"], row["tool_name"], row["vuln_type"],
            _SEVERITY_DISPLAY.get(row["severity"], row["severity"]),
            row["status"], (row["evidence"] or "").replace("\n", " "), row["created_at"],
        ])
    buffer.seek(0)

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])
    filename = f"swas_findings_{safe_name}_{project_id}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- Markdown report ----------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

# "unknown" severity means the finding hasn't been triaged into a real
# severity yet (raw tool output, e.g. sqlmap) - not a severity level a
# reviewer should read past without noticing, hence the loud label
# instead of just "Unknown" in both CSV and the report.
_SEVERITY_DISPLAY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "NOTES FOR MANUAL REVIEW",
}


_IMPACT_TEMPLATES = {
    "critical": "If exploited, this could allow an attacker to fully compromise the affected system, "
                "access or modify sensitive data at scale, or take actions with the highest level of "
                "privilege available in this application.",
    "high": "If exploited, this could allow an attacker to access or modify sensitive data, escalate "
            "privileges, or otherwise significantly impact the confidentiality, integrity, or "
            "availability of the affected system.",
    "medium": "If exploited, this could allow an attacker to access limited sensitive data or "
              "otherwise negatively impact users of the affected system, typically requiring specific "
              "conditions or user interaction.",
    "low": "The direct impact is limited, but this weakens the overall security posture of the "
           "affected system and may be combined with other issues for greater effect.",
    "info": "No direct security impact on its own, but worth documenting as a hardening opportunity "
            "or as supporting evidence for a related finding.",
}

# Coarse, substring-matched starting points - not exhaustive, just enough
# that the operator is editing a real first draft instead of a blank
# textarea. vuln_type strings vary by detector, so this matches loosely.
_REMEDIATION_HINTS = [
    (("sql injection", "sqli"), "Use parameterized queries / prepared statements for all database "
                                  "access; never build SQL via string concatenation with user input."),
    (("xss", "cross-site scripting"), "Encode output for the destination context (HTML, attribute, "
                                        "JS, URL) and apply a restrictive Content-Security-Policy."),
    (("ssrf",), "Validate and allowlist outbound destinations server-side; block requests to "
                 "internal/link-local address ranges and cloud metadata endpoints."),
    (("idor", "broken access control", "authorization"), "Enforce object-level authorization checks "
                                                            "server-side on every request, not just in the UI."),
    (("xxe", "xml external entity"), "Disable external entity resolution and DTD processing in the "
                                       "XML parser."),
    (("open redirect",), "Validate redirect targets against an allowlist rather than trusting a "
                          "user-supplied URL parameter."),
    (("cache poisoning",), "Ensure cache keys account for every header/parameter that changes the "
                             "response, and strip or normalize unkeyed inputs before they reach the origin."),
    (("subdomain takeover",), "Remove the dangling DNS record, or reclaim the resource at the "
                                "third-party provider before an attacker can."),
    (("exposed", "disclosure", "misconfiguration"), "Restrict access to this resource (authentication, "
                                                       "network ACL, or removal from the public-facing "
                                                       "deployment) and rotate any credentials it exposed."),
]


def _guess_remediation(vuln_type: str) -> str:
    lowered = vuln_type.lower()
    for keywords, hint in _REMEDIATION_HINTS:
        if any(k in lowered for k in keywords):
            return hint
    return "Describe the specific fix once confirmed - generally: validate/sanitize the relevant " \
           "input server-side and apply the principle of least privilege to the affected component."


@router.get("/api/findings/{finding_id}/report-draft", response_model=ReportDraft)
async def get_report_draft(finding_id: int):
    """
    A structured starting draft for ONE finding, for the Report Builder.
    Deliberately per-finding rather than per-project - most programs
    want one report per vulnerability, not a bundled dump (that's what
    GET /projects/{id}/report.md is for, as an overview/backup).
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT f.id, f.severity, f.tool_name, f.vuln_type, f.evidence, f.triage_reasoning,
                   f.project_id, st.target,
                   p.name AS project_name, p.platform AS project_platform
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            JOIN projects p ON p.id = f.project_id
            WHERE f.id = $1
            """,
            finding_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    sev = row["severity"] if row["severity"] in _SEVERITY_ORDER else "unknown"
    title = f"{row['vuln_type']} on {row['target']}"
    summary = (
        row["triage_reasoning"].strip()
        if row["triage_reasoning"]
        else f"A {sev} severity {row['vuln_type']} issue was identified on {row['target']}, "
             f"detected via {row['tool_name']}."
    )
    steps = (
        f"1. Navigate to / send a request to: {row['target']}\n"
        f"2. (describe the exact request/action that triggers the issue)\n"
        f"3. Observe: (describe the vulnerable behavior)\n"
        f"\nSee evidence below for the raw output that supports this."
    )
    impact = _IMPACT_TEMPLATES.get(sev, _IMPACT_TEMPLATES["info"])
    remediation = _guess_remediation(row["vuln_type"])

    return {
        "finding_id": row["id"],
        "title": title,
        "severity": sev,
        "vuln_type": row["vuln_type"],
        "tool_name": row["tool_name"],
        "target": row["target"],
        "project_id": row["project_id"],
        "project_name": row["project_name"],
        "platform": row["project_platform"],
        "summary": summary,
        "steps_to_reproduce": steps,
        "impact": impact,
        "remediation": remediation,
        "evidence": row["evidence"],
    }


@router.get("/api/projects/{project_id}/report.md")
async def generate_markdown_report(
    project_id: int,
    severities: Optional[str] = None,
    tools: Optional[str] = None,
    vuln_types: Optional[str] = None,
):
    """
    A submission-ready Markdown report: scope table, then findings
    grouped by severity with evidence in code blocks. Markdown rather
    than PDF deliberately - most Bugcrowd/HackerOne submission forms and
    note fields render Markdown directly, and it avoids adding a PDF-
    rendering dependency (weasyprint/wkhtmltopdf) to the Docker image
    just for this. Paste-and-go for a report body, or open in any editor.

    All three filters are optional and comma-separated
    (severities="critical,high", tools="nuclei,sqlmap",
    vuln_types="sqli,xss"). Omit any of them to skip filtering on that
    dimension - omitting all three exports everything, same as before
    these params existed.
    """
    sev_filter = _parse_severities_param(severities)
    tool_filter = _parse_csv_param(tools)
    vuln_filter = _parse_csv_param(vuln_types)
    pool = database.get_pool()
    async with pool.acquire() as conn:
        project = await conn.fetchrow(
            "SELECT name, platform, created_at FROM projects WHERE id = $1", project_id
        )
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        scope_rows = await conn.fetch(
            """
            SELECT target, target_type, in_scope
            FROM scope_targets WHERE project_id = $1
            ORDER BY created_at ASC
            """,
            project_id,
        )
        finding_rows = await conn.fetch(
            """
            SELECT f.severity, f.tool_name, f.vuln_type, f.evidence, f.status, st.target
            FROM findings f
            JOIN scope_targets st ON st.id = f.target_id
            WHERE f.project_id = $1
              AND ($2::text[] IS NULL OR f.severity = ANY($2::text[]))
              AND ($3::text[] IS NULL OR f.tool_name = ANY($3::text[]))
              AND ($4::text[] IS NULL OR f.vuln_type = ANY($4::text[]))
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
                END,
                f.created_at DESC
            """,
            project_id, sev_filter, tool_filter, vuln_filter,
        )

    lines: list[str] = []
    lines.append(f"# {project['name']} - Security Assessment Report")
    lines.append("")
    lines.append(f"**Platform:** {project['platform'].title()}  ")
    lines.append(f"**Report generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Project created:** {project['created_at'].strftime('%Y-%m-%d')}")
    lines.append("")

    lines.append("## Scope")
    lines.append("")
    if not scope_rows:
        lines.append("_No scope targets recorded._")
    else:
        lines.append("| Target | Type | In Scope |")
        lines.append("|---|---|---|")
        for s in scope_rows:
            lines.append(f"| {s['target']} | {s['target_type']} | {'Yes' if s['in_scope'] else 'No'} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not finding_rows:
        lines.append("_No findings recorded for this project._")
    else:
        by_severity: dict[str, list] = {}
        for f in finding_rows:
            sev = f["severity"] if f["severity"] in _SEVERITY_ORDER else "unknown"
            by_severity.setdefault(sev, []).append(f)

        for sev in _SEVERITY_ORDER:
            rows_for_sev = by_severity.get(sev)
            if not rows_for_sev:
                continue
            lines.append(f"### {_SEVERITY_DISPLAY.get(sev, sev.title())} ({len(rows_for_sev)})")
            lines.append("")
            for f in rows_for_sev:
                lines.append(f"- **{f['target']}** — `{f['tool_name']}` / {f['vuln_type']} _{f['status']}_")
                if f["evidence"]:
                    # Indent so it renders as a nested code block under
                    # the bullet, rather than breaking out to top level.
                    evidence_indented = f["evidence"].strip().replace("\n", "\n  ")
                    lines.append(f"  ```\n  {evidence_indented}\n  ```")
            lines.append("")

    content = "\n".join(lines)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])
    filename = f"swas_report_{safe_name}_{project_id}.md"
    return StreamingResponse(
        iter([content]),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


