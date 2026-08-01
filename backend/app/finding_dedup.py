"""
finding_dedup.py - collapses repeat findings instead of re-inserting.

Nuclei (and other tools) re-run on every scan of the same target.
Without dedup, an unchanged signature - same template/check, same
target, same matched value - creates a brand new `findings` row on
every re-run, e.g. the same leaked API key showing up as 4 separate
"Critical" rows after 4 scans. That's noise in the UI, and wasted
tokens if any of those duplicates reach a report-generation call.

This is a standalone module (not folded into pipeline.py) specifically
so logic_hunter.py can also import it without a circular import -
pipeline.py already imports logic_hunter.
"""
from __future__ import annotations

import hashlib

import asyncpg


def make_dedup_key(vuln_type: str, evidence: str) -> str:
    """Content hash of the parts of a finding that mean 'same
    underlying signal'. project/target/tool are handled as separate
    lookup columns in upsert_finding, not folded into the hash."""
    raw = f"{vuln_type}|{evidence or ''}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


async def upsert_finding(
    conn: asyncpg.Connection,
    project_id: int,
    target_id: int,
    tool_name: str,
    vuln_type: str,
    severity: str,
    evidence: str,
) -> tuple[int, bool]:
    """
    Insert a finding, or bump occurrence_count on an existing match.
    Returns (finding_id, is_new).

    Only matches against non-dismissed findings on purpose: if the
    operator already reviewed and dismissed this exact signature as a
    false positive, a repeat scan hit shouldn't silently reopen it -
    that would undo a deliberate human decision.
    """
    dedup_key = make_dedup_key(vuln_type, evidence)

    existing = await conn.fetchrow(
        """
        SELECT id FROM findings
        WHERE project_id = $1 AND target_id = $2 AND tool_name = $3
          AND dedup_key = $4 AND status != 'dismissed'
        LIMIT 1
        """,
        project_id, target_id, tool_name, dedup_key,
    )
    if existing:
        await conn.execute(
            "UPDATE findings SET occurrence_count = occurrence_count + 1, last_seen = now() WHERE id = $1",
            existing["id"],
        )
        return existing["id"], False

    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence, dedup_key)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        """,
        project_id, target_id, tool_name, vuln_type, severity, evidence, dedup_key,
    )
    return finding_id, True
