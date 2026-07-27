"""
target_intelligence.py - per-target and per-project intelligence that lets
SWAS change its approach per target instead of running the same fixed
style everywhere.

Plain-language: a human hunter doesn't attack a WordPress blog the same
way they attack a custom fintech API, and they don't forget that a WAF
blocked their SSRF payloads last time they hit this same program. This
module gives SWAS that same adaptiveness, in four pieces:

1. PERSONA (per target): a short AI-written attack plan generated once
   per target from its tech stack/type, e.g. "prioritize IDOR and auth
   logic over XSS for this API." Stored once, read by logic_hunter so
   its reasoning is shaped by the target's actual profile instead of a
   generic checklist.

2. TECHNIQUE MEMORY (per target): what worked, what got blocked, and
   what wasted time on THIS specific target - fed back into
   logic_hunter's prompt so it doesn't repeat a dead end.

3. CROSS-TARGET PATTERNS (per project): if a bug class was found on one
   target with a given tech stack, other targets sharing that stack get
   a hint to check for it too - the same intuition a human hunter builds
   after a few targets on the same program.

4. PAYOUT-PRIORITY SCHEDULING (per project): targets are ordered by a
   priority score derived from their reward_range before scan tasks are
   created, so with a bounded concurrency semaphore the highest-value
   targets get worked first instead of whatever order they happen to be
   stored in.

Every function here fails soft: a broken persona/pattern/priority call
should cost SWAS a missed optimization, never a missed finding or a
crashed scan. Same fail-open philosophy as gate.py.
"""

import hashlib
import json
import logging
import os
import re

import asyncpg
from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.target_intelligence")

_PERSONA_MODEL = "gemini-2.5-flash"

# Bounded so technique_notes never grows unbounded on a long-running
# target - same spirit as the 1600-char evidence truncation elsewhere.
_MAX_TECHNIQUE_NOTES = 20

_PERSONA_PROMPT = """You are planning attack strategy for ONE bug bounty target before \
any scanning starts. Based on what's known about it, write a SHORT (2-3 sentence) attack \
persona: which vulnerability classes and techniques are actually worth prioritizing here, \
and which are probably low-yield for this specific kind of target. Be concrete and specific \
to this target's profile, not generic security advice.

Target: {target_name}
Target type: {target_type}
Known tech stack hints: {tech_hint}
Reward range: {reward_range}

Respond with ONLY the persona text, 2-3 sentences, no preamble, no markdown, no JSON."""


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


# ---------------------------------------------------------------------
# 1. Persona
# ---------------------------------------------------------------------

async def get_or_generate_persona(
    conn: asyncpg.Connection,
    target_id: int,
    target_name: str,
    target_type: str | None,
    tech_hint: str = "unknown at this point (pre-recon)",
    reward_range: str | None = None,
) -> str | None:
    """
    Returns the stored persona for this target, generating and storing
    one on first call. Cheap model, one-shot, never regenerated once
    set (a target's fundamental profile doesn't change scan-to-scan the
    way its findings do) - if you want a fresh persona after a major
    scope/tech change, clear the row manually.

    Returns None (not a string) on any failure - callers must treat a
    missing persona as "no persona available yet", not as a value to
    silently coerce.
    """
    existing = await conn.fetchval(
        "SELECT persona FROM target_intelligence WHERE target_id = $1", target_id,
    )
    if existing:
        return existing

    client = _get_client()
    prompt = _PERSONA_PROMPT.format(
        target_name=target_name,
        target_type=target_type or "website",
        tech_hint=tech_hint,
        reward_range=reward_range or "not specified",
    )
    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_PERSONA_MODEL)
        persona = (response.text or "").strip()
        if not persona:
            return None
        await conn.execute(
            """
            INSERT INTO target_intelligence (target_id, persona, persona_generated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (target_id) DO UPDATE SET
                persona = COALESCE(target_intelligence.persona, EXCLUDED.persona),
                persona_generated_at = COALESCE(target_intelligence.persona_generated_at, now())
            """,
            target_id, persona,
        )
        logger.info("target_intelligence: persona generated for target_id=%s via %s", target_id, model_used)
        return persona
    except Exception as exc:
        logger.warning("target_intelligence: persona generation failed for target_id=%s: %s", target_id, exc)
        return None


# ---------------------------------------------------------------------
# 2. Technique memory
# ---------------------------------------------------------------------

async def record_technique_outcome(
    conn: asyncpg.Connection, target_id: int, technique: str, outcome: str, note: str | None = None,
) -> None:
    """
    Appends one {technique, outcome, note, recorded_at} entry to this
    target's technique_notes, keeping only the most recent
    _MAX_TECHNIQUE_NOTES. `technique` should be a short stable slug
    (e.g. "nuclei:CVE-2023-48795" or "ssrf_blind_oob") and `outcome`
    something like "blocked_by_waf", "accepted", "informative",
    "no_signal" - free text is fine, this is prompt context, not a
    constrained enum.
    """
    entry = {"technique": technique, "outcome": outcome, "note": (note or "")[:300]}
    try:
        await conn.execute(
            """
            INSERT INTO target_intelligence (target_id, technique_notes)
            VALUES ($1, $2::jsonb)
            ON CONFLICT (target_id) DO UPDATE SET
                technique_notes = (
                    SELECT jsonb_agg(elem)
                    FROM (
                        SELECT elem
                        FROM jsonb_array_elements(
                            target_intelligence.technique_notes || $2::jsonb
                        ) AS elem
                        ORDER BY COALESCE((elem->>'recorded_at')::timestamptz, now()) DESC
                        LIMIT $3
                    ) sub
                ),
                updated_at = now()
            """,
            target_id,
            json.dumps([{**entry, "recorded_at": None}]),
            _MAX_TECHNIQUE_NOTES,
        )
    except Exception as exc:
        logger.warning("target_intelligence: failed to record technique outcome for target_id=%s: %s", target_id, exc)


async def format_technique_notes(conn: asyncpg.Connection, target_id: int) -> str:
    """
    Returns a short block for prompt injection, or "" if there's no
    history yet - matches triage._format_outcome_context's "say nothing
    rather than reference an empty history" convention.
    """
    notes = await conn.fetchval(
        "SELECT technique_notes FROM target_intelligence WHERE target_id = $1", target_id,
    )
    if not notes:
        return ""
    try:
        parsed = json.loads(notes) if isinstance(notes, str) else notes
    except (TypeError, ValueError):
        return ""
    if not parsed:
        return ""
    lines = "\n".join(
        f"- {n.get('technique', '?')}: {n.get('outcome', '?')}"
        + (f" ({n['note']})" if n.get("note") else "")
        for n in parsed[-_MAX_TECHNIQUE_NOTES:]
    )
    return f"\nWhat's already been tried on THIS specific target before:\n{lines}\n"


# ---------------------------------------------------------------------
# 3. Cross-target pattern propagation
# ---------------------------------------------------------------------

async def record_cross_target_pattern(
    conn: asyncpg.Connection, project_id: int, vuln_type: str,
    tech_stack_signature: str | None, source_target_id: int, note: str,
) -> None:
    """
    Called when a real (triaged, non-'info') finding lands on a target -
    records the vuln class + the tech stack it appeared on, so other
    targets in the SAME project sharing that stack get a hint to check
    for it too. tech_stack_signature should be a short normalized string
    (e.g. sorted, comma-joined tech names) - callers own normalization
    since only they know their tech_stack shape.
    """
    if not tech_stack_signature:
        return
    try:
        await conn.execute(
            """
            INSERT INTO cross_target_patterns
                (project_id, vuln_type, tech_stack_signature, source_target_id, note)
            VALUES ($1, $2, $3, $4, $5)
            """,
            project_id, vuln_type, tech_stack_signature, source_target_id, note[:500],
        )
    except Exception as exc:
        logger.warning("target_intelligence: failed to record cross-target pattern for project_id=%s: %s", project_id, exc)


async def format_cross_target_context(
    conn: asyncpg.Connection, project_id: int, tech_stack_signature: str | None, exclude_target_id: int | None = None,
) -> str:
    """
    Returns hints for THIS target based on what was found on OTHER
    targets in the same project sharing its tech stack signature.
    Exact-match on signature only (no fuzzy matching) - a wrong hint
    costs nothing here since it's advisory prompt context, but a noisy
    fuzzy-match implementation would erode trust in the signal over
    time, so keep it precise.
    """
    if not tech_stack_signature:
        return ""
    rows = await conn.fetch(
        """
        SELECT vuln_type, note, created_at FROM cross_target_patterns
        WHERE project_id = $1 AND tech_stack_signature = $2
          AND ($3::int IS NULL OR source_target_id != $3)
        ORDER BY created_at DESC LIMIT 5
        """,
        project_id, tech_stack_signature, exclude_target_id,
    )
    if not rows:
        return ""
    lines = "\n".join(f"- {r['vuln_type']}: {r['note']}" for r in rows)
    return (
        f"\nOther targets in this project with the SAME tech stack have shown these "
        f"patterns - worth checking whether they apply here too:\n{lines}\n"
    )


# ---------------------------------------------------------------------
# 4. Payout-priority scheduling
# ---------------------------------------------------------------------

# Matches the largest dollar figure in a freeform reward_range string
# like "$500 - $2,500" or "up to $10000" or "$250/low, $5000/critical".
_MONEY_RE = re.compile(r"\$?\s*([\d,]+(?:\.\d+)?)\s*[kK]?")


def compute_payout_priority(reward_range: str | None) -> float:
    """
    Turns a freeform reward_range string into a sortable priority
    score. This is deliberately simple (no LLM call - this runs on
    every scan kickoff and must be instant): it takes the largest
    number found in the string as a proxy for "best case payout", so
    "$500 - $10,000" and "up to $10k critical" both score highly. A
    target with no reward_range at all gets a low-but-nonzero default
    so it still gets scanned, just after targets with disclosed payouts.
    """
    if not reward_range:
        return 1.0
    matches = _MONEY_RE.findall(reward_range)
    if not matches:
        return 1.0
    values = []
    for m in matches:
        try:
            v = float(m.replace(",", ""))
        except ValueError:
            continue
        # crude k-suffix handling: if the original snippet around this
        # number contains a 'k'/'K', the regex above already consumed
        # it as part of the unit, so scale here based on string content.
        values.append(v)
    if not values:
        return 1.0
    best = max(values)
    if "k" in reward_range.lower() and best < 1000:
        best *= 1000
    return best


def normalize_tech_signature(tech_stack_union: str | None) -> str | None:
    """
    Turns attack_surface_summary.tech_stack_union (a freeform,
    insertion-order string like "nginx, PHP, WordPress") into a stable,
    order-independent signature ("nginx,php,wordpress") so two targets
    with the same stack in a different discovery order still match in
    cross_target_patterns lookups. Returns None for empty/unknown input
    - callers should skip pattern recording/lookup entirely in that
    case rather than matching on an empty signature.
    """
    if not tech_stack_union or not tech_stack_union.strip():
        return None
    parts = sorted({p.strip().lower() for p in tech_stack_union.split(",") if p.strip()})
    return ",".join(parts) if parts else None


def order_target_rows(rows: list) -> list:
    """
    Sorts asyncpg Record rows (must include a 'reward_range' column) by
    descending payout priority. Ties (including all-missing
    reward_range, the common case for programs that don't disclose
    per-target payouts) keep their original relative order - Python's
    sort is stable, so this never reshuffles targets that are actually
    tied on priority.
    """
    return sorted(rows, key=lambda r: compute_payout_priority(r.get("reward_range")), reverse=True)


# ---------------------------------------------------------------------
# 5. Rescan / freshness triggers
# ---------------------------------------------------------------------

def compute_surface_fingerprint(live_hosts: list[str], tech_stack: dict[str, list[str]]) -> str:
    """
    A stable hash of "what does this target's attack surface look
    like" - the live host set plus the union of detected tech. Deliberately
    coarse (not per-endpoint-content hashing, which would churn on every
    scan from dynamic pages and defeat the purpose) - this is meant to
    catch real structural change: a new subdomain went live, a WAF got
    added, the stack was upgraded (e.g. PHP -> a new framework) -
    not "the homepage's timestamp changed."
    """
    tech_flat = sorted({t for techs in tech_stack.values() for t in techs})
    signature = "|".join(sorted(live_hosts)) + "||" + ",".join(tech_flat)
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


async def check_and_reset_on_change(
    conn: asyncpg.Connection, target_id: int, live_hosts: list[str], tech_stack: dict[str, list[str]],
) -> bool:
    """
    Compares this scan's surface fingerprint to the last stored one.
    On a genuine change (not the first-ever scan, which has nothing to
    compare against) resets this target's finding_clusters back to
    'pending' for both logic_hunter and triage - the same re-hunt
    mechanism pipeline.py already uses when a cluster gets a brand new
    member finding (see _upsert_finding_cluster), just triggered by
    surface drift instead of a new finding. Returns True if a reset
    happened, False otherwise (including on the first-ever scan, where
    there's deliberately no reset - nothing to be "stale" relative to).
    """
    new_fp = compute_surface_fingerprint(live_hosts, tech_stack)
    try:
        old_fp = await conn.fetchval(
            "SELECT surface_fingerprint FROM target_intelligence WHERE target_id = $1", target_id,
        )
        await conn.execute(
            """
            INSERT INTO target_intelligence (target_id, surface_fingerprint)
            VALUES ($1, $2)
            ON CONFLICT (target_id) DO UPDATE SET
                surface_fingerprint = EXCLUDED.surface_fingerprint, updated_at = now()
            """,
            target_id, new_fp,
        )
        if old_fp is not None and old_fp != new_fp:
            await conn.execute(
                """
                UPDATE finding_clusters
                SET logic_hunter_status = 'pending', triage_status = 'pending', updated_at = now()
                WHERE target_id = $1
                """,
                target_id,
            )
            logger.info(
                "target_intelligence: surface changed for target_id=%s - clusters reset to pending for re-hunt",
                target_id,
            )
            return True
        return False
    except Exception as exc:
        logger.warning("target_intelligence: fingerprint check failed for target_id=%s: %s", target_id, exc)
        return False


# ---------------------------------------------------------------------
# 6. Human-in-the-loop checkpoints
# ---------------------------------------------------------------------

# Findings at/above this severity that triage marked as likely to be
# accepted are worth a real-time alert, not just sitting in the queue
# until someone happens to check the dashboard.
_ALERT_SEVERITIES = ("critical", "high")


async def get_unalerted_high_value_findings(conn: asyncpg.Connection, project_id: int) -> list[dict]:
    """
    Returns triaged findings in this project that are high-value
    (severity critical/high AND likely_program_outcome='accepted') and
    haven't been alerted on yet (alerted_at IS NULL). Callers should
    mark them alerted via mark_alerted() right after sending the
    notification, so the same finding never double-alerts on a later
    scan pass.
    """
    rows = await conn.fetch(
        """
        SELECT f.id, f.target_id, st.target, f.tool_name, f.vuln_type, f.severity, f.triage_reasoning
        FROM findings f
        JOIN scope_targets st ON st.id = f.target_id
        WHERE f.project_id = $1
          AND f.severity = ANY($2::text[])
          AND f.likely_program_outcome = 'accepted'
          AND f.alerted_at IS NULL
        """,
        project_id, list(_ALERT_SEVERITIES),
    )
    return [dict(r) for r in rows]


async def mark_alerted(conn: asyncpg.Connection, finding_ids: list[int]) -> None:
    if not finding_ids:
        return
    await conn.execute(
        "UPDATE findings SET alerted_at = now() WHERE id = ANY($1::int[])", finding_ids,
    )
