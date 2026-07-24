"""
logic_hunter.py - LLM-driven business-logic / auth-bypass reasoning on
high-value clustered endpoints.

Plain-language: static checks (detective.py, nuclei, dalfox, sqlmap) are
pattern-matchers - they catch bugs that LOOK like a known shape. Business
logic flaws ("this checkout endpoint trusts a client-supplied price
field", "this password-reset flow never re-verifies the account after
the token is issued") don't look like anything a signature can match;
they only surface if something actually reasons about what an endpoint
is FOR and what a specific attacker could break given everything else
already known about that target. That's what this phase does: it takes
a target's most promising cluster (2+ findings and/or 2+ distinct
sources - see high_potential_clusters) and asks a strong model to
reason about what the COMBINATION of that evidence suggests, then hands
back one concrete, testable hypothesis - or nothing, if nothing
concrete actually follows.

This only runs against clusters, not every finding - it's an expensive
reasoning call, and it's spent only where correlation already suggests
there's something worth chaining, matching how gate.py spends the cheap
model on everything but triage.py's escalation and this both spend the
strong model only where warranted.

IMPORTANT: this phase produces HYPOTHESES, not confirmed findings. An
LLM reasoning over recon data can be wrong. Every finding it saves is
prefixed "[ai-hypothesis: needs manual verification]" in the evidence,
and triage.py sees that same framing - it should never be reported to a
bounty program off this phase's output alone without a human actually
testing the hypothesis first.

Investigation step: after a hypothesis is produced, agent_loop.py runs a
bounded, read-only, anonymous multi-step investigation against it (up to
6 GET/HEAD/compare probes - see agent_loop.py for the full safety model)
and appends what it found to the evidence. This replaces the old
single-shot "can this be confirmed with exactly one unauthenticated GET"
check, which only ever fired for the narrow slice of hypotheses shaped
like "is this URL reachable with no auth" - most hypotheses (IDOR, most
business-logic claims) instantly failed that bar and stayed pure,
unverified hypothesis. The agentic loop can chase a hypothesis across
several requests instead, so more hypotheses come out of this phase with
at least partial, real signal attached rather than "needs manual
verification" alone. It still can't do anything that genuinely requires
authentication or a second session - that stays item #3 in the build
order (authenticated/multi-account testing) - and the loop says so
explicitly in its conclusion when that's the blocker, rather than
pretending an anonymous probe settled something it couldn't.
"""

import json
import logging
import os

from google import genai

from . import agent_loop
from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.logic_hunter")

# Reasoning-heavy, low-volume (only high-potential clusters) - worth
# starting on the strongest model rather than rotating up to it.
_MODEL = "gemini-2.5-pro"

_LOGIC_HUNTER_PROMPT = """You are a senior bug bounty hunter looking at everything \
already discovered about ONE target during an automated recon/scan pass. Your job is \
NOT to repeat what these findings already say - it's to reason about a business-logic \
or auth-bypass angle that a signature-based scanner can't catch, but that THIS SPECIFIC \
evidence combination suggests is worth a human manually testing.

Target: {target_name} ({target_type})

What we know about this target's broader attack surface (from recon across all scans, \
not just this cluster's findings) - use this for context like "most endpoints need auth \
but this one doesn't", not as findings to repeat:
{surface_context}

Findings already recorded on this target:
{findings_block}

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"has_hypothesis": true, "hypothesis": "one paragraph: the specific logic/auth-bypass angle, WHY this evidence suggests it, and the concrete manual test a human should run to confirm or rule it out", "vuln_type": "short slug like idor_via_leaked_id_pattern", "confidence": 0.0}}

If nothing concrete follows from the evidence, respond with {{"has_hypothesis": false, \
"hypothesis": null, "vuln_type": null, "confidence": 0.0}}.

Guidance: set has_hypothesis to false far more often than true. A real hypothesis needs a \
concrete causal link from the evidence to a specific testable claim - for example, an \
exposed API doc listing a DELETE endpoint with no visible auth middleware nearby, combined \
with a separate finding showing sequential/predictable IDs, gives you something specific to \
test (does one user's session delete another user's resource by ID). Do NOT invent generic \
advice ("test for IDOR", "check for auth bypass") with no specific tie to the evidence given \
- that is a truism, not a hypothesis, and has_hypothesis should be false for it. Confidence \
below 0.5 means "worth a quick look if you have time", above 0.75 means "strong enough a \
human should prioritize this over other manual testing" - most real hypotheses land between.
"""


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_hunter_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def hunt_cluster(target_name: str, target_type: str | None, members: list[dict], surface_summary: dict | None = None) -> dict:
    """
    members: rows with tool_name, vuln_type, severity, evidence, source
    (severity may still be 'unknown' - logic_hunter runs before triage,
    so it's reasoning over raw findings, not triaged ones).

    surface_summary: one row from attack_surface_summary for this
    target, or None if the surface model has no data yet (a brand new
    target on its first scan, or scans predating this feature) - in
    that case the prompt says so plainly rather than silently omitting
    the section, so the model doesn't need to guess why it's missing.
    """
    client = _get_client()
    findings_block = "\n".join(
        f"- {m['tool_name']}/{m['vuln_type']} (source={m['source']}, severity={m['severity']}): "
        f"{(m['evidence'] or '')[:1600]}"
        for m in members
    )
    if surface_summary and surface_summary.get("total_endpoints"):
        surface_context = (
            f"{surface_summary['total_endpoints']} endpoints seen total, "
            f"{surface_summary.get('live_endpoints') or 0} confirmed live. "
            f"Of endpoints with a known auth requirement: "
            f"{surface_summary.get('auth_required_endpoints') or 0} require auth, "
            f"{surface_summary.get('no_auth_endpoints') or 0} don't. "
            f"Tech stack seen across the target: {surface_summary.get('tech_stack_union') or 'unknown'}."
        )
    else:
        surface_context = "No attack-surface data recorded yet for this target - reason from the findings below alone."
    prompt = _LOGIC_HUNTER_PROMPT.format(
        target_name=target_name, target_type=target_type or "website",
        surface_context=surface_context, findings_block=findings_block,
    )

    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_MODEL)
        result = _parse_hunter_response(response.text or "")
        result["model_used"] = model_used
        result["surface_context"] = surface_context
        return result
    except Exception as exc:
        logger.warning("logic_hunter reasoning failed for %s: %s", target_name, exc)
        return {"has_hypothesis": False, "hypothesis": None, "vuln_type": None,
                "confidence": 0.0, "model_used": "none", "surface_context": surface_context}


def _infer_requires_auth(status_code: int | None) -> bool | None:
    """
    Same heuristic as pipeline._infer_requires_auth - duplicated rather
    than imported for the same reason as everything else in this file:
    pipeline.py imports logic_hunter, so the reverse import would be
    circular.
    """
    if status_code in (401, 403):
        return True
    if status_code == 200:
        return False
    return None


async def _upsert_surface_endpoints(conn, target_id: int, endpoints: list[dict]) -> None:
    """
    conn-scoped counterpart to pipeline._save_surface_endpoints_pooled
    (which takes a pool, since recon/probe interleave many outbound
    calls with writes). logic_hunter already holds a single connection
    for the whole phase - see _phase_logic_hunter in pipeline.py - so
    this just uses it directly rather than acquiring its own. Same
    merge-not-overwrite semantics: tech_stack/sources unioned, times_seen
    incremented, requires_auth only set if not already confidently known.
    """
    if not endpoints:
        return
    for ep in endpoints:
        status_code = ep.get("status_code")
        inferred_auth = _infer_requires_auth(status_code)
        auth_evidence = f"inferred from status_code={status_code}" if inferred_auth is not None else None
        await conn.execute(
            """
            INSERT INTO attack_surface_endpoints
                (target_id, url, is_live, last_status_code, sources, requires_auth, auth_evidence)
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
            ON CONFLICT (target_id, url) DO UPDATE SET
                times_seen = attack_surface_endpoints.times_seen + 1,
                last_seen_at = now(),
                last_status_code = EXCLUDED.last_status_code,
                is_live = COALESCE(EXCLUDED.is_live, attack_surface_endpoints.is_live),
                sources = (
                    SELECT jsonb_agg(DISTINCT s)
                    FROM jsonb_array_elements_text(
                        attack_surface_endpoints.sources || EXCLUDED.sources
                    ) AS s
                ),
                requires_auth = COALESCE(attack_surface_endpoints.requires_auth, EXCLUDED.requires_auth),
                auth_evidence = COALESCE(attack_surface_endpoints.auth_evidence, EXCLUDED.auth_evidence)
            """,
            target_id,
            ep["url"],
            ep.get("is_live"),
            status_code,
            json.dumps([ep["source"]] if ep.get("source") else []),
            inferred_auth,
            auth_evidence,
        )


async def _save_hypothesis(conn, project_id: int, target_id: int, target_name: str,
                            target_type: str | None, cluster_id: int, result: dict) -> int | None:
    """
    Saves a logic_hunter hypothesis the same way pipeline._save_finding
    saves everything else (severity='unknown', goes through triage
    normally) - duplicated inline rather than imported from pipeline.py
    to avoid a circular import (pipeline.py is what calls this module).
    gate_status is set straight to 'passed' since this already came out
    the far side of an LLM reasoning pass; it doesn't need the cheap
    noise-filter gate that raw scanner/tool output does.

    Investigation: runs the bounded agentic loop (agent_loop.investigate)
    against the hypothesis - up to a few anonymous, read-only probes,
    not just the old single "is this one URL reachable" check - and
    appends its conclusion to the evidence. Every endpoint the loop
    touched also gets written back into the attack-surface model, so
    this investigation's own probing accumulates the same way recon's
    does, per the "write back, not just read" requirement from the
    build-order notes.
    """
    confidence = result.get("confidence") or 0.0
    investigation = await agent_loop.investigate(
        hypothesis=result["hypothesis"] or "",
        target_name=target_name,
        target_type=target_type,
        surface_context=result.get("surface_context") or "No attack-surface context available.",
    )
    evidence = f"[ai-hypothesis: needs manual verification, confidence={confidence:.2f}]\n{result['hypothesis']}"
    evidence += f"\n{investigation['summary']}"

    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence, gate_status)
        VALUES ($1, $2, 'logic_hunter', $3, 'unknown', $4, 'passed')
        RETURNING id
        """,
        project_id, target_id, result.get("vuln_type") or "business_logic_hypothesis", evidence[:5000],
    )
    await conn.execute(
        """
        INSERT INTO finding_cluster_members (cluster_id, finding_id, source)
        VALUES ($1, $2, 'logic_hunter')
        ON CONFLICT (cluster_id, finding_id) DO NOTHING
        """,
        cluster_id, finding_id,
    )
    await _upsert_surface_endpoints(conn, target_id, investigation["endpoints_touched"])
    return finding_id


async def hunt_project(conn, project_id: int) -> int:
    """
    Runs logic_hunter over every high-potential cluster in this project
    that hasn't been hunted yet (finding_clusters.logic_hunter_status =
    'pending'). Marks each cluster 'done' after processing regardless of
    outcome, so re-running this phase never double-spends the expensive
    call on the same cluster twice. Returns the number of hypotheses
    actually saved (not the number of clusters examined).
    """
    rows = await conn.fetch(
        """
        SELECT hpc.cluster_id, hpc.target_id, hpc.target_name, hpc.target_type
        FROM high_potential_clusters hpc
        JOIN finding_clusters fc ON fc.id = hpc.cluster_id
        WHERE fc.target_id IN (SELECT id FROM scope_targets WHERE project_id = $1)
          AND fc.logic_hunter_status = 'pending'
        """,
        project_id,
    )

    hunted = 0
    for row in rows:
        members = await conn.fetch(
            """
            SELECT f.tool_name, f.vuln_type, f.severity, f.evidence, fcm.source
            FROM finding_cluster_members fcm
            JOIN findings f ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = $1
            """,
            row["cluster_id"],
        )

        surface_summary = await conn.fetchrow(
            "SELECT * FROM attack_surface_summary WHERE target_id = $1", row["target_id"],
        )

        if members:
            result = await hunt_cluster(
                row["target_name"], row["target_type"], [dict(m) for m in members],
                dict(surface_summary) if surface_summary else None,
            )
            if result.get("has_hypothesis") and result.get("hypothesis"):
                finding_id = await _save_hypothesis(
                    conn, project_id, row["target_id"], row["target_name"], row["target_type"],
                    row["cluster_id"], result,
                )
                hunted += 1
                logger.info(
                    "logic_hunter: hypothesis saved for target_id=%s cluster_id=%s (finding_id=%s)",
                    row["target_id"], row["cluster_id"], finding_id,
                )

        # Mark hunted regardless of outcome (including "no members yet"
        # or "no hypothesis found") - this is a one-shot reasoning pass
        # per cluster, not something that should keep re-firing every
        # scan against a cluster that already got looked at.
        await conn.execute(
            "UPDATE finding_clusters SET logic_hunter_status = 'done', updated_at = now() WHERE id = $1",
            row["cluster_id"],
        )

    return hunted
