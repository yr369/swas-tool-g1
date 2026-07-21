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
LLM reasoning over recon data can be wrong, and unlike detective.py's
checks (which confirm behavior against a live response before ever
returning a finding), logic_hunter never sends a single request itself.
Every finding it saves is prefixed "[ai-hypothesis: needs manual
verification]" in the evidence, and triage.py sees that same framing -
it should never be reported to a bounty program off this phase's output
alone without a human actually testing the hypothesis first.
"""

import json
import logging
import os

import httpx
from google import genai

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


_VERIFICATION_TIMEOUT = 10.0

# Deliberately the cheap model, same tier as gate.py - this is a narrow
# extraction task (does the hypothesis contain ONE safely-testable claim),
# not open-ended reasoning, so it doesn't need gemini-2.5-pro.
_VERIFICATION_MODEL = "gemini-2.5-flash-lite"

_VERIFICATION_PROMPT = """A security researcher's hypothesis about a target is below. Your \
ONLY job is to decide whether this specific hypothesis can be partially confirmed or refuted \
with a SINGLE, unauthenticated, read-only HTTP GET request - nothing else counts as testable.

Hypothesis: {hypothesis}

Mark testable=false for ANYTHING that requires: comparing two different user sessions/accounts, \
sending a POST/PUT/DELETE/PATCH, needing a valid auth token you don't already have, or any \
multi-step sequence. Most hypotheses (especially IDOR and most business-logic claims) genuinely \
require a second authenticated session to confirm and are NOT testable this way - it is correct \
and expected for testable to be false most of the time.

Only mark testable=true for narrow cases like: "this admin/internal endpoint is reachable with \
no authentication at all" (a plain GET to that exact URL returning 200 instead of 401/403/404 \
would confirm it), where the full concrete URL is already stated or directly derivable from the \
hypothesis text.

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"testable": false}}
or
{{"testable": true, "url": "https://full/concrete/url", "expected_signal": "one short phrase describing what a CONFIRMING response looks like, e.g. 'HTTP 200 with a JSON body' or 'HTTP 200 instead of 401/403'"}}
"""


def _parse_verification_extraction(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def _attempt_single_request_verification(hypothesis: str) -> str | None:
    """
    Returns a short evidence-appendix string describing the verification
    outcome, or None if the hypothesis wasn't safely testable this way
    (the overwhelmingly common case - most hypotheses need a second
    session and stay pure hypothesis, which is correct and expected).

    Safety: regardless of what the model returns, this only ever issues
    a single GET. No method, header, or body the model suggests can turn
    this into a state-changing request - that's enforced in code, not
    just by the prompt.
    """
    client = _get_client()
    try:
        response, _ = await generate_with_rotation(
            client, _VERIFICATION_PROMPT.format(hypothesis=hypothesis[:2000]),
            preferred_model=_VERIFICATION_MODEL,
        )
        extraction = _parse_verification_extraction(response.text or "")
    except Exception as exc:
        logger.info("logic_hunter: verification extraction failed, leaving as pure hypothesis: %s", exc)
        return None

    if not extraction.get("testable") or not extraction.get("url"):
        return None

    url = extraction["url"]
    expected_signal = (extraction.get("expected_signal") or "")[:200]

    try:
        async with httpx.AsyncClient(timeout=_VERIFICATION_TIMEOUT, verify=False, follow_redirects=True) as http_client:
            resp = await http_client.get(url)  # GET only - hardcoded, never derived from model output
    except httpx.HTTPError as exc:
        logger.info("logic_hunter: verification GET failed for %s: %s", url, exc)
        return f"[auto-verification attempted, request failed: {exc}] no signal either way."

    if resp.status_code in (401, 403, 404):
        return (
            f"[auto-verification: GET {url} returned {resp.status_code} - the claimed "
            f"unauthenticated access does NOT appear to hold; this hypothesis looks weaker "
            f"than it first read, but confirm manually before dismissing]"
        )
    if resp.status_code == 200 and len(resp.text) > 50:
        return (
            f"[auto-verification: GET {url} returned 200 with a {len(resp.text)}-byte body "
            f"with no auth sent - consistent with the hypothesis (expected signal: "
            f"{expected_signal!r}). Still needs a human to confirm the response body actually "
            f"contains what's claimed before this is report-ready.]"
        )
    return (
        f"[auto-verification: GET {url} returned {resp.status_code} - inconclusive, "
        f"doesn't clearly confirm or refute the hypothesis]"
    )


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_hunter_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def hunt_cluster(target_name: str, target_type: str | None, members: list[dict]) -> dict:
    """
    members: rows with tool_name, vuln_type, severity, evidence, source
    (severity may still be 'unknown' - logic_hunter runs before triage,
    so it's reasoning over raw findings, not triaged ones).
    """
    client = _get_client()
    findings_block = "\n".join(
        f"- {m['tool_name']}/{m['vuln_type']} (source={m['source']}, severity={m['severity']}): "
        f"{(m['evidence'] or '')[:1600]}"
        for m in members
    )
    prompt = _LOGIC_HUNTER_PROMPT.format(
        target_name=target_name, target_type=target_type or "website", findings_block=findings_block,
    )

    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_MODEL)
        result = _parse_hunter_response(response.text or "")
        result["model_used"] = model_used
        return result
    except Exception as exc:
        logger.warning("logic_hunter reasoning failed for %s: %s", target_name, exc)
        return {"has_hypothesis": False, "hypothesis": None, "vuln_type": None,
                "confidence": 0.0, "model_used": "none"}


async def _save_hypothesis(conn, project_id: int, target_id: int, cluster_id: int, result: dict) -> int | None:
    """
    Saves a logic_hunter hypothesis the same way pipeline._save_finding
    saves everything else (severity='unknown', goes through triage
    normally) - duplicated inline rather than imported from pipeline.py
    to avoid a circular import (pipeline.py is what calls this module).
    gate_status is set straight to 'passed' since this already came out
    the far side of an LLM reasoning pass; it doesn't need the cheap
    noise-filter gate that raw scanner/tool output does.
    """
    confidence = result.get("confidence") or 0.0
    verification_note = await _attempt_single_request_verification(result["hypothesis"] or "")
    evidence = f"[ai-hypothesis: needs manual verification, confidence={confidence:.2f}]\n{result['hypothesis']}"
    if verification_note:
        evidence += f"\n{verification_note}"
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

        if members:
            result = await hunt_cluster(row["target_name"], row["target_type"], [dict(m) for m in members])
            if result.get("has_hypothesis") and result.get("hypothesis"):
                finding_id = await _save_hypothesis(conn, project_id, row["target_id"], row["cluster_id"], result)
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
