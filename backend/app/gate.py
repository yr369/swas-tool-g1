"""
gate.py - the "7-Question Gate": a cheap, fast LLM pass that runs right
after scan and right before full triage.

Plain-language: triage.py's job is to decide REAL severity and whether
a bounty program would actually pay for something - that's a nuanced
call and it's worth spending a stronger model on. But a meaningful slice
of raw scanner output is just noise: a WAF block page, a truncated
parse, an empty match, a generic 404 that looked interesting for a
half-second. Spending a full triage call (with VRT mapping, outcome
history, policy-exclusion reasoning) on that is wasted cost and wasted
time. This gate exists purely to catch THAT category - "is there even a
real signal here worth a closer look" - using the cheapest model in the
rotation, before anything reaches triage.py.

Important distinction from triage.py: this gate is NOT the policy-
exclusion filter. A finding that's a real, well-formed signal but that
most bounty programs would still call Informative (e.g. a missing
security header) should PASS this gate - that judgment belongs to
triage.py, which has the actual policy-exclusion guidance and VRT
context this cheap pass doesn't. Conflating the two would mean a
legitimate-but-Informative finding never even reaches the model that's
actually equipped to say so in the report reasoning.

Fail-open by design: if the gate call itself errors out (quota, bad
JSON, whatever), the finding passes through to triage anyway. A broken
gate must never be the reason a real finding gets silently dropped -
the worst case of failing open is one wasted triage call, the worst
case of failing closed is a missed bug.
"""

import json
import logging
import os

from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.gate")

# Cheapest/fastest model in the rotation - this is a high-volume, low-
# stakes pass (every single finding goes through it), so cost matters
# more here than anywhere else in the pipeline.
_GATE_MODEL = "gemini-2.5-flash-lite"

_GATE_PROMPT = """You are the first, cheap filter in a two-stage review of an \
automated security scan finding. Answer 7 yes/no questions about it, then decide \
pass/fail.

Tool: {tool_name}
Evidence:
---
{evidence}
---

1. Does this evidence show a specific, concrete technical signal (not just a tool/template name with no actual detail)?
2. Is the evidence free of obvious parsing garbage (truncated JSON, binary noise, a generic 404/error page unrelated to any real behavior)?
3. Does this look like it came from actually hitting the target, not a WAF/CDN block page or captcha page?
4. Is there at least one concrete fact here (a path, a header value, a version string, a response difference) rather than just an assertion with nothing backing it?
5. If this is a scanner template match, does the matched content look plausible for that template (not an obvious false trigger on unrelated text)?
6. Would a human reviewer need more than a few seconds looking at this to conclude it's empty or junk?
7. Overall, is this worth spending a more expensive AI triage pass on?

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"answers": {{"q1": true, "q2": true, "q3": true, "q4": true, "q5": true, "q6": true, "q7": true}}, "pass": true, "reasoning": "one short sentence"}}

Guidance: default to "pass": true unless this is CLEARLY noise, junk, a parsing failure, \
or a WAF/block page. Do NOT fail something for being low severity, boring, or likely \
Informative to a bounty program - that policy call belongs to the next stage, which has \
the actual scope/exclusion guidance this pass doesn't. This gate only exists to catch \
garbage before it wastes an expensive call - when in doubt, pass it through.
"""


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_gate_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def run_gate(tool_name: str, evidence: str) -> dict:
    """
    Returns {"pass": bool, "reasoning": str, "model_used": str, ...}.
    Evidence is capped hard - this pass only needs enough to judge
    "is there a real signal here", not the full context triage.py gets.
    """
    client = _get_client()
    prompt = _GATE_PROMPT.format(tool_name=tool_name, evidence=(evidence or "")[:1500])

    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_GATE_MODEL)
        result = _parse_gate_response(response.text or "")
        result["model_used"] = model_used
        result["pass"] = bool(result.get("pass", True))
        return result
    except Exception as exc:
        logger.warning("Gate call failed, failing open (passing through to triage): %s", exc)
        return {"pass": True, "reasoning": f"gate call failed, fail-open: {exc}", "model_used": "none"}


async def _rollup_cluster_gate_status(conn, project_id: int) -> None:
    """
    Rolls per-finding gate results up to the cluster level. A cluster
    with ANY passed member stays eligible for high_potential_clusters
    (which already excludes gate_status='failed' - see
    correlation_schema_fix2.sql). A cluster only gets marked 'failed'
    once EVERY one of its members has been gated and NONE of them
    passed - never based on a partial/in-progress gating pass.
    """
    await conn.execute(
        """
        UPDATE finding_clusters fc
        SET gate_status = 'passed', updated_at = now()
        WHERE fc.target_id IN (SELECT id FROM scope_targets WHERE project_id = $1)
          AND fc.gate_status != 'passed'
          AND EXISTS (
              SELECT 1 FROM finding_cluster_members fcm
              JOIN findings f ON f.id = fcm.finding_id
              WHERE fcm.cluster_id = fc.id AND f.gate_status = 'passed'
          )
        """,
        project_id,
    )
    await conn.execute(
        """
        UPDATE finding_clusters fc
        SET gate_status = 'failed', updated_at = now()
        WHERE fc.target_id IN (SELECT id FROM scope_targets WHERE project_id = $1)
          AND fc.gate_status = 'pending'
          AND NOT EXISTS (
              SELECT 1 FROM finding_cluster_members fcm
              JOIN findings f ON f.id = fcm.finding_id
              WHERE fcm.cluster_id = fc.id AND f.gate_status != 'failed'
          )
        """,
        project_id,
    )


async def gate_project_findings(conn, project_id: int) -> int:
    """
    Runs the gate on every finding still pending gate review
    (severity='unknown' AND gate_status='pending') for a project, then
    rolls the results up to each affected cluster. Shared by the
    automatic "gate" phase and the on-demand /gate-all endpoint, same
    pattern as triage.triage_project_findings. Returns the number of
    findings gated.
    """
    rows = await conn.fetch(
        "SELECT id, tool_name, evidence FROM findings "
        "WHERE project_id = $1 AND severity = 'unknown' AND gate_status = 'pending'",
        project_id,
    )

    gated = 0
    for row in rows:
        result = await run_gate(row["tool_name"], row["evidence"] or "")
        status = "passed" if result["pass"] else "failed"
        await conn.execute(
            "UPDATE findings SET gate_status = $1, gate_reasoning = $2 WHERE id = $3",
            status, (result.get("reasoning") or "")[:500], row["id"],
        )
        gated += 1

    if gated:
        await _rollup_cluster_gate_status(conn, project_id)

    return gated
