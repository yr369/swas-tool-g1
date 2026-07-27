"""
report_writer.py - turns a raw, triaged finding into a clean, platform-
tailored report draft.

Plain-language: everything upstream of this module (detective.py,
gate.py, triage.py, logic_hunter.py) produces EVIDENCE - raw tool
output, an AI severity judgment, a hypothesis. None of that is what you
paste into a Bugcrowd/HackerOne submission form. A human still has to
turn "nuclei matched CVE-2023-xxxx on /api/foo" into a clear title,
a clean reproduction, and an impact statement written the way THAT
platform's triagers actually respond to. This module does that
rewrite - it does NOT change the underlying severity/evidence/outcome
judgment, which stays triage.py's job entirely.

This is explicitly a DRAFT, same framing as logic_hunter's hypotheses:
it should be reviewed and edited before submission, not pasted in
verbatim. Report quality directly affects triage speed and outcome on
real platforms, so getting the tone/structure right matters, but a
wrong technical claim in a report is far more costly than a wrong
severity guess earlier in the pipeline (this is what a program actually
reads), so the prompt is deliberately conservative: it must not invent
impact, reproduction steps, or details beyond what's in the evidence.
"""

import json
import logging
import os

from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.report_writer")

_MODEL = "gemini-2.5-pro"

_REPORT_PROMPT = """You are drafting a bug bounty report submission for the "{platform}" \
platform, based on an ALREADY-TRIAGED finding. Do not change the technical judgment - \
severity, whether it's a real bug, what the evidence shows - just write it up the way an \
experienced hunter would submit it on this specific platform.

Target: {target}
Vulnerability type: {vuln_type}
Severity (already decided, do not second-guess): {severity}
VRT category: {vrt_category}
Triage reasoning (already decided, do not second-guess): {triage_reasoning}

Raw evidence:
---
{evidence}
---

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"title": "concise, specific report title", "summary": "one paragraph describing the vulnerability", "steps_to_reproduce": ["step 1", "step 2", "..."], "impact": "one paragraph on real-world impact, grounded in the evidence - do not invent impact beyond what the evidence supports", "suggested_fix": "one or two sentences, generic remediation guidance for this vuln class"}}

Platform tone guidance: {platform_guidance}

CRITICAL: every claim in the report must trace back to the evidence or triage reasoning \
given above. Do not invent specific request/response details, parameter names, or impact \
scenarios that aren't grounded in the evidence - if the evidence doesn't specify exact \
reproduction steps, say so in steps_to_reproduce rather than fabricating them (e.g. "Send \
the payload noted in the evidence to the affected endpoint and observe the described \
behavior" is honest; inventing a specific curl command with made-up parameter values \
that aren't in the evidence is not). This report will be submitted to a real program - \
a fabricated technical detail that doesn't hold up under review costs credibility on the \
whole account, not just this one report.
"""

_PLATFORM_GUIDANCE = {
    "bugcrowd": (
        "Bugcrowd triagers value a tight, VRT-aligned structure and a clear P1-P5 framing "
        "in the impact section. Be direct about severity justification."
    ),
    "hackerone": (
        "HackerOne triagers respond well to a clear CVSS-style impact framing and explicit "
        "reproduction steps a triager can follow without prior context on the target."
    ),
}


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_report_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def draft_report(
    platform: str, target: str, vuln_type: str, severity: str,
    evidence: str, vrt_category: str | None = None, triage_reasoning: str | None = None,
) -> dict:
    """
    Returns {"title", "summary", "steps_to_reproduce", "impact",
    "suggested_fix", "model_used"} or {"error": str} on failure -
    callers should surface the error rather than silently falling back
    to something that looks like a real draft, since this is
    user-facing content meant to be copy-pasted toward a real
    submission.
    """
    client = _get_client()
    platform_guidance = _PLATFORM_GUIDANCE.get(
        platform.lower(), "No platform-specific guidance available - use a clear, generic structure."
    )
    prompt = _REPORT_PROMPT.format(
        platform=platform, target=target, vuln_type=vuln_type, severity=severity,
        vrt_category=vrt_category or "none assigned",
        triage_reasoning=triage_reasoning or "none recorded",
        evidence=(evidence or "")[:3000],
        platform_guidance=platform_guidance,
    )
    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_MODEL)
        result = _parse_report_response(response.text or "")
        result["model_used"] = model_used
        return result
    except Exception as exc:
        logger.warning("report_writer: draft failed for target=%s vuln_type=%s: %s", target, vuln_type, exc)
        return {"error": str(exc)}
