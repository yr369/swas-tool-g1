"""
triage.py - assigns real severity to findings using a tiered AI approach.

Plain-language: Phase 1 stored every finding with severity='unknown'.
This module asks Gemini "how severe is this, really?" - but uses a cheap,
fast model (gemini-2.5-flash) for the routine cases, and only spends more
on a stronger model when the cheap model itself signals low confidence.
Most findings are routine (a missing security header is always 'info';
an exposed admin panel is usually 'high') - escalation is the exception,
not the rule, which keeps cost and time down without sacrificing
accuracy on the genuinely ambiguous cases.
"""

import asyncio
import json
import logging
import os

from google import genai
from google.genai import errors as genai_errors

logger = logging.getLogger("swas.triage")

_CHEAP_MODEL = "gemini-2.5-flash"
_ESCALATION_MODEL = "gemini-2.5-pro"
_MAX_RETRIES = 3
_RETRY_DELAY_SECONDS = 3

_TRIAGE_PROMPT = """You are triaging a security finding from an automated \
bug bounty scan. Assign a severity and a confidence score.

Tool: {tool_name}
Evidence (raw tool output, may contain multiple lines):
---
{evidence}
---
{outcome_context}
Respond with ONLY a JSON object, no other text, no markdown fences:
{{"severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "one sentence"}}

Guidance: missing security headers, generic fingerprinting (server/version
detection), and DNS records are almost always "info". Known CVEs with
confirmed version matches are at least "medium", often "high". Anything
suggesting actual exploitability (working SQLi, XSS execution, auth
bypass) is "high" or "critical". If you are NOT confident in this
classification (the evidence is ambiguous, contradictory, or you're
guessing), set confidence below 0.6 - this is expected and fine, it
routes the finding to a closer look rather than forcing a bad guess.
"""


def build_signature(tool_name: str, vuln_type: str, target_type: str = "website") -> str:
    """
    Builds the stable pattern key used to look up past outcomes - e.g.
    "nuclei:CVE-2023-48795:website". Keeping this in one function means
    triage and outcome-logging always agree on the same format.
    """
    return f"{tool_name}:{vuln_type}:{target_type}"


def _format_outcome_context(stats: dict | None) -> str:
    """
    Turns aggregated past-outcome stats into a short block injected into
    the prompt. Returns "" (nothing added) if there's no history yet -
    this is the realistic case for a brand-new signature, and the prompt
    should read naturally without it, not reference an empty history.
    """
    if not stats or stats.get("total", 0) == 0:
        return ""

    total = stats["total"]
    return (
        f"\nHistorical context: findings matching this exact pattern have been "
        f"submitted {total} time(s) before, with these outcomes: "
        f"{stats.get('accepted', 0)} accepted, {stats.get('duplicate', 0)} duplicate, "
        f"{stats.get('rejected', 0)} rejected, {stats.get('informative', 0)} informative, "
        f"{stats.get('not_applicable', 0)} not applicable. Weigh this history when judging "
        f"severity and confidence - e.g. a pattern rejected every time before should lower "
        f"your confidence in it being worth high severity, unless this specific evidence "
        f"clearly differs from past instances.\n"
    )


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


async def _call_with_retry(client: genai.Client, model: str, prompt: str):
    last_error = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            return client.models.generate_content(model=model, contents=prompt)
        except genai_errors.ServerError as exc:
            last_error = exc
            logger.warning("Triage call failed (attempt %d/%d): %s", attempt, _MAX_RETRIES, exc)
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_RETRY_DELAY_SECONDS * attempt)
        except Exception:
            raise
    raise last_error


def _parse_triage_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def triage_finding(tool_name: str, evidence: str, outcome_stats: dict | None = None) -> dict:
    """
    Returns {"severity": str, "confidence": float, "reasoning": str,
    "model_used": str}. Token budget is kept small on purpose - evidence
    is capped, and we send one finding at a time rather than dumping
    unrelated context, so cost scales with actual findings, not with
    everything we happen to know.

    outcome_stats (optional): aggregated past-outcome history for this
    finding's signature, from finding_outcomes via get_signature_stats().
    When provided and non-empty, it's woven into the prompt as real
    context - this is the actual "learns from mistakes" mechanism. When
    absent (a brand-new pattern with no history), triage proceeds exactly
    as before with no behavior change.

    Tries the cheap model first. If its own reported confidence is below
    0.6, escalates ONE retry to the stronger model - this is the
    "spend more only on the hard cases" behavior, not a blanket upgrade.
    """
    client = _get_client()
    # Cap evidence length sent to the model - keeps prompts small/cheap
    # and avoids wasting tokens on truncated-anyway giant tool dumps.
    capped_evidence = evidence[:2000]
    outcome_context = _format_outcome_context(outcome_stats)
    prompt = _TRIAGE_PROMPT.format(
        tool_name=tool_name, evidence=capped_evidence, outcome_context=outcome_context
    )

    try:
        response = await _call_with_retry(client, _CHEAP_MODEL, prompt)
        result = _parse_triage_response(response.text or "")
        result["model_used"] = _CHEAP_MODEL
    except Exception as exc:
        logger.exception("Cheap-tier triage failed entirely")
        return {"severity": "unknown", "confidence": 0.0, "reasoning": f"Triage failed: {exc}", "model_used": "none"}

    if result.get("confidence", 1.0) < 0.6:
        logger.info("Low confidence (%.2f) on cheap model, escalating", result.get("confidence", 0))
        try:
            response = await _call_with_retry(client, _ESCALATION_MODEL, prompt)
            escalated = _parse_triage_response(response.text or "")
            escalated["model_used"] = _ESCALATION_MODEL
            return escalated
        except Exception as exc:
            logger.warning("Escalation failed, keeping cheap-tier result: %s", exc)
            # Fall back to the cheap-tier result rather than losing the
            # finding entirely - a low-confidence guess is still more
            # useful than nothing, and it's clearly labeled as such.
            return result

    return result
