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


async def triage_finding(tool_name: str, evidence: str) -> dict:
    """
    Returns {"severity": str, "confidence": float, "reasoning": str,
    "model_used": str}. Token budget is kept small on purpose - evidence
    is capped, and we send one finding at a time rather than dumping
    unrelated context, so cost scales with actual findings, not with
    everything we happen to know.

    Tries the cheap model first. If its own reported confidence is below
    0.6, escalates ONE retry to the stronger model - this is the
    "spend more only on the hard cases" behavior, not a blanket upgrade.
    """
    client = _get_client()
    # Cap evidence length sent to the model - keeps prompts small/cheap
    # and avoids wasting tokens on truncated-anyway giant tool dumps.
    capped_evidence = evidence[:2000]
    prompt = _TRIAGE_PROMPT.format(tool_name=tool_name, evidence=capped_evidence)

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
