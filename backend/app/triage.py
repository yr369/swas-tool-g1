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

import json
import logging
import os

from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.triage")

_CHEAP_MODEL = "gemini-2.5-flash"
_ESCALATION_MODEL = "gemini-2.5-pro"

_TRIAGE_PROMPT = """You are triaging a security finding from an automated \
bug bounty scan. Assign a severity and a confidence score.

Tool: {tool_name}
Evidence (raw tool output, may contain multiple lines):
---
{evidence}
---
{outcome_context}{vrt_context}
Respond with ONLY a JSON object, no other text, no markdown fences:
{{"severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "one sentence", "vrt_category": "closest matching VRT category name or null"}}

Guidance: missing security headers, generic fingerprinting (server/version
detection), and DNS records are almost always "info". Known CVEs with
confirmed version matches are at least "medium", often "high". Anything
suggesting actual exploitability (working SQLi, XSS execution, auth
bypass) is "high" or "critical". If you are NOT confident in this
classification (the evidence is ambiguous, contradictory, or you're
guessing), set confidence below 0.6 - this is expected and fine, it
routes the finding to a closer look rather than forcing a bad guess.

SSL/TLS/certificate findings (weak ciphers, self-signed or expired
certs, missing HSTS/CSP, protocol version warnings, and similar scanner
output) are ALWAYS "info", high confidence (0.9+), and should NOT be
escalated - mature programs consistently close these as Informational
or Not Applicable unless paired with a demonstrated exploit. Treat the
certificate/TLS data as reconnaissance (it can reveal org names,
internal hostnames, or infrastructure) rather than as a reportable
vulnerability in its own right - say so in "reasoning" rather than
inventing a higher severity.

If the evidence mentions or the target hostname suggests Adobe
Experience Manager (AEM), note in "reasoning" that this is worth manual
follow-up on AEM-specific attack surface (dispatcher config exposure,
default admin interfaces like /crx/de, SSRF via AEM), not just the raw
scanner line - but still classify the raw scanner output itself by its
own actual severity, don't inflate it just because AEM was mentioned.
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


def _parse_triage_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def triage_finding(
    tool_name: str, evidence: str, outcome_stats: dict | None = None, vrt_entries: list[dict] | None = None
) -> dict:
    """
    Returns {"severity": str, "confidence": float, "reasoning": str,
    "vrt_category": str|None, "model_used": str}. Token budget is kept
    small on purpose - evidence is capped, and we send one finding at a
    time rather than dumping unrelated context, so cost scales with
    actual findings, not with everything we happen to know.

    outcome_stats (optional): aggregated past-outcome history for this
    finding's signature, from finding_outcomes via get_signature_stats().
    When provided and non-empty, it's woven into the prompt as real
    context - this is the actual "learns from mistakes" mechanism. When
    absent (a brand-new pattern with no history), triage proceeds exactly
    as before with no behavior change.

    vrt_entries (optional): Bugcrowd's real VRT categories (from vrt.py),
    given to the model so it can name the closest matching Bugcrowd
    category - grounding our generic severity scale in Bugcrowd's actual
    scoring language, not just our own words.

    Tries the cheap model first. If its own reported confidence is below
    0.6, escalates ONE retry to the stronger model - this is the
    "spend more only on the hard cases" behavior, not a blanket upgrade.
    """
    client = _get_client()
    # Cap evidence length sent to the model - keeps prompts small/cheap
    # and avoids wasting tokens on truncated-anyway giant tool dumps.
    capped_evidence = evidence[:2000]
    outcome_context = _format_outcome_context(outcome_stats)
    from . import vrt as vrt_module  # local import avoids a circular import at module load time
    vrt_context = vrt_module.format_vrt_context(vrt_entries or [])
    prompt = _TRIAGE_PROMPT.format(
        tool_name=tool_name, evidence=capped_evidence,
        outcome_context=outcome_context, vrt_context=vrt_context,
    )

    try:
        # generate_with_rotation tries _CHEAP_MODEL first, then rotates
        # through the rest of MODEL_ROTATION automatically if it hits a
        # 429 quota error - so a single exhausted free-tier model no
        # longer kills triage for the rest of the scan.
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_CHEAP_MODEL)
        result = _parse_triage_response(response.text or "")
        result["model_used"] = model_used
    except Exception as exc:
        logger.exception("Triage failed on every model in the rotation")
        return {"severity": "unknown", "confidence": 0.0, "reasoning": f"Triage failed: {exc}", "model_used": "none"}

    if result.get("confidence", 1.0) < 0.6:
        logger.info("Low confidence (%.2f) on %s, escalating", result.get("confidence", 0), result["model_used"])
        try:
            # Escalation also rotates, starting from the pro model, so an
            # exhausted pro quota falls back through the rest of the
            # chain rather than giving up after one try.
            response, escalation_model_used = await generate_with_rotation(
                client, prompt, preferred_model=_ESCALATION_MODEL
            )
            escalated = _parse_triage_response(response.text or "")
            escalated["model_used"] = escalation_model_used
            return escalated
        except Exception as exc:
            logger.warning("Escalation failed on every model, keeping first-pass result: %s", exc)
            # Fall back to the first-pass result rather than losing the
            # finding entirely - a low-confidence guess is still more
            # useful than nothing, and it's clearly labeled as such.
            return result

    return result
