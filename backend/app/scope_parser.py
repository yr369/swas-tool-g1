"""
scope_parser.py - uses the Gemini API to turn loosely-structured scope text
(pasted from a Bugcrowd/HackerOne program page, or extracted from an
uploaded file) into a normalized list of targets.

Plain-language explanation: a bug bounty program's scope is usually just
a block of text or a table on a webpage - "example.com and all subdomains
are in scope, *.internal.example.com is NOT in scope, mobile app coming
soon" - not a clean structured format. This module asks Gemini to read
that messy text and turn it into a clean, consistent list our database can
actually use. The operator ALWAYS reviews this list before anything is
saved - Gemini's output here is a draft, never the final word.
"""

import json
import logging
import os

from google import genai

from .models import ParsedScopeItem

logger = logging.getLogger("swas.scope_parser")

_PROMPT_TEMPLATE = """You are helping parse a bug bounty program's scope \
definition into a structured format. The program is on the "{platform}" \
platform.

Read the following raw scope text and extract EVERY target mentioned, \
whether in-scope or explicitly out-of-scope. Be thorough - don't skip \
targets just because they look minor.

For each target, determine:
- "target": the actual domain, URL, app identifier, or asset name
- "target_type": one of "website", "api", "mobile", "hardware", "unknown"
- "in_scope": true if the program includes it as testable, false if it is
  explicitly excluded
- "reward_range": the bounty reward range for this target if stated
  (e.g. "$100-$500"), otherwise null
- "notes": anything important about this target (e.g. "wildcard subdomain",
  "requires special test account", "read-only testing only"), otherwise null

IMPORTANT: If something looks like it might be a mobile app identifier
(e.g. a package name like "com.company.app", or an App Store/Play Store
ID), still include it as a normal entry with target_type "mobile" -
do NOT silently omit it. The operator needs to see every target, even
ones the system is unsure about classifying.

Respond with ONLY a JSON array, no other text, no markdown formatting,
no code fences. Each element must match this exact shape:
{{"target": "...", "target_type": "...", "in_scope": true, "reward_range": null, "notes": null}}

Raw scope text:
---
{raw_text}
---
"""


def _get_client() -> genai.Client:
    api_key = os.environ["GEMINI_API_KEY"]
    return genai.Client(api_key=api_key)


async def parse_scope_text(platform: str, raw_text: str) -> list[ParsedScopeItem]:
    """
    Sends raw scope text to Gemini and returns a list of validated
    ParsedScopeItem objects. Raises ValueError with a clear message if
    Gemini's response can't be parsed - the caller (the API endpoint)
    is responsible for turning that into a clean error for the operator,
    rather than this function ever returning a guessed/fabricated result.
    """
    if not raw_text.strip():
        raise ValueError("No scope text provided to parse")

    client = _get_client()
    prompt = _PROMPT_TEMPLATE.format(platform=platform, raw_text=raw_text.strip())

    try:
        response = client.models.generate_content(
            model="gemini-flash-latest",
            contents=prompt,
        )
    except Exception as exc:
        logger.exception("Gemini API call failed during scope parsing")
        raise ValueError(f"Could not reach the AI parser: {exc}") from exc

    raw_response_text = (response.text or "").strip()

    # Gemini occasionally wraps JSON in markdown code fences despite being
    # asked not to - strip those defensively rather than failing on them.
    if raw_response_text.startswith("```"):
        raw_response_text = raw_response_text.strip("`")
        if raw_response_text.startswith("json"):
            raw_response_text = raw_response_text[4:].strip()

    try:
        parsed_json = json.loads(raw_response_text)
    except json.JSONDecodeError as exc:
        logger.error("Gemini returned non-JSON output: %s", raw_response_text[:500])
        raise ValueError(
            "The AI parser's response could not be understood. This can "
            "happen with unusual scope text - try simplifying it or "
            "entering targets manually."
        ) from exc

    if not isinstance(parsed_json, list):
        raise ValueError("The AI parser's response was not a list of targets as expected")

    items: list[ParsedScopeItem] = []
    for raw_item in parsed_json:
        try:
            items.append(ParsedScopeItem(**raw_item))
        except Exception as exc:
            # One malformed item shouldn't discard everything else Gemini
            # got right - log it and skip just that item.
            logger.warning("Skipping one malformed scope item: %s (%s)", raw_item, exc)

    if not items:
        raise ValueError(
            "The AI parser could not extract any valid targets from this "
            "text - try entering targets manually instead."
        )

    return items
