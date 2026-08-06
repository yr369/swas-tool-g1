"""
policy_gate.py - turns a program's pasted scope/policy document into a
structured list of what THAT program specifically excludes, and formats
it for injection into triage.py's prompt.

Why this exists separately from triage.py's existing generic
policy-exclusion guidance (see _TRIAGE_PROMPT): that guidance is real
and correct bug-bounty-industry-standard knowledge (DoS, self-XSS, open
redirects alone, etc. are USUALLY excluded everywhere) - but "usually"
isn't "always", and programs vary. A check across production data
during batch work on this tool found the impact-hint scorer working
correctly but starved of real outcome data to validate against; a
program-specific override on top of the already-good generic guidance
is a more direct lever than more scanner tuning; that's the origin of
this module. Pasting a program's actual policy text once lets its real,
specific rules augment (not replace) the generic guidance every finding
already gets judged against.

Fails open throughout: any parse failure returns [] (no exclusions
added, existing behavior unchanged) rather than raising - a broken
Gemini call must never block triage or scanning, same principle as
gate.py and fp_filter.py.
"""

import json
import logging
import os

from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.policy_gate")

_CHEAP_MODEL = "gemini-2.0-flash"

_PARSE_PROMPT = """You are extracting bug bounty program policy rules from a pasted \
scope/policy document. Identify every vulnerability category or finding type this \
SPECIFIC program explicitly excludes, treats as out-of-scope, or says it will not \
reward - including anything unusual that differs from typical bug bounty norms.

Policy document (may be partial, informally written, or a raw copy-paste from a \
program page - work with what's given):
---
{raw_text}
---

Respond with ONLY a JSON array, no other text, no markdown fences. Each element:
{{"category": "short name of the excluded finding type, e.g. \\"self-XSS\\" or \\"rate limiting\\"", \
"reason": "one sentence, quoting or closely paraphrasing what the policy actually says about it"}}

If the document explicitly says it WILL reward something usually excluded elsewhere \
(e.g. "we do pay for confirmed DoS with PoC"), include that too with \
"category": "ALLOWED: <thing>" so triage knows to treat it as an override, not an \
exclusion. If the document has no clear exclusions or you can't find any, respond \
with an empty JSON array: []
"""


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


async def parse_policy_exclusions(raw_text: str) -> list[dict]:
    """
    Calls Gemini once to extract structured exclusions from a pasted
    policy document. Returns [] on any failure (empty input, API error,
    malformed JSON) - callers should treat [] as "nothing to add" and
    proceed exactly as if this module didn't exist, not as an error
    that needs surfacing every time.
    """
    text = (raw_text or "").strip()
    if not text:
        return []

    client = _get_client()
    prompt = _PARSE_PROMPT.format(raw_text=text[:8000])  # cap - policy pages can be long, this is plenty for exclusion lists

    try:
        response, _model_used = await generate_with_rotation(client, prompt, preferred_model=_CHEAP_MODEL)
        parsed = json.loads((response.text or "").strip().strip("`").removeprefix("json").strip())
        if not isinstance(parsed, list):
            logger.warning("Policy parse returned non-list JSON, discarding: %r", parsed)
            return []
        cleaned = [
            {"category": str(item.get("category", "")).strip(), "reason": str(item.get("reason", "")).strip()}
            for item in parsed
            if isinstance(item, dict) and item.get("category")
        ]
        return cleaned
    except Exception:
        logger.exception("Policy exclusion parse failed - proceeding with no program-specific overrides")
        return []


def format_policy_context(exclusions: list[dict] | None) -> str:
    """
    Formats parsed exclusions into a prompt block for triage.py, same
    pattern as _format_outcome_context there. Returns "" for None/empty
    (the realistic case for most projects, which haven't had a policy
    pasted in) - the prompt reads naturally without this section rather
    than referencing an empty list.
    """
    if not exclusions:
        return ""

    lines = []
    for item in exclusions:
        category = item.get("category", "")
        reason = item.get("reason", "")
        if not category:
            continue
        lines.append(f"- {category}: {reason}" if reason else f"- {category}")

    if not lines:
        return ""

    return (
        "\nThis specific program's own published policy adds the following - these are "
        "REAL rules from THIS program, not general bug-bounty norms, and take precedence "
        "over the general guidance above where they conflict. Anything prefixed "
        "\"ALLOWED:\" means this program explicitly WILL reward that category despite it "
        "being commonly excluded elsewhere - do not downgrade severity for those:\n"
        + "\n".join(lines) + "\n"
    )
