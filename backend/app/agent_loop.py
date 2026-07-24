"""
agent_loop.py - the agentic investigation loop for logic_hunter hypotheses.

Plain-language: batch 2's "bounded auto-verification" could only ever try
ONE single unauthenticated GET, and only for the narrow slice of
hypotheses shaped like "is this exact URL reachable with no auth" - so
most hypotheses (IDOR, most business-logic claims) instantly gave up and
stayed a pure, unverified hypothesis, even when a FEW more read-only
requests could have told a human a lot more: does the claimed field even
exist in the response? does changing an ID in the URL path change
anything about the response shape, even unauthenticated? does a
documented-but-unused parameter change behavior?

This module generalizes that one bolted-on verification step into a real
multi-step agent: given a hypothesis and the target's known attack
surface, a strong model can issue up to `_MAX_STEPS` safe, read-only
probes, look at each result, and decide what to check next - then hands
back (a) an investigation summary appended to the finding's evidence,
same spirit as before, and (b) every endpoint it touched, so the caller
can write those back into the attack-surface model. That's the point
called out in the handoff notes: the agent should WRITE to the surface
model as it investigates, not just read from it - the next hypothesis on
this same target (or the next scan entirely) should benefit from what
this investigation actually learned, not just whatever detective.py/gate
happened to observe on their own separate passes.

SAFETY - this is the single most important property of this file, more
important than investigation depth or cleverness:
  - The only HTTP methods ever actually issued are GET and HEAD, and
    that choice is made IN CODE (see `_execute_tool_call` /
    `_ALLOWED_ACTIONS`), never derived from anything the model returns.
    A model asking for an action outside {get, head, compare, finish} -
    including "post", "put", "delete", or anything else - gets a plain
    tool-result string saying that action doesn't exist. It is not
    silently upgraded, downgraded, or ignored-but-attempted; no network
    call happens for it at all. See `test_agent_loop_manual.py` for a
    reproducible check of this specific property.
  - No request ever carries a cookie, Authorization header, session
    token, or any other credential - every probe this loop issues is
    fully anonymous. That matches the "single-session" limitation
    called out in the handoff doc; authenticated/multi-account testing
    is deliberately a separate, later phase (item #3) that needs its
    own explicit credential-scoping and a per-program policy check
    before it ever touches real accounts.
  - A hard step ceiling (`_MAX_STEPS`) is enforced by the Python loop
    itself, not just mentioned in the prompt - the loop physically
    cannot issue more than this many model calls or requests no matter
    what the model asks for or how the response is phrased.
  - Every probe uses the same short, fixed timeout (`_STEP_TIMEOUT`)
    used elsewhere in this codebase; a single slow/hanging endpoint
    can't stall the whole loop.
"""

import json
import logging
import os

import httpx
from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.agent_loop")

# Same strong model already used for logic_hunter's initial hypothesis
# reasoning (hunt_cluster) - this is the other half of that same
# reasoning-heavy, low-volume budget (only runs per saved hypothesis,
# capped at _MAX_STEPS calls each), so it stays on the strong model
# rather than the cheap gate-tier one the old single-GET verifier used.
_MODEL = "gemini-2.5-pro"

_MAX_STEPS = 6
_STEP_TIMEOUT = 10.0
_BODY_SAMPLE_CHARS = 800
_HISTORY_RESULT_CHARS = 500

_ALLOWED_ACTIONS = {"get", "head", "compare", "finish"}

_INTERESTING_HEADERS = (
    "content-type", "content-length", "location", "set-cookie",
    "www-authenticate", "server", "cache-control",
)

_AGENT_STEP_PROMPT = """You are investigating ONE specific security hypothesis about a target \
through a bounded, read-only agentic loop. You get up to {max_steps} total actions (this is \
action {step_num} of {max_steps}) before you must conclude either way.

Target: {target_name} ({target_type})
Attack surface context: {surface_context}

Hypothesis under investigation: {hypothesis}

Available actions - respond with ONLY one JSON object, no markdown fences, no other text:
  {{"action": "get", "url": "https://full/url", "why": "one short phrase"}}
  {{"action": "head", "url": "https://full/url", "why": "one short phrase"}}
  {{"action": "compare", "url_a": "https://...", "url_b": "https://...", "why": "one short phrase"}}
  {{"action": "finish", "conclusion": "one paragraph: what the probes actually showed and whether \
they support, weaken, or are inconclusive about the hypothesis - be specific about what was and \
wasn't confirmed", "confidence": 0.0}}

Rules:
- Every request is ANONYMOUS - no cookies, no auth headers, no session. This loop can only test \
what an unauthenticated, single-session attacker could see. If the hypothesis genuinely requires \
comparing two different authenticated accounts, say so plainly in "finish" rather than treating an \
anonymous probe as having settled it either way.
- Only GET/HEAD exist - there is no state-changing action in this loop at all; asking for one just \
wastes a step, it will not be executed.
- Prefer 'compare' over two separate 'get's when you specifically want to know whether changing one \
thing (an ID, a parameter value) changes the response - it's cheaper and the diff is computed for you.
- Call 'finish' as soon as you have enough signal either way - do not pad out to {max_steps} steps \
out of habit. Most real investigations conclude in 2-4 steps.
- confidence in 'finish' means "how confident are you in the CONCLUSION you just wrote" - a confident \
refutation is just as valid an outcome as a confident confirmation.

Investigation so far:
{history_block}

What do you do next?
"""

_FORCE_CONCLUDE_PROMPT = """Your investigation budget is exhausted ({max_steps} actions used). \
Based on everything below, respond with ONLY this JSON now - no other action is available:
  {{"conclusion": "one paragraph summarizing what the probes showed and whether they support, \
weaken, or are inconclusive about the hypothesis", "confidence": 0.0}}

Target: {target_name} ({target_type})
Hypothesis: {hypothesis}

Investigation so far:
{history_block}
"""


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_json_response(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


def _summarize_headers(headers: httpx.Headers) -> str:
    parts = []
    for name in _INTERESTING_HEADERS:
        value = headers.get(name)
        if value:
            parts.append(f"{name}={value[:120]}")
    return "; ".join(parts) if parts else "(no notable headers)"


def _record_endpoint(endpoints_seen: list[dict], url: str, status_code: int | None) -> None:
    endpoints_seen.append({
        "url": url,
        "source": "logic_hunter_agent",
        "is_live": status_code is not None,
        "status_code": status_code,
    })


async def _do_get(url: str, endpoints_seen: list[dict]) -> str:
    if not url or not url.startswith(("http://", "https://")):
        return "Invalid or missing URL - must be a full http(s) URL. No request sent."
    try:
        async with httpx.AsyncClient(timeout=_STEP_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)  # GET hardcoded - never derived from model output
    except httpx.HTTPError as exc:
        _record_endpoint(endpoints_seen, url, None)
        return f"GET {url} failed: {exc}"

    _record_endpoint(endpoints_seen, url, resp.status_code)
    body_sample = resp.text[:_BODY_SAMPLE_CHARS]
    return (
        f"GET {url} -> {resp.status_code}, {len(resp.content)} bytes. "
        f"Headers: {_summarize_headers(resp.headers)}. Body sample: {body_sample!r}"
    )


async def _do_head(url: str, endpoints_seen: list[dict]) -> str:
    if not url or not url.startswith(("http://", "https://")):
        return "Invalid or missing URL - must be a full http(s) URL. No request sent."
    try:
        async with httpx.AsyncClient(timeout=_STEP_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.head(url)  # HEAD hardcoded - never derived from model output
    except httpx.HTTPError as exc:
        _record_endpoint(endpoints_seen, url, None)
        return f"HEAD {url} failed: {exc}"

    _record_endpoint(endpoints_seen, url, resp.status_code)
    return f"HEAD {url} -> {resp.status_code}. Headers: {_summarize_headers(resp.headers)}"


async def _do_compare(url_a: str, url_b: str, endpoints_seen: list[dict]) -> str:
    if not url_a or not url_b:
        return "compare requires both url_a and url_b. No requests sent."
    result_a = await _do_get(url_a, endpoints_seen)
    result_b = await _do_get(url_b, endpoints_seen)
    return f"A) {result_a}\nB) {result_b}"


async def _execute_tool_call(action: dict, endpoints_seen: list[dict]) -> str:
    """
    The enforcement point. `action` is untrusted model output - only the
    four literal strings in _ALLOWED_ACTIONS ever cause a real HTTP call,
    and get/head/compare each hardcode their own method (see _do_get/
    _do_head above). Anything else - a typo, an attempt to smuggle a
    different method in via the "action" field, an unrecognized shape -
    falls straight into the else branch below and issues no request.
    """
    action_type = action.get("action") if isinstance(action, dict) else None
    if action_type not in _ALLOWED_ACTIONS or action_type == "finish":
        return (
            f"Action '{action_type}' is not available in this loop - only get, head, "
            f"and compare issue requests (finish ends the loop). No request was sent."
        )
    if action_type == "get":
        return await _do_get(action.get("url", ""), endpoints_seen)
    if action_type == "head":
        return await _do_head(action.get("url", ""), endpoints_seen)
    return await _do_compare(action.get("url_a", ""), action.get("url_b", ""), endpoints_seen)


def _render_history_block(history: list[dict]) -> str:
    if not history:
        return "(nothing yet - this is the first action)"
    lines = []
    for i, entry in enumerate(history, start=1):
        action_desc = json.dumps(entry["action"])[:200]
        result = (entry["result"] or "")[:_HISTORY_RESULT_CHARS]
        lines.append(f"Step {i}: action={action_desc}\n  result: {result}")
    return "\n".join(lines)


async def _force_conclude(client: genai.Client, hypothesis: str, target_name: str,
                           target_type: str, history: list[dict]) -> tuple[str | None, float | None]:
    prompt = _FORCE_CONCLUDE_PROMPT.format(
        max_steps=_MAX_STEPS, target_name=target_name, target_type=target_type,
        hypothesis=hypothesis[:2000], history_block=_render_history_block(history),
    )
    try:
        response, _ = await generate_with_rotation(client, prompt, preferred_model=_MODEL)
        parsed = _parse_json_response(response.text or "")
        return parsed.get("conclusion"), parsed.get("confidence")
    except Exception as exc:
        logger.info("agent_loop: forced-conclude call failed: %s", exc)
        return None, None


def _render_summary(conclusion: str | None, confidence, steps_taken: int, history: list[dict]) -> str:
    conf_str = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "unknown"
    steps_desc = "; ".join(
        f"step {i}: {entry['action'].get('action') if isinstance(entry['action'], dict) else '?'}"
        for i, entry in enumerate(history, start=1)
    ) or "(no steps taken)"
    return (
        f"[agentic investigation: {steps_taken} step(s) taken, concluding confidence={conf_str}]\n"
        f"{conclusion or '(automated summarization did not produce a conclusion - review the raw steps manually)'}\n"
        f"Steps: {steps_desc}"
    )


async def investigate(hypothesis: str, target_name: str, target_type: str | None,
                       surface_context: str) -> dict:
    """
    Runs the bounded multi-step loop for one hypothesis. Returns:
      {"summary": str,              - evidence-appendix text, same role the old
                                       single-GET verification note played
       "steps_taken": int,
       "endpoints_touched": list[dict]}  - {url, source, is_live, status_code} per
                                            probe, for the caller to upsert into
                                            attack_surface_endpoints

    Never raises - any failure (model error, malformed JSON, etc.) ends
    the loop early with whatever was learned so far rather than losing
    the whole investigation.
    """
    client = _get_client()
    history: list[dict] = []
    endpoints_seen: list[dict] = []
    conclusion: str | None = None
    confidence = None
    steps_taken = 0

    for step_num in range(1, _MAX_STEPS + 1):
        steps_taken = step_num
        prompt = _AGENT_STEP_PROMPT.format(
            max_steps=_MAX_STEPS, step_num=step_num, target_name=target_name,
            target_type=target_type or "website", surface_context=surface_context,
            hypothesis=hypothesis[:2000], history_block=_render_history_block(history),
        )
        try:
            response, _ = await generate_with_rotation(client, prompt, preferred_model=_MODEL)
            action = _parse_json_response(response.text or "")
        except Exception as exc:
            logger.info("agent_loop: step %s reasoning failed, ending investigation: %s", step_num, exc)
            break

        if isinstance(action, dict) and action.get("action") == "finish":
            conclusion = action.get("conclusion")
            confidence = action.get("confidence")
            history.append({"action": action, "result": "(investigation concluded)"})
            break

        result = await _execute_tool_call(action if isinstance(action, dict) else {}, endpoints_seen)
        history.append({"action": action if isinstance(action, dict) else {"action": "invalid"}, "result": result})

    if conclusion is None:
        conclusion, confidence = await _force_conclude(client, hypothesis, target_name, target_type or "website", history)

    return {
        "summary": _render_summary(conclusion, confidence, steps_taken, history),
        "steps_taken": steps_taken,
        "endpoints_touched": endpoints_seen,
    }
