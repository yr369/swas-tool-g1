"""
gemini_rotation.py - shared model-rotation logic for every AI call in SWAS.

Why this exists: Google's free tier caps each MODEL at its own small
daily quota (e.g. 20 requests/day for gemini-2.5-flash). That's easy to
blow through mid-scan on a real project. The fix isn't retrying the same
model harder - a 429 RESOURCE_EXHAUSTED will just fail again immediately.
The fix is rotating to a different model name, because each model has
its own independent free-tier quota bucket. This module is the one place
that rotation logic lives, so triage.py and scope_parser.py (and
anything added later) share the exact same behavior instead of drifting
out of sync.

Import note: 429 RESOURCE_EXHAUSTED comes back from the SDK as a
genai_errors.ClientError, NOT a ServerError. The previous retry code in
both files only caught ServerError (503/UNAVAILABLE), so quota errors
were falling straight through to the generic except-and-fail path -
that's the actual bug this module fixes, not just an enhancement.

Tier 2 - non-Gemini fallback: once every model in MODEL_ROTATION has
been tried and failed (quota exhausted or otherwise), this module falls
through to a second tier of OpenAI-compatible providers (DeepSeek, GLM)
before finally giving up. This keeps triage/scope-parsing working on a
day the whole Gemini free tier is spent, instead of failing every
finding for the rest of the day. Tier 2 is opt-in - it only activates if
the relevant API key env var is set, so a fresh install with no extra
keys behaves exactly as before (Gemini-only, raises once the rotation
is exhausted).
"""

import asyncio
import logging
import os
import time

import httpx
from google import genai
from google.genai import errors as genai_errors

logger = logging.getLogger("swas.gemini_rotation")

# Circuit breaker: generate_with_rotation() used to restart from
# MODEL_ROTATION[0] (or preferred_model) on EVERY call, so once a model
# hits its daily 429 quota, every subsequent call for the rest of the
# day still burns a real request on it before rotating past it - wasted
# latency at scale, and on a busy day it's most of the models most of
# the time. This tracks which models are known-exhausted (per-process,
# in-memory - resets on container restart, which is fine since a
# restart is a reasonable point to give a model another chance anyway)
# and skips them outright until the cooldown elapses. Default 6h: long
# enough to stop hammering a genuinely exhausted model, short enough
# that it doesn't stay skipped long past whenever Google's quota
# actually resets (which isn't a fixed, documented time SWAS can rely
# on). Override with GEMINI_MODEL_COOLDOWN_SECONDS if needed.
_MODEL_COOLDOWN_SECONDS = int(os.environ.get("GEMINI_MODEL_COOLDOWN_SECONDS", str(6 * 3600)))

_tripped_models: dict[str, float] = {}


def _is_tripped(model: str) -> bool:
    """True if `model` is currently in its cooldown window. Clears the
    trip and returns False once the cooldown has elapsed, so a model
    isn't skipped forever after one bad day."""
    tripped_at = _tripped_models.get(model)
    if tripped_at is None:
        return False
    if time.monotonic() - tripped_at >= _MODEL_COOLDOWN_SECONDS:
        del _tripped_models[model]
        return False
    return True


def _trip(model: str) -> None:
    _tripped_models[model] = time.monotonic()
    logger.warning(
        "Circuit breaker: model %s quota-exhausted, skipping it for %ds (until cooldown elapses)",
        model, _MODEL_COOLDOWN_SECONDS,
    )


def get_circuit_breaker_status() -> dict[str, float]:
    """Returns {model: seconds_remaining_in_cooldown} for every
    currently-tripped model. Used by the health dashboard; also handy
    for debugging why rotation is jumping straight to tier-2."""
    now = time.monotonic()
    return {
        model: max(0.0, _MODEL_COOLDOWN_SECONDS - (now - tripped_at))
        for model, tripped_at in _tripped_models.items()
        if _is_tripped(model)
    }


def _reset_circuit_breaker_for_tests() -> None:
    """Test-only helper - clears all trip state. Not called from
    production code paths."""
    _tripped_models.clear()

# Ordered cheapest/fastest -> most capable. Rotation tries them in this
# order (starting from a caller-preferred model if given). Free-tier
# availability changes on Google's side periodically - if a model here
# stops existing or stops being free, just edit this list, nothing else
# needs to change.
#
# As of July 2026: gemini-1.5-flash is fully shut down (404s on every
# call - confirmed live). gemini-2.0-flash passed its own June 1, 2026
# shutdown date and is on borrowed time (still answering with quota
# errors as of this edit, but liable to 404 at any point without
# further notice) - both removed. gemini-3.1-flash-lite and
# gemini-3.5-flash added: neither has an announced shutdown date yet,
# per https://ai.google.dev/gemini-api/docs/deprecations. The 2.5
# family stays in rotation too - it doesn't shut down until Oct 16,
# 2026, still months out - but don't be surprised if this list needs
# another pass before then.
MODEL_ROTATION = [
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash",
    "gemini-2.5-pro",
]

_MAX_RETRIES_PER_MODEL = 2
_RETRY_DELAY_SECONDS = 3


def _is_quota_exhausted(exc: Exception) -> bool:
    """
    True for a 429 RESOURCE_EXHAUSTED - the free-tier quota error -
    as opposed to some other client error (bad request, bad API key)
    that switching models won't fix.
    """
    if isinstance(exc, genai_errors.ClientError):
        code = getattr(exc, "code", None)
        status = str(getattr(exc, "status", "") or "")
        message = str(exc)
        return code == 429 or "RESOURCE_EXHAUSTED" in status or "RESOURCE_EXHAUSTED" in message
    return False


def _is_transient_server_error(exc: Exception) -> bool:
    return isinstance(exc, genai_errors.ServerError)


class _TextResponse:
    """
    Minimal stand-in for the google-genai response object. Every call
    site in this codebase only ever reads `response.text`, so this is
    the entire surface area tier-2 providers need to satisfy to be a
    drop-in replacement - triage.py and scope_parser.py don't need to
    know or care which provider actually answered.
    """

    def __init__(self, text: str):
        self.text = text


# Tier 2: OpenAI-compatible providers tried (in this order) only after
# every model in MODEL_ROTATION has failed. Each entry is opt-in - it's
# skipped unless its api_key env var is actually set, so installs
# without these keys behave exactly as before.
#
# Both model slugs use the "org/model" naming convention OpenRouter
# uses, so that's the default base_url. If you're calling DeepSeek or
# Zhipu (GLM) directly instead of through OpenRouter, override the
# base_url/model/key env vars below to match that provider's own API.
_TIER_2_PROVIDERS = [
    {
        "name": "deepseek-v4-flash",
        "model_env": "DEEPSEEK_MODEL",
        "model_default": "deepseek-ai/deepseek-v4-flash",
        "key_env": "DEEPSEEK_API_KEY",
        "base_url_env": "DEEPSEEK_BASE_URL",
        "base_url_default": "https://openrouter.ai/api/v1",
    },
    {
        "name": "glm-5.2",
        "model_env": "GLM_MODEL",
        "model_default": "z-ai/glm-5.2",
        "key_env": "GLM_API_KEY",
        "base_url_env": "GLM_BASE_URL",
        "base_url_default": "https://openrouter.ai/api/v1",
    },
    {
        "name": "llama-3.3-70b-instruct",
        "model_env": "LLAMA_MODEL",
        "model_default": "meta/llama-3.3-70b-instruct",
        "key_env": "LLAMA_API_KEY",
        "base_url_env": "LLAMA_BASE_URL",
        "base_url_default": "https://openrouter.ai/api/v1",
    },
]

_TIER_2_TIMEOUT_SECONDS = 60


async def _call_openai_compatible(base_url: str, api_key: str, model: str, prompt: str) -> str:
    """
    One-shot chat-completion call against an OpenAI-compatible endpoint
    (OpenRouter, or a provider's own direct API if it speaks the same
    /chat/completions shape). Raises on any HTTP error or malformed
    response - the caller decides whether to move to the next provider.
    """
    async with httpx.AsyncClient(timeout=_TIER_2_TIMEOUT_SECONDS) as http_client:
        resp = await http_client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"] or ""


async def _generate_with_tier_2(prompt: str):
    """
    Tries each configured tier-2 provider in order. Skips any provider
    whose API key env var isn't set. Returns (response, model_used) on
    first success, or (None, None) if none are configured/succeeded.
    """
    for provider in _TIER_2_PROVIDERS:
        api_key = os.environ.get(provider["key_env"])
        if not api_key:
            continue

        model = os.environ.get(provider["model_env"], provider["model_default"])
        base_url = os.environ.get(provider["base_url_env"], provider["base_url_default"])

        try:
            text = await _call_openai_compatible(base_url, api_key, model, prompt)
            logger.info("Gemini rotation exhausted - succeeded on tier-2 provider %s", provider["name"])
            return _TextResponse(text), model
        except Exception as exc:
            logger.warning("Tier-2 provider %s failed: %s", provider["name"], exc)
            continue

    return None, None


async def generate_with_rotation(
    client: genai.Client,
    prompt: str,
    preferred_model: str | None = None,
):
    """
    Tries each model in MODEL_ROTATION, starting from preferred_model if
    given (falls back to rotation order if preferred_model isn't in the
    list). Behavior per error type:

    - 429 RESOURCE_EXHAUSTED: quota is genuinely used up for that model
      today - retrying it is pointless, so we move to the next model
      immediately, no delay.
    - Transient 5xx (ServerError): worth a couple of quick retries on
      the SAME model first (could just be a momentary blip), then
      rotate if it keeps failing.
    - Anything else (bad API key, malformed request, etc.): logged and
      we still try the next model, in case it's model-specific, but
      don't burn retries on the same model since the error won't change.

    Once every Gemini model has failed, falls through to tier 2
    (DeepSeek / GLM via _TIER_2_PROVIDERS) before giving up entirely.

    A model that's tripped the circuit breaker (see _trip/_is_tripped
    above - hit a 429 recently and hasn't cleared its cooldown yet) is
    skipped outright, without spending an attempt on it.

    Returns (response, model_used). Raises the last error only if every
    Gemini model AND every configured tier-2 provider has failed.
    """
    models = MODEL_ROTATION
    if preferred_model and preferred_model in models:
        start = models.index(preferred_model)
        models = models[start:] + models[:start]

    last_error: Exception | None = None
    any_attempted = False

    for model in models:
        if _is_tripped(model):
            logger.info("Model %s in circuit-breaker cooldown, skipping without an attempt", model)
            continue

        any_attempted = True
        for attempt in range(1, _MAX_RETRIES_PER_MODEL + 1):
            try:
                response = client.models.generate_content(model=model, contents=prompt)
                if model != models[0]:
                    logger.info("Succeeded on rotated model %s", model)
                return response, model
            except Exception as exc:
                last_error = exc
                if _is_quota_exhausted(exc):
                    logger.warning("Model %s quota exhausted for today, rotating to next model", model)
                    _trip(model)
                    break
                elif _is_transient_server_error(exc):
                    logger.warning(
                        "Model %s transient server error (attempt %d/%d): %s",
                        model, attempt, _MAX_RETRIES_PER_MODEL, exc,
                    )
                    if attempt < _MAX_RETRIES_PER_MODEL:
                        await asyncio.sleep(_RETRY_DELAY_SECONDS * attempt)
                        continue
                    break
                else:
                    logger.warning("Model %s failed with non-retryable error: %s", model, exc)
                    break

    if not any_attempted:
        logger.warning("Every Gemini model is in circuit-breaker cooldown - going straight to tier-2")
    else:
        logger.warning("All Gemini models exhausted/failed, trying tier-2 providers: %s", models)

    response, model_used = await _generate_with_tier_2(prompt)
    if response is not None:
        return response, model_used

    if last_error is None:
        last_error = RuntimeError(
            "All Gemini models are in circuit-breaker cooldown and no tier-2 provider "
            "is configured (or all tier-2 providers also failed)"
        )
    logger.error("All Gemini models AND all tier-2 providers exhausted/failed")
    raise last_error
