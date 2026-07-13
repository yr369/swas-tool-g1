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

import httpx
from google import genai
from google.genai import errors as genai_errors

logger = logging.getLogger("swas.gemini_rotation")

# Ordered cheapest/fastest -> most capable. Rotation tries them in this
# order (starting from a caller-preferred model if given). Free-tier
# availability changes on Google's side periodically - if a model here
# stops existing or stops being free, just edit this list, nothing else
# needs to change.
MODEL_ROTATION = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.5-flash-lite",
    "gemini-1.5-flash",
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

    Returns (response, model_used). Raises the last error only if every
    Gemini model AND every configured tier-2 provider has failed.
    """
    models = MODEL_ROTATION
    if preferred_model and preferred_model in models:
        start = models.index(preferred_model)
        models = models[start:] + models[:start]

    last_error: Exception | None = None

    for model in models:
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

    logger.warning("All Gemini models exhausted/failed, trying tier-2 providers: %s", models)

    response, model_used = await _generate_with_tier_2(prompt)
    if response is not None:
        return response, model_used

    logger.error("All Gemini models AND all tier-2 providers exhausted/failed")
    raise last_error
