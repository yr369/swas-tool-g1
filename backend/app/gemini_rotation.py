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

Multi-key rotation: a single Google AI Studio key already gets rotated
across every model in MODEL_ROTATION (see above), but the *key* itself
was never rotated - every call site built one genai.Client from the
single GEMINI_API_KEY env var, so a second or third free-tier key sat
unused. GEMINI_API_KEY_2, GEMINI_API_KEY_3, ... (any number, contiguous
from 2) are now auto-discovered from the environment: once the primary
key's full model rotation is exhausted, the full MODEL_ROTATION list is
retried again on each extra key, in order, before falling through to
tier-2. This is opt-in and automatic - callers don't pass anything extra;
generate_with_rotation() discovers extra keys itself unless the caller
explicitly overrides `extra_clients`. Each key's circuit-breaker state
is tracked separately (keyed by key-index:model) so one key going
quota-exhausted on a model doesn't affect another key's independent
quota bucket for that same model.

Tier 2 - non-Gemini fallback: once every model has been tried and
failed (quota exhausted or otherwise) on every Gemini key, this module
falls through to a second tier of OpenAI-compatible providers
(DeepSeek, GLM, Llama) before finally giving up. This keeps
triage/scope-parsing working on a day the whole Gemini free tier is
spent, instead of failing every finding for the rest of the day. Tier 2
is opt-in - it only activates if the relevant API key env var is set,
so a fresh install with no extra keys behaves exactly as before
(Gemini-only, raises once the rotation is exhausted). Each tier-2
provider also supports a comma-separated model fallback list (e.g.
LLAMA_MODELS) tried under that same provider's single key before moving
to the next provider - useful for NVIDIA-hosted models, where one
nvapi- key already covers multiple model slugs.
"""

import asyncio
import logging
import os
import re
import time

import httpx
from google import genai
from google.genai import errors as genai_errors

logger = logging.getLogger("swas.gemini_rotation")

_NUMBERED_KEY_RE = re.compile(r"^GEMINI_API_KEY_(\d+)$")

# Cache of already-built genai.Client objects, keyed by API key string,
# so repeated calls within a process don't rebuild a client per request.
_client_cache: dict[str, genai.Client] = {}

# Sentinel default for generate_with_rotation(extra_clients=...) meaning
# "auto-discover extra Gemini keys from the environment". A plain None
# default can't distinguish "caller explicitly disabled extra-key
# rotation" from "caller didn't pass this new argument at all" -
# existing call sites (and the manual test harness) don't pass it, and
# should get auto-discovery, not silently disabled rotation.
_AUTO_EXTRA_CLIENTS = object()


def _client_for_key(api_key: str) -> genai.Client:
    client = _client_cache.get(api_key)
    if client is None:
        client = genai.Client(api_key=api_key)
        _client_cache[api_key] = client
    return client


def _collect_extra_gemini_keys() -> list[str]:
    """Returns every GEMINI_API_KEY_<n> value found in the environment
    (n=2,3,4,... - any count, doesn't need to be contiguous), sorted by
    n, skipping blanks and skipping anything that duplicates the
    primary GEMINI_API_KEY value (a common copy-paste mistake that
    shouldn't count as a second real key)."""
    primary = os.environ.get("GEMINI_API_KEY")
    numbered: list[tuple[int, str]] = []
    for name, value in os.environ.items():
        if not value:
            continue
        m = _NUMBERED_KEY_RE.match(name)
        if m:
            numbered.append((int(m.group(1)), value))
    numbered.sort(key=lambda pair: pair[0])

    seen = {primary} if primary else set()
    extra_keys = []
    for _, value in numbered:
        if value in seen:
            continue
        seen.add(value)
        extra_keys.append(value)
    return extra_keys


def get_extra_clients() -> list[genai.Client]:
    """Builds (or reuses, via the client cache) a genai.Client for every
    extra Gemini key configured in the environment. Empty list if only
    the primary GEMINI_API_KEY is set - that's the common case and
    keeps behavior identical to before this feature existed."""
    return [_client_for_key(key) for key in _collect_extra_gemini_keys()]

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
        "name": "llama",
        # LLAMA_MODELS (preferred) can be a comma-separated fallback
        # list under the same key/base_url. LLAMA_MODEL (singular) is
        # kept as a back-compat alias for a single-model setup.
        "model_env": "LLAMA_MODELS",
        "model_env_fallback": "LLAMA_MODEL",
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
    whose API key env var isn't set. Within a provider, tries every
    model in its comma-separated model list (falling back to a single
    default model if unset) before moving to the next provider - this
    lets one NVIDIA nvapi- key cover several Llama model slugs as
    successive fallbacks. Returns (response, model_used) on first
    success, or (None, None) if none are configured/succeeded.
    """
    for provider in _TIER_2_PROVIDERS:
        api_key = os.environ.get(provider["key_env"])
        if not api_key:
            continue

        base_url = os.environ.get(provider["base_url_env"], provider["base_url_default"])
        models_raw = os.environ.get(provider["model_env"])
        if not models_raw and provider.get("model_env_fallback"):
            models_raw = os.environ.get(provider["model_env_fallback"])
        if not models_raw:
            models_raw = provider["model_default"]
        models = [m.strip() for m in models_raw.split(",") if m.strip()] or [provider["model_default"]]

        for model in models:
            try:
                text = await _call_openai_compatible(base_url, api_key, model, prompt)
                logger.info(
                    "Gemini rotation exhausted - succeeded on tier-2 provider %s (model %s)",
                    provider["name"], model,
                )
                return _TextResponse(text), model
            except Exception as exc:
                logger.warning("Tier-2 provider %s model %s failed: %s", provider["name"], model, exc)
                continue

    return None, None


async def _try_models_on_client(client, models: list[str], prompt: str, breaker_prefix: str):
    """
    Tries each model in `models` (in order) against `client`, applying
    the same retry/rotate/circuit-breaker rules as before. breaker_prefix
    namespaces the circuit-breaker state per Gemini key - "" for the
    primary key (so breaker state for it is keyed by bare model name,
    unchanged from before this function was extracted) and "gk<n>:" for
    extra key #n, so one key's 429 on a model doesn't wrongly skip a
    DIFFERENT key's independent quota bucket for that same model name.

    Returns (response, model, last_error, any_attempted). response is
    None if nothing succeeded on this client.
    """
    last_error: Exception | None = None
    any_attempted = False

    for model in models:
        breaker_key = f"{breaker_prefix}{model}"
        if _is_tripped(breaker_key):
            logger.info("Model %s in circuit-breaker cooldown, skipping without an attempt", breaker_key)
            continue

        any_attempted = True
        for attempt in range(1, _MAX_RETRIES_PER_MODEL + 1):
            try:
                response = client.models.generate_content(model=model, contents=prompt)
                if model != models[0]:
                    logger.info("Succeeded on rotated model %s", breaker_key)
                return response, model, last_error, any_attempted
            except Exception as exc:
                last_error = exc
                if _is_quota_exhausted(exc):
                    logger.warning("Model %s quota exhausted for today, rotating to next model", breaker_key)
                    _trip(breaker_key)
                    break
                elif _is_transient_server_error(exc):
                    logger.warning(
                        "Model %s transient server error (attempt %d/%d): %s",
                        breaker_key, attempt, _MAX_RETRIES_PER_MODEL, exc,
                    )
                    if attempt < _MAX_RETRIES_PER_MODEL:
                        await asyncio.sleep(_RETRY_DELAY_SECONDS * attempt)
                        continue
                    break
                else:
                    logger.warning("Model %s failed with non-retryable error: %s", breaker_key, exc)
                    break

    return None, None, last_error, any_attempted


async def _generate_with_rotation_inner(
    client: genai.Client,
    prompt: str,
    preferred_model: str | None = None,
    extra_clients: list[genai.Client] | None = _AUTO_EXTRA_CLIENTS,
):
    """
    Tries each model in MODEL_ROTATION against `client` (the primary
    Gemini key), starting from preferred_model if given. Behavior per
    error type:

    - 429 RESOURCE_EXHAUSTED: quota is genuinely used up for that model
      today - retrying it is pointless, so we move to the next model
      immediately, no delay.
    - Transient 5xx (ServerError): worth a couple of quick retries on
      the SAME model first (could just be a momentary blip), then
      rotate if it keeps failing.
    - Anything else (bad API key, malformed request, etc.): logged and
      we still try the next model, in case it's model-specific, but
      don't burn retries on the same model since the error won't change.

    If every model fails on the primary key, the SAME full model list
    is retried again on each extra Gemini key (GEMINI_API_KEY_2, _3,
    ... - each has its own independent free-tier quota) before falling
    through to tier 2 (DeepSeek / GLM / Llama via _TIER_2_PROVIDERS).
    extra_clients defaults to "auto", which discovers extra keys from
    the environment automatically (see get_extra_clients()) - pass an
    explicit list to override, or [] to disable extra-key rotation for
    this call.

    A model that's tripped the circuit breaker (see _trip/_is_tripped
    above - hit a 429 recently and hasn't cleared its cooldown yet) is
    skipped outright, without spending an attempt on it. Each Gemini
    key tracks its own breaker state independently.

    Returns (response, model_used). Raises the last error only if every
    Gemini model on every key AND every configured tier-2 provider has
    failed.
    """
    models = MODEL_ROTATION
    if preferred_model and preferred_model in models:
        start = models.index(preferred_model)
        models = models[start:] + models[:start]

    if extra_clients is _AUTO_EXTRA_CLIENTS:
        extra_clients = get_extra_clients()

    last_error: Exception | None = None
    any_attempted = False

    response, model, err, attempted = await _try_models_on_client(client, models, prompt, "")
    last_error = err or last_error
    any_attempted = any_attempted or attempted
    if response is not None:
        return response, model

    for key_index, alt_client in enumerate(extra_clients or [], start=2):
        logger.warning("Primary Gemini key exhausted, rotating to extra key #%d", key_index)
        response, model, err, attempted = await _try_models_on_client(
            alt_client, models, prompt, f"gk{key_index}:"
        )
        last_error = err or last_error
        any_attempted = any_attempted or attempted
        if response is not None:
            return response, model

    if not any_attempted:
        logger.warning("Every Gemini model/key is in circuit-breaker cooldown - going straight to tier-2")
    else:
        logger.warning("All Gemini models exhausted/failed on every configured key, trying tier-2 providers")

    response, model_used = await _generate_with_tier_2(prompt)
    if response is not None:
        return response, model_used

    if last_error is None:
        last_error = RuntimeError(
            "All Gemini models are in circuit-breaker cooldown on every configured key and no "
            "tier-2 provider is configured (or all tier-2 providers also failed)"
        )
    logger.error("All Gemini models AND all tier-2 providers exhausted/failed")
    raise last_error


# ---------------------------------------------------------------------
# Batch 25 - rate-limit budget tracking (item 2) + per-project cost/
# token tracking (item 3). Both share one mechanism: every successful
# call always increments a "global" bucket (item 2 - works for every
# existing caller automatically, nothing else to wire up) and, if the
# caller passed a tracking_key, ALSO increments that specific bucket
# (item 3 - opt-in per-project attribution). In-memory, per-process -
# same tradeoff already accepted for the circuit breaker above: resets
# on restart, which is fine for a "how much have we used today/this
# session" dashboard number, not meant as permanent billing history.
# ---------------------------------------------------------------------
_GLOBAL_USAGE_KEY = "_global"
_usage_by_key: dict[str, dict] = {}


def _record_usage(tracking_key: str | None, model: str, prompt_tokens: int, output_tokens: int, estimated: bool) -> None:
    for key in (_GLOBAL_USAGE_KEY, tracking_key):
        if key is None:
            continue
        bucket = _usage_by_key.setdefault(
            key, {"calls": 0, "prompt_tokens": 0, "output_tokens": 0, "estimated_tokens": 0, "by_model": {}}
        )
        bucket["calls"] += 1
        if estimated:
            bucket["estimated_tokens"] += prompt_tokens + output_tokens
        else:
            bucket["prompt_tokens"] += prompt_tokens
            bucket["output_tokens"] += output_tokens
        model_bucket = bucket["by_model"].setdefault(model, 0)
        bucket["by_model"][model] = model_bucket + 1


def get_usage_stats(tracking_key: str | None = None) -> dict:
    """
    Returns the usage bucket for `tracking_key` (e.g. "project:42"), or
    the GLOBAL bucket (every call from every caller, regardless of
    tracking_key) if none given - this is what the health dashboard's
    rate-limit budget view (batch 25 item 2) reads. Returns a zeroed
    bucket, never None/KeyError, for a key that hasn't seen any calls
    yet - a fresh project asking for its usage shouldn't need a
    try/except.
    """
    key = tracking_key or _GLOBAL_USAGE_KEY
    return _usage_by_key.get(
        key, {"calls": 0, "prompt_tokens": 0, "output_tokens": 0, "estimated_tokens": 0, "by_model": {}}
    )


async def generate_with_rotation(
    client: genai.Client,
    prompt: str,
    preferred_model: str | None = None,
    extra_clients: list[genai.Client] | None = _AUTO_EXTRA_CLIENTS,
    tracking_key: str | None = None,
):
    """
    Thin wrapper around _generate_with_rotation_inner (which has all the
    actual rotation/retry/circuit-breaker logic - see its docstring)
    that additionally records token usage for the batch 25 observability
    work. tracking_key is entirely optional and additive - omitting it
    (every pre-existing call site) behaves EXACTLY as before; passing
    e.g. "project:42" additionally attributes this call's usage to that
    project for the per-project cost dashboard.

    Real Gemini responses expose response.usage_metadata with real
    prompt/candidates token counts - used directly when available. The
    tier-2 fallback's _TextResponse stand-in doesn't carry token counts
    (the OpenAI-compatible providers' responses aren't parsed for usage
    here), so those calls fall back to a rough word-count-based
    estimate, clearly flagged as estimated in the returned stats rather
    than presented as if they were exact.
    """
    response, model = await _generate_with_rotation_inner(client, prompt, preferred_model, extra_clients)

    usage = getattr(response, "usage_metadata", None)
    if usage is not None and getattr(usage, "prompt_token_count", None) is not None:
        _record_usage(
            tracking_key, model,
            usage.prompt_token_count or 0,
            getattr(usage, "candidates_token_count", 0) or 0,
            estimated=False,
        )
    else:
        # Tier-2 provider or a Gemini SDK version without usage_metadata -
        # rough estimate only (~4 chars/token is the standard rule of
        # thumb), clearly marked as such in the stats bucket.
        estimated_prompt = len(prompt) // 4
        estimated_output = len(getattr(response, "text", "") or "") // 4
        _record_usage(tracking_key, model, estimated_prompt, estimated_output, estimated=True)

    return response, model
