"""
gemini_rotation.py - shared model-rotation logic for every Gemini API call
in SWAS.

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
"""

import asyncio
import logging

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

    Returns (response, model_used). Raises the last error only if every
    model in the rotation has failed.
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

    logger.error("All models in rotation exhausted/failed: %s", models)
    raise last_error
