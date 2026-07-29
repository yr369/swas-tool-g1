"""
error_taxonomy.py - one shared error_type classification for every phase
failure in the pipeline.

Why this exists: phase_runs.error_message has always existed, but it's a
free-text string - answering "how many scans failed because of Gemini
quota this week vs a broken target vs a DB hiccup" meant grepping
error_message for substrings and hoping the wording never drifted. This
gives every failure ONE canonical error_type from a fixed, small set, so
that question becomes a GROUP BY instead.

classify_error() is the single function checkpoint.py's run_phase calls
on every caught exception. Ordering is deliberate: more specific checks
(AuthPolicyError, a genai quota error, a timeout) run before generic
fallbacks (bare OSError/Exception -> broader buckets), since a broad
isinstance check would otherwise shadow the more specific subclass a
caller actually wants to distinguish.
"""

import asyncio
import json as _json

# The fixed taxonomy. Keep this list small and stable - it's meant to be
# GROUP-BY-able, not a place to describe every possible failure in
# detail (that's still what error_message is for).
ERROR_TYPES = [
    "ai_quota_exhausted",   # every Gemini model + all tier-2 providers exhausted/unconfigured
    "ai_provider_error",    # a Gemini/tier-2 call failed for a reason OTHER than quota
    "db_error",             # Postgres/asyncpg error
    "network_timeout",      # a subprocess tool or HTTP call timed out
    "network_error",        # connection refused/reset, DNS failure, etc.
    "tool_not_found",       # a CLI binary (nuclei, subfinder, ...) is missing at call time
    "auth_policy_denied",   # require_approved() blocked an authenticated-testing action
    "config_error",         # a required setting/env var was missing or invalid
    "parse_error",          # malformed JSON/data from a tool or API response
    "unknown",              # anything not covered above - the catch-all, not a dumping ground
]


def classify_error(exc: Exception) -> str:
    """
    Maps an exception instance to one of ERROR_TYPES. Always returns a
    value from that list - never raises, never returns something not in
    the taxonomy - so every phase_runs.error_type value is guaranteed
    queryable/groupable without a caller needing to sanitize it first.
    """
    # Import third-party/internal exception classes lazily, inside the
    # function - this module gets imported by checkpoint.py, which is
    # imported very early (main.py's top-level import list), so a
    # broken optional import here shouldn't be able to turn "classify
    # this error" into an import-time crash for the whole app.
    try:
        from google.genai import errors as genai_errors
    except ImportError:  # pragma: no cover - google-genai is a real requirements.txt dep
        genai_errors = None

    try:
        import asyncpg
    except ImportError:  # pragma: no cover - asyncpg is a real requirements.txt dep
        asyncpg = None

    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a real requirements.txt dep
        httpx = None

    from . import auth_policy
    from . import config as config_module

    message = str(exc)

    # --- auth policy gate ---
    if isinstance(exc, auth_policy.AuthPolicyError):
        return "auth_policy_denied"

    # --- config problems (missing/placeholder env vars, missing binaries) ---
    if isinstance(exc, config_module.ConfigError):
        return "config_error"
    if isinstance(exc, KeyError) and any(
        marker in message for marker in ("GEMINI_API_KEY", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB")
    ):
        return "config_error"

    # --- AI provider errors (Gemini + tier-2 fallbacks) ---
    if genai_errors is not None and isinstance(exc, (genai_errors.ClientError, genai_errors.ServerError)):
        code = getattr(exc, "code", None)
        status = str(getattr(exc, "status", "") or "")
        if code == 429 or "RESOURCE_EXHAUSTED" in status or "RESOURCE_EXHAUSTED" in message:
            return "ai_quota_exhausted"
        return "ai_provider_error"
    if "circuit-breaker cooldown" in message and "tier-2" in message:
        # gemini_rotation's synthetic RuntimeError when every model is
        # tripped and no tier-2 provider is configured/succeeded.
        return "ai_quota_exhausted"
    if httpx is not None and isinstance(exc, httpx.HTTPStatusError):
        # Tier-2 (OpenRouter/DeepSeek/GLM) calls go through httpx, not
        # the genai SDK, so their errors need their own check.
        return "ai_provider_error"

    # --- timeouts (subprocess tools, or any HTTP call) - checked BEFORE
    # the broader network_error/OSError bucket, since httpx.TimeoutException
    # is itself a subclass of httpx.HTTPError. ---
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "network_timeout"
    if httpx is not None and isinstance(exc, httpx.TimeoutException):
        return "network_timeout"

    # --- database ---
    if asyncpg is not None and isinstance(exc, asyncpg.PostgresError):
        return "db_error"

    # --- missing CLI binary (raised by tools.py's subprocess wrapper
    # when shutil.which/subprocess can't find the binary) ---
    if isinstance(exc, FileNotFoundError):
        return "tool_not_found"

    # --- other network-level failures ---
    if httpx is not None and isinstance(exc, httpx.HTTPError):
        return "network_error"
    if isinstance(exc, (ConnectionError, OSError)):
        return "network_error"

    # --- malformed data from a tool or API response ---
    if isinstance(exc, _json.JSONDecodeError):
        return "parse_error"
    if isinstance(exc, (ValueError, TypeError)) and (
        "json" in message.lower() or "decode" in message.lower() or "parse" in message.lower()
    ):
        return "parse_error"

    return "unknown"
