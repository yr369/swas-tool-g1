"""
config.py - startup config sanity checks.

Why this exists: without it, a missing GEMINI_API_KEY or a nuclei binary
that never got installed in the image doesn't surface until a scan is
already 3 phases in and something throws `KeyError: 'GEMINI_API_KEY'` or
`FileNotFoundError: nuclei` deep in a subprocess call - by then it's
buried in scan logs, not obvious, and the container has looked "healthy"
the whole time.

This makes the container refuse to start with the SAME failure it would
have hit later anyway - just immediate, named, and in one place, instead
of surfacing piecemeal the first time each broken thing is actually used.
"""

import logging
import os
import shutil

logger = logging.getLogger("swas.config")

# env var -> why a scan breaks without it. Missing/blank/placeholder ->
# hard fail, since every one of these WILL cause a real failure the
# first time it's touched, not a degraded-but-working mode.
_REQUIRED_ENV = {
    "GEMINI_API_KEY": "every AI call (triage, scope parsing, logic_hunter, "
                       "agent_loop, report drafting) needs this - without "
                       "it every scan fails at the first AI step",
    "POSTGRES_USER": "asyncpg's connection string is built from this",
    "POSTGRES_PASSWORD": "asyncpg's connection string is built from this",
    "POSTGRES_DB": "asyncpg's connection string is built from this",
}

# Values copied straight out of .env.example without being changed -
# these LOOK set (non-empty) but are guaranteed wrong.
_PLACEHOLDER_VALUES = {
    "your_gemini_api_key_here",
    "changeme_use_a_real_password",
}

# Recommended, not required - missing these degrades behavior (CORS
# blocked, no notifications) rather than breaking scans outright, so
# these only warn.
_RECOMMENDED_ENV = {
    "ALLOWED_ORIGINS": "frontend requests will be CORS-blocked without this",
}

# binary -> which pipeline phase breaks without it. Checked with
# shutil.which so this catches "image build skipped installing a tool"
# before the pipeline does, instead of a scan silently producing zero
# findings from that phase forever.
_REQUIRED_BINARIES = {
    "subfinder": "recon phase (subdomain enumeration)",
    "httpx-pd": "probe phase (live host detection)",
    "nuclei": "scan phase (template-based vuln scanning)",
    "arjun": "fuzz phase (parameter discovery)",
    "ffuf": "fuzz phase (content/dir fuzzing)",
    "dalfox": "verify phase (XSS confirmation)",
    "sqlmap": "verify phase (SQLi confirmation)",
}


class ConfigError(RuntimeError):
    """
    Raised when a REQUIRED config item is missing/invalid. main.py's
    lifespan lets this propagate out of startup, which means the
    container never reaches "started" and its health check never
    passes - orchestration (docker compose, k8s) surfaces this
    immediately as a crash-looping container instead of one that looks
    "up" but is quietly broken.
    """


def check_startup_config() -> list[str]:
    """
    Runs once at app startup (see main.py's lifespan). Returns a list of
    warning strings for RECOMMENDED-but-missing items - caller logs
    these but startup proceeds. Raises ConfigError immediately if
    anything REQUIRED is missing, blank, or left at its .env.example
    placeholder value; the exception message lists every problem found
    in one pass rather than failing on the first one, so a fresh
    install doesn't have to restart-fix-restart-fix through each error
    one at a time.
    """
    errors: list[str] = []
    warnings: list[str] = []

    for var, why in _REQUIRED_ENV.items():
        value = os.environ.get(var, "").strip()
        if not value:
            errors.append(f"{var} is not set - {why}")
        elif value in _PLACEHOLDER_VALUES:
            errors.append(f"{var} is still set to its .env.example placeholder value - {why}")

    for binary, phase in _REQUIRED_BINARIES.items():
        if shutil.which(binary) is None:
            errors.append(f"binary '{binary}' not found on PATH - {phase} will fail every time it runs")

    for var, why in _RECOMMENDED_ENV.items():
        if not os.environ.get(var, "").strip():
            warnings.append(f"{var} is not set - {why}")

    webhook = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
    if webhook and not (webhook.startswith("http://") or webhook.startswith("https://")):
        warnings.append(
            f"NOTIFY_WEBHOOK_URL is set but doesn't look like a URL "
            f"('{webhook[:40]}...') - notifications will fail"
        )

    if errors:
        for e in errors:
            logger.error("STARTUP CONFIG ERROR: %s", e)
        bullet_list = "\n  - ".join(errors)
        raise ConfigError(
            f"{len(errors)} required config item(s) missing/invalid - refusing to start:\n"
            f"  - {bullet_list}\n"
            f"Fix .env (or the image, for missing binaries) and restart."
        )

    return warnings
