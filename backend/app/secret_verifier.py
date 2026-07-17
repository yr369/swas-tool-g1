"""
secret_verifier.py - live, read-only verification for a subset of the
API key/token signatures detective.py's check_api_key_leak_signature
already matches.

Plain-language: finding a string that LOOKS like a Stripe key or a
GitHub token is a pattern match, not proof. Programs routinely mark
"found a string matching a known key format" as Informative, because a
huge share of these turn out to be revoked, rotated, or test/sandbox
keys with no real access. This module makes exactly one extra,
side-effect-free, read-only API call per candidate to ask the
provider itself "is this credential currently valid, and if so, whose
is it" - which is the difference between "possible secret" and
"confirmed live credential," a real payout difference.

IMPORTANT DESIGN CONSTRAINT - this must be called INLINE, at the
moment detective.py finds the match, not later from a stored finding.
check_api_key_leak_signature deliberately redacts the full secret to
an 8-char preview before it's ever written to the findings table (see
that function) - by design, the full credential is never persisted.
That's the right call for a tool that stores results in a database;
it does mean verification has exactly one window to happen, while the
full matched string is still in memory. Do not try to re-derive or
store full secrets here either - verify, report the verdict, and let
the caller redact as it already does.

SCOPE - only providers where the regex detective.py already uses
captures a complete, self-contained bearer credential are handled
here. AWS access keys (AKIA...) and Twilio API Keys (SK...) are
deliberately NOT included: both require a paired secret that has no
fixed, greppable format and isn't captured by the existing signature
match, so there is nothing here to verify against - claiming to verify
them would be fake confidence, not a real check.
"""

import logging

import httpx

logger = logging.getLogger("swas.secret_verifier")

_TIMEOUT = httpx.Timeout(8.0, connect=4.0)

# Providers this module can genuinely verify, given what
# detective.py's regex actually captures (a complete, usable
# credential on its own - no paired secret needed).
VERIFIABLE_PROVIDERS = {
    "Stripe Live Secret Key",
    "GitHub Personal Access Token",
    "Slack Token",
}


async def _verify_stripe(key: str) -> dict:
    """
    GET /v1/balance is Stripe's own recommended lightweight way to test
    a key - it's read-only, has no side effects, and doesn't touch
    customer data. A valid key returns 200 with balance data; an
    invalid/revoked key returns 401 with error.type == "invalid_request_error".
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, ""),  # Stripe convention: key as HTTP Basic username, blank password
            )
    except httpx.HTTPError as exc:
        return {"checked": False, "note": f"verification request failed: {exc}"}

    if resp.status_code == 200:
        try:
            data = resp.json()
            available = data.get("available", [])
            amounts = ", ".join(f"{a.get('amount')} {a.get('currency', '').upper()}" for a in available)
        except Exception:
            amounts = "(could not parse balance)"
        return {
            "checked": True,
            "valid": True,
            "note": f"LIVE Stripe key confirmed via /v1/balance - account balance visible: {amounts or '0'}",
        }
    if resp.status_code == 401:
        return {"checked": True, "valid": False, "note": "Stripe rejected the key (401) - revoked/invalid/test key"}
    return {"checked": True, "valid": None, "note": f"Stripe returned unexpected status {resp.status_code} - inconclusive"}


async def _verify_github(token: str) -> dict:
    """
    GET /user with the token is GitHub's own documented way to check
    "who am I" - read-only, and the X-OAuth-Scopes response header is a
    bonus: it tells you exactly what the token can do (repo, admin:org,
    etc.) without any further requests, which matters a lot for
    severity - a token scoped to "public_repo" is a very different
    finding from one scoped to "admin:org".
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}"},
            )
    except httpx.HTTPError as exc:
        return {"checked": False, "note": f"verification request failed: {exc}"}

    if resp.status_code == 200:
        try:
            data = resp.json()
            login = data.get("login", "unknown")
        except Exception:
            login = "unknown"
        scopes = resp.headers.get("X-OAuth-Scopes", "(no scopes header returned)")
        return {
            "checked": True,
            "valid": True,
            "note": f"LIVE GitHub token confirmed via /user - belongs to '{login}', scopes: {scopes}",
        }
    if resp.status_code == 401:
        return {"checked": True, "valid": False, "note": "GitHub rejected the token (401) - revoked/invalid"}
    return {"checked": True, "valid": None, "note": f"GitHub returned unexpected status {resp.status_code} - inconclusive"}


async def _verify_slack(token: str) -> dict:
    """
    POST /api/auth.test is Slack's own documented, purpose-built
    endpoint for exactly this - "is this token valid, and for which
    workspace/user." Explicitly read-only per Slack's own docs.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        return {"checked": False, "note": f"verification request failed: {exc}"}

    try:
        data = resp.json()
    except Exception:
        return {"checked": True, "valid": None, "note": "Slack response could not be parsed - inconclusive"}

    if data.get("ok"):
        team = data.get("team", "unknown workspace")
        user = data.get("user", "unknown user")
        return {
            "checked": True,
            "valid": True,
            "note": f"LIVE Slack token confirmed via auth.test - workspace '{team}', user '{user}'",
        }
    error = data.get("error", "unknown_error")
    if error in ("invalid_auth", "token_revoked", "account_inactive"):
        return {"checked": True, "valid": False, "note": f"Slack rejected the token ({error}) - revoked/invalid"}
    return {"checked": True, "valid": None, "note": f"Slack returned '{error}' - inconclusive, not a clear invalid signal"}


_VERIFIERS = {
    "Stripe Live Secret Key": _verify_stripe,
    "GitHub Personal Access Token": _verify_github,
    "Slack Token": _verify_slack,
}


async def verify_secret(provider: str, raw_secret: str) -> dict | None:
    """
    Entry point. Returns None if this provider isn't one we can
    honestly verify (see module docstring - AWS/Twilio need a paired
    secret we don't have). Otherwise returns:
        {"checked": bool, "valid": True|False|None, "note": str}
    valid=None means the verification call itself was inconclusive
    (network error, unexpected response) - never treat that the same
    as a confirmed-invalid key.
    """
    verifier_fn = _VERIFIERS.get(provider)
    if verifier_fn is None:
        return None
    try:
        return await verifier_fn(raw_secret)
    except Exception as exc:
        logger.warning("secret_verifier: unexpected error verifying %s: %s", provider, exc)
        return {"checked": False, "note": f"verification raised an unexpected error: {exc}"}
