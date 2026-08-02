"""
Client-side checks: reflected/DOM XSS, JSONP callback XSS,
clickjacking, insecure file/SVG upload.

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
)

async def check_reflected_xss(url: str) -> dict | None:
    """
    Injects a unique, unlikely-to-collide marker containing raw HTML
    special characters into each existing query parameter, then checks
    whether it comes back completely unescaped in an HTML response.
    Proof bar: the exact raw string (angle brackets, quotes intact) must
    appear verbatim in a text/html response - HTML-entity-encoded
    reflection (e.g. &lt;script&gt;) is explicitly not a match, since
    that's the app doing its job correctly.
    """
    marker_id = uuid.uuid4().hex[:10]
    payload = f'"><svg/onload=alert(/swas{marker_id}/)>'

    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        for param_name in existing_params:
            test_params = dict(existing_params)
            test_params[param_name] = payload
            test_url = parsed.copy_with(params=test_params)
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                continue

            content_type = resp.headers.get("content-type", "")
            if "html" not in content_type.lower():
                continue  # JSON/plain-text APIs aren't a browser-execution context here
            if payload in resp.text:
                return {
                    "vuln_type": "reflected_xss",
                    "severity": "high",
                    "evidence": (
                        f"{test_url}: parameter '{param_name}' reflected the payload "
                        f"{payload!r} completely unescaped in a text/html response - "
                        f"browser would execute this as markup/script."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: reflected XSS check failed for %s: %s", url, exc)
    return None


_DOM_XSS_SOURCES = ["location.hash", "location.search", "location.href", "document.URL",
                     "document.referrer", "window.name"]
_DOM_XSS_SINKS = ["innerHTML", "outerHTML", "document.write(", "document.writeln(",
                   "eval(", "insertAdjacentHTML("]


async def check_dom_xss_sink_flagging(url: str) -> str | None:
    """
    Downloads a JS bundle and flags it if it contains BOTH a known
    attacker-controllable source (location.hash, document.referrer, etc.)
    and a known dangerous sink (innerHTML, eval, document.write) within
    the same file. Returns a plain string, NOT a findings dict - same
    convention as check_idor_candidate and check_waf_fingerprint.
    Confirming actual DOM XSS requires tracing real taint flow from the
    specific source to the specific sink (the source's value has to
    actually reach the sink unsanitized), which static keyword presence
    can't prove - a file can easily use both independently with no
    connection between them. This flags candidates worth a manual
    browser-based check (or a proper taint-analysis tool), not a
    verdict.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: DOM XSS sink check failed for %s: %s", url, exc)
        return None

    body = resp.text
    found_sources = [s for s in _DOM_XSS_SOURCES if s in body]
    found_sinks = [s for s in _DOM_XSS_SINKS if s in body]
    if found_sources and found_sinks:
        return (
            f"{url}: contains both attacker-controllable source(s) "
            f"({', '.join(found_sources[:3])}) and dangerous sink(s) "
            f"({', '.join(found_sinks[:3])}) - candidate for manual DOM XSS "
            f"taint-flow verification (static match only, source->sink "
            f"connection not confirmed)"
        )
    return None


_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+'none'|frame-ancestors\s+'self'", re.IGNORECASE)


async def check_clickjacking_missing_protection(url: str) -> str | None:
    """
    Checks for the absence of BOTH X-Frame-Options and a restrictive
    CSP frame-ancestors directive. Returns a plain string, NOT a
    findings dict, and deliberately not auto-filed even though this is
    a real, correctly-detected gap - clickjacking is one of the most
    commonly Informative/excluded categories on bug bounty programs
    across the board, valuable only when demonstrated against a
    specific sensitive action (funds transfer, account deletion, 2FA
    disable), not as a standalone "header is missing" report. Same
    reasoning already applied to check_csp_weakness and check_missing_sri.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: clickjacking check failed for %s: %s", url, exc)
        return None

    if resp.headers.get("x-frame-options"):
        return None
    csp = resp.headers.get("content-security-policy", "")
    if _FRAME_ANCESTORS_RE.search(csp):
        return None

    return (
        f"{url}: no X-Frame-Options header and no restrictive CSP frame-ancestors directive "
        f"- page can be framed by any origin. Almost always rated Informative on its own; "
        f"only worth reporting if you can demonstrate a real sensitive action being framed "
        f"(funds transfer, account deletion, 2FA disable), not as a standalone header finding"
    )


_FILE_INPUT_RE = re.compile(r'<input[^>]+type=["\']file["\'][^>]*>', re.IGNORECASE)
_ACCEPT_ATTR_RE = re.compile(r'accept=["\']([^"\']*)["\']', re.IGNORECASE)


async def check_file_upload_form_candidate(url: str) -> str | None:
    """
    Flags pages containing a file-upload form (<input type="file">).
    Returns a plain string, NOT a findings dict, and never attempts an
    actual upload - unrestricted file upload -> RCE is a high-payout bug
    class, but actually testing extension/content-type/magic-byte
    bypasses means uploading real files to what might be production
    storage, which carries real risk of leaving artifacts behind on a
    target you don't control. This only tells you where the upload
    surface is so you can test it manually and clean up after yourself.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: file upload form check failed for %s: %s", url, exc)
        return None

    body = resp.text
    file_inputs = _FILE_INPUT_RE.findall(body)
    if not file_inputs:
        return None

    accept_values = [m for m in _ACCEPT_ATTR_RE.findall(" ".join(file_inputs))]
    accept_note = f", accept={accept_values}" if accept_values else " (no accept attribute set)"
    return (
        f"{url}: contains {len(file_inputs)} file-upload input(s){accept_note} - candidate "
        f"for manual upload-restriction-bypass testing (double extensions, null byte, "
        f"content-type spoofing, magic-byte bypass); not tested here to avoid leaving "
        f"uploaded artifacts on the target"
    )


async def check_insecure_svg_upload_flagging(url: str) -> str | None:
    """
    Narrower complement to check_file_upload_form_candidate (batch 14):
    specifically flags upload forms whose accept attribute includes SVG
    (image/svg+xml or .svg). SVG files can embed <script> tags and are
    frequently rendered inline or served with a permissive content-type,
    making SVG upload a well-known path to stored XSS that a generic
    "has a file upload" note doesn't call out specifically. Returns a
    plain string, NOT a findings dict, and never uploads anything -
    same reasoning as the general file-upload check.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: SVG upload flagging check failed for %s: %s", url, exc)
        return None

    body = resp.text
    for file_input in _FILE_INPUT_RE.findall(body):
        if "svg" in file_input.lower():
            return (
                f"{url}: file upload form explicitly accepts SVG (accept attribute "
                f"references svg) - SVG can embed <script> and is a well-known stored-XSS "
                f"upload vector; not tested here to avoid leaving uploaded artifacts on the "
                f"target"
            )
    return None


_JSONP_PARAM_NAMES = ["callback", "jsonp", "cb", "jsonpcallback"]


async def check_jsonp_callback_xss(url: str) -> dict | None:
    """
    JSONP endpoints wrap a JSON response in a caller-controlled function
    name: callback({...}). If the callback parameter isn't validated
    against a strict identifier pattern, injecting script-breaking
    characters produces attacker-controlled JavaScript that executes
    when the response is loaded as a <script src>. Same unique-marker
    discipline as check_reflected_xss: a UUID fragment in the payload
    means a coincidental match is effectively impossible, so this
    doesn't need baseline diffing.
    """
    parsed = httpx.URL(url)
    existing_params = dict(parsed.params)
    marker_id = uuid.uuid4().hex[:10]
    payload = f"alert(/swas{marker_id}/)//"

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        for param_name in _JSONP_PARAM_NAMES:
            test_params = dict(existing_params)
            test_params[param_name] = payload
            test_url = parsed.copy_with(params=test_params)
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                continue
            content_type = resp.headers.get("content-type", "").lower()
            if "javascript" not in content_type and "json" not in content_type:
                continue
            if payload not in resp.text:
                continue
            # Confirm the payload wasn't JSON-string-escaped into harmlessness
            # (e.g. "alert(\/swas...\/)//" inside a quoted string literal) -
            # check the few characters immediately before it for an escaping
            # backslash-quote, which would mean it's inert data, not live code.
            idx = resp.text.find(payload)
            preceding = resp.text[max(0, idx - 5):idx]
            if '\\"' in preceding or "\\'" in preceding:
                continue
            return {
                "vuln_type": "jsonp_callback_xss",
                "severity": "high",
                "evidence": (
                    f"{test_url}: JSONP parameter '{param_name}' with payload "
                    f"{payload!r} was reflected unescaped into a "
                    f"javascript/json-typed response - executes as script when "
                    f"loaded via <script src>."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: JSONP callback XSS check failed for %s: %s", url, exc)
    return None


