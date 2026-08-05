"""
Recon and miscellaneous checks that do not cleanly fit the other
categories: subdomain takeover, cache deception/poisoning, WAF
fingerprinting, GraphQL introspection, open redirect variants,
websocket downgrade/CSWSH, weak TLS, business-logic recon signals.

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
    _GRAPHQL_PATHS,
)

_TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    # (cname substring, response substring that proves it's unclaimed, service name)
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "no-such-app", "Heroku"),
    ("herokudns.com", "no-such-app", "Heroku"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service"),
    ("cloudapp.net", "404", "Azure Cloud Service"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("wpengine.com", "The site you were looking for couldn't be found", "WP Engine"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost.io"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket Pages"),
    ("statuspage.io", "You are being", "Statuspage.io"),
    ("tumblr.com", "Whatever you were looking for doesn't currently exist", "Tumblr"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("readme.io", "Project doesnt exist", "Readme.io"),
]


async def check_subdomain_takeover(hostname: str) -> dict | None:
    """
    Resolves the CNAME chain for `hostname` via DNS-over-HTTPS (Cloudflare
    1.1.1.1) - no new binary or DNS library needed since httpx is already
    a dependency. If the CNAME points at a known third-party service, we
    fetch the live page and check for that service's "unclaimed" message.

    Returns a dict describing the finding, or None if nothing looks
    hijackable (which is the overwhelmingly common case - this should
    stay quiet unless it's confident).
    """
    hostname = _extract_hostname(hostname)
    if hostname is None:
        return None  # not a real hostname - scope-import junk, skip quietly

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        logger.info("detective: checking subdomain takeover for %s", hostname)
        dns_resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": hostname, "type": "CNAME"},
            headers={"accept": "application/dns-json"},
        )
        if dns_resp.status_code != 200:
            return None
        answers = dns_resp.json().get("Answer", [])
        cname_targets = [a["data"].rstrip(".") for a in answers if a.get("type") == 5]

        if not cname_targets:
            return None

        for cname in cname_targets:
            for fingerprint, unclaimed_marker, service in _TAKEOVER_FINGERPRINTS:
                if fingerprint not in cname:
                    continue
                try:
                    page_resp = await client.get(
                        f"https://{hostname}", follow_redirects=True
                    )
                    body = page_resp.text
                except httpx.HTTPError:
                    body = ""
                if unclaimed_marker.lower() in body.lower():
                    return {
                        "vuln_type": "subdomain_takeover",
                        "severity": "high",
                        "evidence": (
                            f"{hostname} CNAMEs to {cname} ({service}), which returns "
                            f"an unclaimed-resource page. Likely takeover candidate."
                        ),
                    }
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("detective: takeover check failed for %s: %s", hostname, exc)
    return None


_CACHE_DECEPTION_PATH_HINTS = re.compile(
    r"(account|profile|dashboard|settings|billing|invoice|user|me|orders?)\b",
    re.IGNORECASE,
)


async def check_cache_deception(url: str) -> dict | None:
    """
    Appends a fake static extension (e.g. /account/profile/nonexistent.css)
    to a URL that looks like it serves personal data. If a CDN/cache layer
    caches that response as if it were a static asset, a SECOND
    unauthenticated request to the same URL returning the same private
    body (a cache HIT) confirms Web Cache Deception - other users could
    then be served a victim's cached private page.

    Only runs against URLs matching _CACHE_DECEPTION_PATH_HINTS - this is
    intentionally conservative to avoid false positives on generic pages.
    """
    if not _CACHE_DECEPTION_PATH_HINTS.search(url):
        return None

    probe_url = url.rstrip("/") + "/nonexistent-swas-probe.css"
    logger.info("detective: checking cache deception for %s", probe_url)

    try:
        # follow_redirects=False on purpose: a 3xx here means the fake
        # static-extension path isn't actually being served/cached as
        # its own resource - it's just bouncing to the homepage or a
        # catch-all, which is normal CDN caching, not deception.
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        first = await client.get(probe_url)
        if first.status_code != 200:
            return None
        # A cache-deception candidate: the fake-static-extension path
        # returned 200 with a body, AND either an explicit cache HIT
        # header shows up, or the response looks like real page
        # content (html) rather than a generic 404/error page.
        cache_status = (
            first.headers.get("x-cache", "")
            or first.headers.get("cf-cache-status", "")
            or first.headers.get("x-cache-status", "")
        ).lower()

        second = await client.get(probe_url)
        cache_status_2 = (
            second.headers.get("x-cache", "")
            or second.headers.get("cf-cache-status", "")
            or second.headers.get("x-cache-status", "")
        ).lower()

        looks_cached = "hit" in cache_status_2 and first.text == second.text
        looks_like_real_page = "<html" in first.text.lower() and len(first.text) > 200

        if looks_cached and looks_like_real_page:
            return {
                "vuln_type": "cache_deception",
                "severity": "high",
                "evidence": (
                    f"{probe_url} returned HTTP 200 with page content and was served "
                    f"from cache on a second request (cache status: {cache_status_2}). "
                    f"Possible Web Cache Deception - private content may be cached and "
                    f"served to other users."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: cache deception check failed for %s: %s", url, exc)
    return None


async def check_file_entropy(url: str) -> dict | None:
    """
    Downloads a single file (JS bundle, config, .env-looking path, etc.)
    and looks for key=value / "key": "value" pairs whose value has high
    Shannon entropy - the statistical signature of a real API key, JWT
    secret, or token, as opposed to ordinary readable text. Flags the
    key NAME and entropy score, but truncates the actual secret VALUE in
    the evidence so the finding itself doesn't become a leak.
    """
    if not _SENSITIVE_FILE_HINTS.search(url):
        return None

    if _TEST_FIXTURE_PATH_HINTS.search(url):
        # Test/fixture/example/mock paths in open-source or public repos
        # routinely contain hardcoded dummy tokens that are high-entropy
        # by construction but were never meant to be real credentials -
        # not worth reporting even if the entropy math looks convincing.
        return None

    logger.info("detective: checking file entropy for %s", url)
    try:
        # follow_redirects=False on purpose: if this URL 3xx's somewhere
        # else, we'd otherwise be scanning an unrelated landing page for
        # entropy and misattributing any hit to this path (the same bug
        # class that caused false heapdump findings).
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: entropy check fetch failed for %s: %s", url, exc)
        return None

    if resp.status_code != 200 or not resp.text:
        return None

    body = resp.text
    hits = []
    for match in _TOKEN_PATTERN.finditer(body):
        key_name, value = match.group(1), match.group(2)
        entropy = _shannon_entropy(value)
        # Entropy > 4.0 over a >=12-char value reliably separates
        # random-looking secrets from ordinary words/placeholders like
        # "your_api_key_here" (English text sits well under 4.0).
        if entropy > 4.0 and not _PLACEHOLDER_VALUE_HINTS.search(value):
            hits.append((key_name, entropy, value[:4] + "..." + value[-2:]))

    if not hits:
        return None

    summary = "; ".join(f"{k} (entropy={e:.2f}, value={masked})" for k, e, masked in hits[:5])
    return {
        "vuln_type": "sensitive_file_exposure",
        "severity": "medium",
        "evidence": (
            f"{url} contains {len(hits)} high-entropy key/value pair(s) that look like "
            f"leaked secrets: {summary}"
        ),
    }


_REDIRECT_PARAM_PATTERN = re.compile(
    r"^(url|redirect|redirect_uri|redirect_url|return|return_url|returnto|"
    r"return_to|next|dest|destination|continue|r|redir|target|out|forward)$",
    re.IGNORECASE,
)
_OPEN_REDIRECT_PROBE = "https://swas-redirect-probe.example.com"


async def check_open_redirect(url: str) -> dict | None:
    """
    If `url` has a parameter whose name looks redirect-related, replaces
    its value with an external probe domain and checks whether the
    server issues an HTTP redirect straight to it without validation.
    Does not follow the redirect (follow_redirects=False) - we only need
    to see the Location header the server itself generated.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    redirect_param = next(
        (p for p in query_params if _REDIRECT_PARAM_PATTERN.match(p)), None
    )
    if redirect_param is None:
        return None

    mutated = _replace_query_param(parsed, query_params, redirect_param, _OPEN_REDIRECT_PROBE)
    logger.info("detective: checking open redirect for %s", mutated)

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
        resp = await client.get(mutated)
    except httpx.HTTPError as exc:
        logger.info("detective: open redirect check failed for %s: %s", mutated, exc)
        return None

    location = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and _OPEN_REDIRECT_PROBE in location:
        return {
            "vuln_type": "open_redirect",
            "severity": "low",
            "evidence": (
                f"{url} param '{redirect_param}' causes an unvalidated HTTP "
                f"{resp.status_code} redirect straight to an attacker-controlled "
                f"domain: Location: {location}"
            ),
        }
    return None


_WEAK_CSP_PATTERN = re.compile(r"unsafe-inline|unsafe-eval|\*", re.IGNORECASE)


async def check_csp_weakness(url: str) -> str | None:
    """
    Reads the Content-Security-Policy header and returns a short
    human-readable note if script-src/default-src looks loose enough to
    make XSS payloads more likely to execute. Returns a plain string (or
    None), NOT a findings dict - this is intentionally never saved to
    the findings table. A weak CSP alone is not a vulnerability a
    program pays for; it's context for where to spend dalfox/manual XSS
    effort. See the module docstring for why.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
        resp = await client.get(url)
    except httpx.HTTPError:
        return None

    csp = resp.headers.get("content-security-policy", "")
    if not csp:
        return f"{url}: no CSP header set - XSS payloads face no CSP restriction here"

    directives = [d.strip() for d in csp.split(";") if d.strip()]
    weak = [d for d in directives if _WEAK_CSP_PATTERN.search(d)]
    if weak:
        return f"{url}: weak CSP directive(s): {'; '.join(weak[:3])}"
    return None


_INTROSPECTION_QUERY = {
    "query": "{__schema{queryType{name} mutationType{name} types{name kind fields{name}}}}"
}


async def check_graphql_introspection(host: str) -> dict | None:
    """
    Tries a short list of common GraphQL endpoint paths under `host`. If
    introspection is enabled (the server just answers a __schema query
    with no auth), pulls back the full type/field list - this routinely
    surfaces mutation names and internal fields that were never meant to
    be discoverable, which is genuinely useful attack-surface mapping
    even though the introspection response itself is the finding here
    rather than a direct exploit.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        for path in _GRAPHQL_PATHS:
            url = base + path
            logger.info("detective: checking GraphQL introspection for %s", url)
            try:
                resp = await client.post(url, json=_INTROSPECTION_QUERY)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue

            schema = (data.get("data") or {}).get("__schema")
            if not schema or not schema.get("types"):
                continue

            type_names = [t["name"] for t in schema["types"] if t.get("name")][:10]
            mutation_type = (schema.get("mutationType") or {}).get("name")
            return {
                "vuln_type": "graphql_introspection_exposed",
                "severity": "medium",
                "evidence": (
                    f"{url} allows unauthenticated GraphQL introspection - "
                    f"{len(schema['types'])} types exposed, including: "
                    f"{', '.join(type_names)}"
                    + (f". Mutation root: {mutation_type}" if mutation_type else "")
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: GraphQL introspection check failed for %s: %s", host, exc)
    return None


_WAF_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "akamai": ["akamai", "ak_bmsc"],
    "imperva": ["incap_ses", "visid_incap", "x-iinfo"],
    "sucuri": ["x-sucuri-id", "sucuri"],
}


async def check_waf_fingerprint(host: str) -> str | None:
    """
    Identifies common WAF/CDN signatures in response headers and a small
    body sample. Returns a plain string (or None), NOT a findings dict -
    same reasoning as check_csp_weakness: which WAF fronts a target is
    not itself a vulnerability, it's context. Concretely, it exists so a
    human (or a future check) can tell "this odd response is just the
    WAF's block page" apart from "the application actually behaved this
    way" - without it, WAF block pages risk getting misread as real
    findings by less careful heuristics.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
        resp = await client.get(host)
    except httpx.HTTPError:
        return None

    header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    body_sample = resp.text[:2000].lower()
    for waf_name, signatures in _WAF_SIGNATURES.items():
        if any(sig in header_blob or sig in body_sample for sig in signatures):
            return f"{host}: WAF/CDN detected - {waf_name}"
    return None


_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_WS_PROBE_PATHS = ["/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket"]
_CSWSH_ATTACKER_ORIGIN = "https://swas-cswsh-probe.example.com"


def _ws_accept_key(sec_websocket_key: str) -> str:
    """RFC 6455's Sec-WebSocket-Accept algorithm: SHA1(key + magic GUID),
    base64-encoded. Used to confirm a 101 response is a genuine completed
    WebSocket handshake, not some unrelated server that happens to
    return HTTP 101 for other reasons."""
    digest = hashlib.sha1((sec_websocket_key + _WEBSOCKET_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


async def _try_ws_handshake(hostname: str, port: int, path: str, use_tls: bool) -> bool:
    """
    Hand-rolls a raw WebSocket opening handshake (it's just one HTTP
    Upgrade request - no need for a websockets library to test only the
    handshake, and this keeps detective.py dependency-free like the rest
    of the module). Sends an attacker-controlled Origin header; returns
    True only if the server completes a byte-verified handshake anyway
    (101 status AND the correct Sec-WebSocket-Accept value for the key
    we sent - not just any 101 response).
    """
    sec_key = base64.b64encode(os.urandom(16)).decode()
    expected_accept = _ws_accept_key(sec_key)

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {sec_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {_CSWSH_ATTACKER_ORIGIN}\r\n"
        f"\r\n"
    ).encode()

    ssl_context = None
    if use_tls:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ssl_context), timeout=4.0
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False

    try:
        writer.write(request)
        await writer.drain()
        try:
            response = await asyncio.wait_for(reader.read(4096), timeout=4.0)
        except asyncio.TimeoutError:
            return False
        response_text = response.decode(errors="ignore")
        status_line = response_text.split("\r\n", 1)[0]
        if " 101 " not in f" {status_line} ":
            return False
        return expected_accept.lower() in response_text.lower()
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - best-effort cleanup, never let this raise
            pass


async def check_websocket_cswsh(host: str) -> dict | None:
    """
    Tries a short list of common WebSocket paths under `host`. If any
    completes a full, byte-verified handshake despite an attacker
    Origin, that's evidence the server doesn't validate Origin on this
    endpoint. Deliberately scored medium (not high/critical) with an
    explicit caveat in the evidence: CSWSH only matters if the socket
    carries authenticated/session data via cookies, which we can't
    confirm without a real logged-in session (no test accounts
    available yet - see the multi-token IDOR discussion). Reporting this
    as-is against a public/anonymous WebSocket feed would likely come
    back Informative.
    """
    hostname = _extract_hostname(host)
    if hostname is None:
        return None

    use_tls = not host.lower().startswith("http://")
    port = 443 if use_tls else 80

    for path in _WS_PROBE_PATHS:
        scheme = "wss" if use_tls else "ws"
        logger.info("detective: checking WebSocket CSWSH for %s://%s%s", scheme, hostname, path)
        accepted = await _try_ws_handshake(hostname, port, path, use_tls)
        if accepted:
            return {
                "vuln_type": "websocket_origin_not_validated",
                "severity": "medium",
                "evidence": (
                    f"{scheme}://{hostname}{path} completed a full WebSocket handshake despite "
                    f"an attacker-controlled Origin header ({_CSWSH_ATTACKER_ORIGIN}). This only "
                    f"has real impact if the endpoint carries session/authenticated data via "
                    f"cookies - verify that manually before reporting, since CSWSH on a public/"
                    f"anonymous feed is routinely triaged as Informative."
                ),
            }
    return None


_OPTIONSBLEED_PROBE_COUNT = 6
_STANDARD_HTTP_METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
}


async def check_apache_optionsbleed(host: str) -> dict | None:
    """
    CVE-2017-9798: a specific Apache memory-disclosure bug where a
    misconfigured 'Limit' directive across multiple .htaccess/vhost
    configs causes a freed/uninitialized pointer to leak into the Allow
    header of OPTIONS responses. Detected the same way the original
    disclosure did: send several OPTIONS requests to the same path and
    check whether the Allow header value varies AND contains tokens
    outside the standard HTTP method vocabulary - header reordering
    alone is normal and not a signal, so both conditions are required.
    """
    url = host.rstrip("/") + "/"
    logger.info("detective: checking Apache OptionsBleed for %s", url)
    allow_headers: set[str] = set()
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        for _ in range(_OPTIONSBLEED_PROBE_COUNT):
            try:
                resp = await client.request("OPTIONS", url)
            except httpx.HTTPError:
                return None
            allow = resp.headers.get("allow")
            if allow:
                allow_headers.add(allow)
    except httpx.HTTPError as exc:
        logger.info("detective: OptionsBleed check failed for %s: %s", url, exc)
        return None

    if len(allow_headers) <= 1:
        return None  # consistent Allow header - no variance, no signal

    suspicious = any(
        {t.strip() for t in header_value.split(",")} - _STANDARD_HTTP_METHODS
        for header_value in allow_headers
    )
    if not suspicious:
        return None

    return {
        "vuln_type": "apache_optionsbleed",
        "severity": "high",
        "evidence": (
            f"{url} returned {len(allow_headers)} different Allow header values across "
            f"{_OPTIONSBLEED_PROBE_COUNT} repeated OPTIONS requests, including non-standard "
            f"method tokens: {sorted(allow_headers)[:5]}. Consistent with CVE-2017-9798 "
            f"(Optionsbleed) - an Apache memory disclosure bug."
        ),
    }


_OPEN_REDIRECT_ENCODED_PAYLOADS = [
    "/\\evil-swas-redirect-probe.test",
    "//evil-swas-redirect-probe.test",
    "/%09/evil-swas-redirect-probe.test",
    "/%2f%2fevil-swas-redirect-probe.test",
    "https:evil-swas-redirect-probe.test",
]
_REDIRECT_PARAM_NAME_RE = re.compile(r"url|redirect|next|return|dest|continue|target", re.IGNORECASE)


async def check_open_redirect_encoding_bypass(url: str) -> dict | None:
    """
    Complements check_open_redirect (batch 1) with encoding/parsing-trick
    variants - backslash-as-slash, double-slash, tab-injected slash,
    percent-encoded slashes, scheme-relative confusion - that a naive
    "starts with http(s):// or //" validator often misses even when it
    correctly blocks the plain forms.

    Proof bar: the Location header of an actual redirect response must
    resolve to a domain we chose (evil-swas-redirect-probe.test) -
    deterministic string matching against a known value, not a
    coincidental substring.

    Open redirect findings are frequently rated Informative or low-
    severity on bug bounty programs unless chained with additional
    impact (OAuth token leakage, login CSRF) - worth checking program
    policy before treating a hit here as automatically report-worthy.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)
    redirect_params = [p for p in existing_params if _REDIRECT_PARAM_NAME_RE.search(p)]
    if not redirect_params:
        return None

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
        for param_name in redirect_params:
            for payload in _OPEN_REDIRECT_ENCODED_PAYLOADS:
                test_params = dict(existing_params)
                test_params[param_name] = payload
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil-swas-redirect-probe.test" in location:
                    return {
                        "vuln_type": "open_redirect_encoding_bypass",
                        "severity": "medium",
                        "evidence": (
                            f"{test_url}: parameter '{param_name}' with encoding-trick "
                            f"payload {payload!r} produced a {resp.status_code} redirect to "
                            f"Location: {location!r} - a naive prefix/domain validator was "
                            f"bypassed. Note: open redirect is commonly rated Informative "
                            f"without demonstrated chained impact - check program policy."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: open redirect encoding bypass check failed for %s: %s", url, exc)
    return None


_GRAPHQL_BLIND_MUTATION_PROBES = [
    '{"query": "mutation { __typename }"}',
]


async def check_unauthenticated_graphql_mutation(url: str) -> dict | None:
    """
    Sends a minimal, universally-valid mutation shell (`mutation {
    __typename }`) with no authentication at all. Every GraphQL server
    that accepts mutations at all will answer this one - it costs
    nothing and asks nothing sensitive, but if the endpoint requires
    auth for mutations, a properly configured server rejects it before
    ever reaching resolution. A clean top-level "data" key with no
    "errors" key means mutations are reachable without authentication -
    a real access-control gap, distinct from (and complementary to)
    check_graphql_introspection, which only tests read-side schema
    disclosure.
    """
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            resp = await client.post(
                url,
                content=_GRAPHQL_BLIND_MUTATION_PROBES[0],
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            return None
    except httpx.HTTPError as exc:
        logger.info("detective: unauthenticated GraphQL mutation check failed for %s: %s", url, exc)
        return None

    try:
        response_json = resp.json()
    except Exception:
        return None
    if not isinstance(response_json, dict):
        return None

    if "data" in response_json and response_json.get("data") and "errors" not in response_json:
        return {
            "vuln_type": "unauthenticated_graphql_mutation",
            "severity": "high",
            "evidence": (
                f"{url}: an unauthenticated 'mutation {{ __typename }}' request succeeded "
                f"(top-level 'data' present, no 'errors') - mutations are reachable without "
                f"authentication, worth manually enumerating real mutation names for actual "
                f"write-access impact."
            ),
        }
    return None


async def check_negative_number_business_logic_candidate(url: str) -> str | None:
    """
    Flags numeric query parameters that silently accept a negative value
    (same 200 status as the original, no obvious validation-error
    language) as candidates for manual business-logic testing (price/
    quantity/balance manipulation). Returns a plain string, NOT a
    findings dict - accepting a negative number isn't itself a
    vulnerability; real impact requires knowing what the parameter
    controls and manually confirming a negative value produces an
    exploitable outcome (negative total, balance increase, etc.), which
    is app-specific business logic this scanner can't verify generically.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)
    numeric_params = {k: v for k, v in existing_params.items() if re.fullmatch(r"\d+", v or "")}
    if not numeric_params:
        return None

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            baseline_resp = await client.get(url)
        except httpx.HTTPError:
            return None
        if baseline_resp.status_code != 200:
            return None

        for param_name, value in numeric_params.items():
            test_params = dict(existing_params)
            test_params[param_name] = "-" + value
            test_url = parsed.copy_with(params=test_params)
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                continue
            body_lower = resp.text[:2000].lower()
            error_language = any(
                kw in body_lower for kw in ("invalid", "must be positive", "error", "bad request")
            )
            if resp.status_code == 200 and not error_language:
                return (
                    f"{test_url}: numeric parameter '{param_name}' (originally {value!r}) "
                    f"accepted a negative value with a 200 response and no obvious "
                    f"validation-error language - candidate for manual business-logic "
                    f"testing (price/quantity/balance manipulation)"
                )
    except httpx.HTTPError as exc:
        logger.info("detective: negative number business logic check failed for %s: %s", url, exc)
    return None


async def check_web_cache_poisoning_unkeyed_header(url: str) -> dict | None:
    """
    Sends a unique marker via X-Forwarded-Host (an "unkeyed" header -
    most caches don't include it in the cache key), then makes a
    SEPARATE, completely plain follow-up request with no special headers
    at all. If the marker still comes back on that plain request, the
    poisoned response got cached and would be served to any other user
    hitting the same URL - that's the actual proof of cache poisoning,
    not just "the header was reflected once" (which check_host_header_
    injection from batch 7 already covers for the non-cached case).
    """
    marker = "swas-cache-poison-" + uuid.uuid4().hex[:10]
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            await client.get(url, headers={"X-Forwarded-Host": marker})
        except httpx.HTTPError:
            return None
        try:
            followup_resp = await client.get(url)
        except httpx.HTTPError:
            return None
        if marker in followup_resp.text:
            return {
                "vuln_type": "web_cache_poisoning_unkeyed_header",
                "severity": "high",
                "evidence": (
                    f"{url}: sending X-Forwarded-Host: {marker} once, then making a "
                    f"completely plain follow-up request with no special headers, still "
                    f"returned the marker - the poisoned response was cached and would be "
                    f"served to any other visitor of this URL."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: cache poisoning check failed for %s: %s", url, exc)
    return None


_WS_URL_RE = re.compile(r'\bws://[^\s"\'<>]+', re.IGNORECASE)


async def check_websocket_downgrade(url: str) -> dict | None:
    """
    Scans an HTTPS page for hardcoded ws:// (unencrypted) WebSocket URLs
    instead of wss://. A WebSocket carrying session tokens, chat
    content, or live app data over plaintext on an otherwise-HTTPS site
    is a real, low-collision structural finding - "ws://" as an exact
    scheme prefix essentially never appears coincidentally in unrelated
    content, so this doesn't need baseline diffing the way generic
    substring checks do.
    """
    if not url.lower().startswith("https://"):
        return None  # only meaningful as a downgrade if the page itself is HTTPS

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: WebSocket downgrade check failed for %s: %s", url, exc)
        return None

    match = _WS_URL_RE.search(resp.text)
    if match:
        return {
            "vuln_type": "websocket_unencrypted_downgrade",
            "severity": "medium",
            "evidence": (
                f"{url}: HTTPS page references an unencrypted WebSocket URL "
                f"({match.group(0)[:100]!r}) instead of wss:// - any data sent over that "
                f"connection (session tokens, live app data) is exposed to network-level "
                f"interception despite the page itself being served over HTTPS."
            ),
        }
    return None


async def check_graphql_query_via_get(url: str) -> str | None:
    """
    Checks whether a GraphQL endpoint accepts queries via GET (as query-
    string parameters) rather than requiring POST. Returns a plain
    string, NOT a findings dict - this is a structural capability check,
    not a vulnerability by itself. It matters because a GET-based query
    rides along with a victim's cookies automatically in a simple cross-
    site request (no preflight needed the way a custom-header POST
    would trigger), which is a real CSRF-chaining candidate - but
    confirming actual impact needs an authenticated session to see what
    data a forced query could exfiltrate, which this scanner doesn't
    have.
    """
    probe_url = url.rstrip("/") + '?query={__typename}'
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        try:
            resp = await client.get(probe_url)
        except httpx.HTTPError:
            return None
    except httpx.HTTPError as exc:
        logger.info("detective: GraphQL GET query check failed for %s: %s", url, exc)
        return None

    try:
        response_json = resp.json()
    except Exception:
        return None
    if isinstance(response_json, dict) and response_json.get("data") and "errors" not in response_json:
        return (
            f"{probe_url}: GraphQL query accepted via GET - candidate for CSRF-chaining "
            f"(rides along with victim cookies with no preflight); confirming real impact "
            f"needs an authenticated session to see what a forced query could exfiltrate"
        )
    return None


_CDN_EDGE_RANGES = [
    # Cloudflare (ipv4)
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Akamai (representative ranges)
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
    "2.16.0.0/13", "95.100.0.0/15",
    # Fastly
    "151.101.0.0/16", "199.27.72.0/21", "146.75.0.0/16",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "204.246.164.0/22",
    "204.246.168.0/22", "205.251.192.0/19", "52.222.128.0/17",
]
_CDN_EDGE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in _CDN_EDGE_RANGES]


def _is_known_cdn_edge_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _CDN_EDGE_NETWORKS)


async def check_origin_ip_waf_bypass(host: str) -> dict | None:
    """
    Resolves the host's A record via DNS-over-HTTPS, then compares a
    normal hostname-based request against a direct request to the raw
    IP (with the Host header stripped to a generic value). If a WAF/CDN
    sits in front of the hostname but the origin server is directly
    reachable on its IP and serves the SAME real content, any
    hostname-based protection (WAF rules, rate limiting, geo-blocking)
    can be bypassed entirely by hitting the origin directly. Proof bar:
    the IP-direct response must actually resemble real application
    content (reasonable size, 200 status), not a default nginx/apache
    placeholder page or a connection failure.
    """
    domain = httpx.URL(host).host
    if not domain or domain.replace(".", "").isdigit():
        return None  # already a bare IP

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        try:
            dns_resp = await client.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                headers={"Accept": "application/dns-json"},
            )
            dns_data = dns_resp.json()
        except Exception:
            return None
        answers = [a.get("data") for a in dns_data.get("Answer", []) if a.get("type") == 1]
        if not answers:
            return None
        origin_ip = answers[0]

        if _is_known_cdn_edge_ip(origin_ip):
            # The public DNS record points at a CDN edge node, not the
            # real origin - hitting this IP directly still goes through
            # the same CDN/WAF layer, so there's nothing to bypass.
            # (This is expected and correct for any site behind
            # Cloudflare/Akamai/Fastly/CloudFront - not a finding.)
            return None

        try:
            hostname_resp = await client.get(host)
        except httpx.HTTPError:
            return None

        scheme = "https" if host.startswith("https") else "http"
        ip_url = f"{scheme}://{origin_ip}/"
        try:
            ip_resp = await client.get(ip_url, headers={"Host": domain})
        except httpx.HTTPError:
            return None

        if (
            ip_resp.status_code == 200
            and len(ip_resp.text) > 200
            and abs(len(ip_resp.text) - len(hostname_resp.text)) < max(200, len(hostname_resp.text) * 0.3)
        ):
            return {
                "vuln_type": "origin_ip_waf_cdn_bypass",
                "severity": "high",
                "evidence": (
                    f"{domain} resolves to {origin_ip}, and requesting that IP directly "
                    f"(with Host: {domain} set explicitly) returned a "
                    f"{len(ip_resp.text)}-byte response closely matching the real "
                    f"hostname-based response ({len(hostname_resp.text)} bytes) - the "
                    f"origin server is directly reachable, bypassing any WAF/CDN/rate-"
                    f"limiting that only protects the hostname."
                ),
            }
    except httpx.HTTPError as exc:
        logger.info("detective: origin IP WAF bypass check failed for %s: %s", host, exc)
    return None


_META_REFRESH_PARAM_RE = re.compile(r"url|redirect|next|return|dest|continue|target", re.IGNORECASE)


async def check_open_redirect_via_meta_refresh(url: str) -> dict | None:
    """
    Complements the header-based open redirect checks (batch 1, batch
    12) with the client-side equivalent: a URL parameter reflected
    unescaped into a <meta http-equiv="refresh" content="...url=..."> 
    tag redirects the browser without ever touching a Location header,
    which bypasses server-side redirect-target validation that only
    inspects outgoing Location headers. Proof uses a unique marker
    domain, so it's a deterministic exact-match, not a coincidental
    substring.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)
    redirect_params = [p for p in existing_params if _META_REFRESH_PARAM_RE.search(p)]
    if not redirect_params:
        return None

    marker_domain = f"evil-swas-meta-{uuid.uuid4().hex[:8]}.test"
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
        for param_name in redirect_params:
            test_params = dict(existing_params)
            test_params[param_name] = f"http://{marker_domain}/"
            test_url = parsed.copy_with(params=test_params)
            try:
                resp = await client.get(test_url)
            except httpx.HTTPError:
                continue
            match = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*' + re.escape(marker_domain),
                resp.text, re.IGNORECASE,
            )
            if match:
                return {
                    "vuln_type": "open_redirect_meta_refresh",
                    "severity": "medium",
                    "evidence": (
                        f"{test_url}: parameter '{param_name}' was reflected unescaped "
                        f"into a <meta http-equiv=\"refresh\"> tag pointing at an "
                        f"attacker-controlled domain - client-side redirect that bypasses "
                        f"Location-header-only validation. Note: open redirect is commonly "
                        f"rated Informative without chained impact."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: meta-refresh open redirect check failed for %s: %s", url, exc)
    return None


async def check_insecure_tls_weak_protocol(host: str) -> dict | None:
    """
    Attempts a raw TLS handshake explicitly forcing TLSv1.0 (deprecated
    since 2021, vulnerable to BEAST and other downgrade-family attacks).
    If the handshake actually completes, the server still accepts a
    protocol version modern clients refuse to negotiate by default -
    real, deterministic (either the handshake completes or it doesn't,
    no substring matching involved).
    """
    hostname = httpx.URL(host).host
    if not hostname or not host.lower().startswith("https://"):
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        return None  # this Python/OpenSSL build doesn't support enabling TLSv1 at all

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=ctx), timeout=5.0
        )
    except Exception:
        return None
    negotiated = None
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            negotiated = ssl_obj.version()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if negotiated == "TLSv1":
        return {
            "vuln_type": "insecure_tls_weak_protocol_accepted",
            "severity": "medium",
            "evidence": (
                f"{hostname}:443 completed a TLS handshake when the client offered ONLY "
                f"TLSv1.0 (deprecated since 2021, vulnerable to BEAST-family downgrade "
                f"attacks) - modern clients won't negotiate this by default, but the "
                f"server still accepts it from any client that does."
            ),
        }
    return None


async def check_dangling_ns_delegation_takeover(hostname: str) -> dict | None:
    """
    A different, rarer, and more severe takeover technique than
    check_subdomain_takeover (batch 1, which only checks CNAME records
    against known SaaS fingerprints). This resolves the subdomain's own
    NS (nameserver delegation) records - if a whole subdomain's DNS was
    ever delegated to a third-party nameserver (a common pattern for
    dev/staging environments hosted elsewhere) and that nameserver's own
    parent domain no longer resolves (NXDOMAIN), then that nameserver
    hostname itself is available for anyone to register - and whoever
    registers it gains the ability to answer DNS for the ENTIRE
    delegated subdomain, not just one hijackable CNAME target. Detected
    read-only via DNS-over-HTTPS lookups only; never attempts to
    register anything.
    """
    hostname = _extract_hostname(hostname)
    if hostname is None:
        return None

    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        ns_resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": hostname, "type": "NS"},
            headers={"accept": "application/dns-json"},
        )
        if ns_resp.status_code != 200:
            return None
        ns_answers = ns_resp.json().get("Answer", [])
        ns_hosts = [a["data"].rstrip(".") for a in ns_answers if a.get("type") == 2]
        if not ns_hosts:
            return None  # no explicit NS delegation for this subdomain - nothing to check

        for ns_host in ns_hosts:
            labels = ns_host.split(".")
            if len(labels) < 2:
                continue
            parent_domain = ".".join(labels[-2:])  # e.g. ns1.example-dns-provider.com -> example-dns-provider.com

            try:
                parent_resp = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": parent_domain, "type": "NS"},
                    headers={"accept": "application/dns-json"},
                )
            except httpx.HTTPError:
                continue
            if parent_resp.status_code != 200:
                continue
            parent_data = parent_resp.json()
            # DNS RCODE 3 == NXDOMAIN - the nameserver's own parent
            # domain doesn't exist at all, meaning it's registerable.
            if parent_data.get("Status") == 3:
                return {
                    "vuln_type": "dangling_ns_delegation_takeover",
                    "severity": "critical",
                    "evidence": (
                        f"{hostname} is NS-delegated to {ns_host}, but {ns_host}'s own "
                        f"parent domain ({parent_domain}) returns NXDOMAIN - that domain is "
                        f"unregistered and available, and whoever registers it can stand up "
                        f"a nameserver answering DNS for the entire {hostname} subdomain, "
                        f"not just a single hijackable CNAME target. Higher-severity than a "
                        f"standard CNAME-based takeover; detected read-only via DNS lookups "
                        f"only, nothing registered."
                    ),
                }
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("detective: dangling NS delegation check failed for %s: %s", hostname, exc)
    return None


