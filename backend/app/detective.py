"""
detective.py - "detective mindset" checks: pure-Python, zero-new-binary
vulnerability detectors that don't need a CLI tool (unlike tools.py,
which shells out to subfinder/nuclei/etc.).

Plain-language explanation: these are small, focused checks SWAS can run
against a host or URL to catch a few specific, well-known, high-payout bug
classes that generic scanners don't reliably find:

Batch 1:
  1. Subdomain takeover (CNAME points to an unclaimed third-party service)
  2. CORS misconfiguration (server blindly trusts any Origin header)
  3. Web cache deception (private data cached under a fake static URL)
  4. Sensitive file entropy (leaked API keys/secrets sitting in plain JS
     or config files that were never meant to be public)

Batch 2:
  5. Blind SQL injection via timing (quiet, WAF-friendly SLEEP() probes -
     no UNION/OR 1=1 noise that trips signature-based firewalls)
  6. Leaked source maps (.js.map files that let you reconstruct original
     source and find hardcoded secrets/internal URLs)
  7. Open redirect (a redirect-looking parameter that sends users to an
     attacker-controlled domain instead of validating it)
  8. CSP weakness analysis - NOT saved as a standalone finding. A weak
     Content-Security-Policy is routinely triaged as Informative by
     programs unless it's demonstrated alongside a real XSS. This check
     exists purely to log which hosts have loose CSP directives so you
     know where to point manual/dalfox XSS testing effort - never to
     report CSP looseness by itself.

Batch 3:
  9. GraphQL introspection mapper (finds exposed GraphQL endpoints and
     pulls their full schema - types, fields, mutations - which often
     reveals internal/admin functionality never meant to be public)
 10. Exposed Firebase database (JS bundles frequently hardcode a
     Firebase project's databaseURL; if that DB allows anonymous reads,
     the entire dataset is public)
 11. Exposed Docker/Kubernetes control API (an unauthenticated Docker
     daemon or kubelet API on its default port hands over full container
     control)
 12. Exposed .git directory (if a deployed app's .git folder is publicly
     served, HEAD/config confirm it - full source reconstruction from
     this is a bigger follow-up task, not automated in this batch)

Batch 4:
 13. Exposed Elasticsearch index (default port 9200 with no auth hands
     over the full index catalog, and from there, the actual documents)
 14. Exposed Prometheus/Spring Actuator metrics (these endpoints
     frequently dump environment variables, connection strings, and
     internal service maps that were never meant to leave the cluster)
 15. Exposed NoSQL database port (MongoDB 27017, CouchDB 5984 answering
     with no authentication at all)
 16. Swagger/OpenAPI doc parser (finds a live API spec, then flags any
     path whose name suggests admin/internal functionality being
     described - and thus discoverable - without auth)

Batch 5:
 17. WAF/honeypot fingerprinting - NOT saved as a finding (like the CSP
     check). Detects Cloudflare/Akamai/Imperva-style block-page
     signatures so other checks in the same run can tell "the WAF
     blocked us" apart from "the target actually responded that way" -
     without this, a WAF block page can get misread as a real result by
     checks further down the pipeline.
 18. Exposed heapdump (parses a leaked JVM/app heapdump for credential
     and token strings using the same entropy/keyword detection as the
     Actuator and file-entropy checks)
 19. CRLF / HTTP response-splitting (injects a carriage-return-newline
     sequence into a redirect-like parameter and checks whether it lands
     in the raw response headers - only reported when it demonstrates
     actual header injection, e.g. a forged Set-Cookie, not just an
     unencoded newline being reflected in a body)
 20. WebSocket hijacking / CSWSH (opens a WebSocket handshake with an
     arbitrary Origin header and checks whether the server accepts the
     connection - a missing Origin check on an authenticated WebSocket
     lets any website ride a victim's session)

Batch 6:
 21. Blind NoSQL injection (tests login/search forms with MongoDB-style
     operator payloads like {"$ne": ""} - no test account needed, since
     a successful bypass IS the account access)
 22. JSON type confusion (mutates a discovered POST JSON body's field
     types - array/boolean/integer-overflow substitutions - looking for
     backend parsers that mishandle the unexpected shape; confirmation
     is HTTP-status/response-shape based, not a login bypass claim)
 23. HTTP Parameter Pollution recon (duplicates a query parameter and
     checks whether the response changes based on which value "wins" -
     NOT saved as a standalone finding, see check_http_param_pollution's
     own docstring for why: pollution alone proves a parsing
     inconsistency exists, not that it bypasses anything, without a
     privileged session to test against)
 24. Apache OptionsBleed (a malformed OPTIONS request can trigger a
     race condition in vulnerable Apache configs that leaks a fragment
     of server memory into the Allow header - a known, specific,
     easily-confirmed CVE-class bug, not a fuzzing guess)

Every function here is read-only / non-destructive - no writes, no
exploitation, just detection. Each returns None when nothing is found, or
a dict describing the finding when something is. Callers (pipeline.py)
decide what to do with that.
"""

import asyncio
import base64
import hashlib
import logging
import math
import os
import re
import ssl
import time
from collections import Counter
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("swas.detective")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Every httpx.AsyncClient below is created with verify=False. This matches
# the rest of this stack (nuclei, httpx-pd, sqlmap - all Go/CLI tools that
# skip strict TLS verification by default) rather than trusting Python's
# stricter default. We are the client intentionally probing someone else's
# infrastructure as an authorized tester, not a browser that needs to trust
# the site - refusing to even connect because a staging/internal host has a
# mismatched or self-signed cert would blind us to exactly the messy,
# interesting hosts (aem-prod, dev-unstable, auth-nonprod, etc.) that are
# often the most worth testing. This was confirmed as a real bug in live
# testing: every CORS/cache-deception check was silently failing with
# CERTIFICATE_VERIFY_FAILED against wildcard-scoped targets before this.


# ---------------------------------------------------------------------
# 1. Subdomain takeover (CNAME fingerprinting)
# ---------------------------------------------------------------------
# Signature list: if a CNAME points at one of these services AND the
# service responds with its own "not claimed / no such site" page, the
# subdomain is very likely hijackable. This is the same public technique
# tools like subjack/nuclei use - it's standard bug bounty recon, not a
# secret list. Kept short and high-confidence on purpose: a shorter list
# of well-known, reliably-fingerprinted services beats a huge list that
# generates noisy false positives.
_MAX_REASONABLE_URL_LENGTH = 500


def _extract_hostname(candidate: str) -> str | None:
    """
    Normalizes a takeover-check candidate into a bare hostname, or
    returns None if it's not something a CNAME lookup makes sense for.
    Scope-import data is often messy - HackerOne/Bugcrowd scope lists
    routinely include app-store links, raw numeric app IDs, or
    malformed concatenated URLs scraped by gau/waybackurls. This exists
    so those get skipped quietly instead of wasting a DNS lookup (and
    cluttering logs) on something that was never a hostname to begin
    with.
    """
    candidate = candidate.strip()
    if not candidate or len(candidate) > _MAX_REASONABLE_URL_LENGTH:
        return None
    if candidate.count("://") > 1:
        return None  # classic sign of a scraper gluing multiple URLs together

    host = urlparse(candidate).netloc if "://" in candidate else candidate.split("/")[0]
    host = host.split(":")[0].split("@")[-1]  # strip port and any userinfo@ prefix

    if not host or "." not in host:
        return None
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        return None
    return host.lower()


def _looks_like_sane_url(url: str) -> bool:
    """
    Basic sanity gate for the URL-based checks (SQLi timing, open
    redirect, source maps). Rejects the same categories of scraper junk
    as _extract_hostname, plus an overall length cap - a single blind
    SQLi timing test costs several deliberate seconds, so it's worth a
    cheap check up front rather than burning that time on garbage input.
    """
    url = url.strip()
    if not url or len(url) > _MAX_REASONABLE_URL_LENGTH:
        return False
    if url.count("://") > 1:
        return False
    parsed = urlparse(url)
    if not parsed.netloc or "." not in parsed.netloc:
        return False
    return True


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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
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


# ---------------------------------------------------------------------
# 2. CORS misconfiguration
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# 3. Web cache deception
# ---------------------------------------------------------------------

# Only worth testing paths that look like they'd return authenticated /
# personal data - hitting this against every static asset wastes cycles
# and produces meaningless results.
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
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


# ---------------------------------------------------------------------
# 4. Sensitive file entropy checker
# ---------------------------------------------------------------------
# Only worth downloading/scanning files that could plausibly contain
# secrets - random images/fonts/CSS waste bandwidth and produce nothing.
_SENSITIVE_FILE_HINTS = re.compile(
    r"\.(js|json|env|ya?ml|config|cfg|ini|xml|txt)$|\b(config|backup|\.env|settings)\b",
    re.IGNORECASE,
)

# Matches a "key: value" or "KEY=value" looking token so we only run
# entropy math on plausible secret-shaped substrings, not entire minified
# JS blobs (which are naturally high-entropy and would be pure noise).
_TOKEN_PATTERN = re.compile(
    r"""["']?([A-Za-z0-9_]{3,40}(?:key|secret|token|password|pwd|api|auth)[A-Za-z0-9_]{0,10})["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{12,100})["']""",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


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

    logger.info("detective: checking file entropy for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
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
        if entropy > 4.0:
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


# ---------------------------------------------------------------------
# 5. Blind SQL injection via timing (WAF-quiet)
# ---------------------------------------------------------------------
# WAFs pattern-match on loud payloads (UNION SELECT, OR 1=1). A timing
# payload just asks the database to pause - nothing that looks like an
# attack signature. We confirm with a 3-step measurement (baseline ->
# delayed -> zero-delay control) specifically to rule out ordinary
# network jitter before ever calling this a finding: a single slow
# response proves nothing, three consistent measurements do.
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
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0), verify=False) as client:
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


def _replace_query_param(parsed, query_params: dict, target_param: str, value: str) -> str:
    """Rebuilds `url` with `target_param`'s value swapped for `value`,
    leaving every other query parameter untouched."""
    new_params = {k: v[0] for k, v in query_params.items()}
    new_params[target_param] = value
    new_query = urlencode(new_params)
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------
# 6. Leaked source maps
# ---------------------------------------------------------------------
# Same secret-shaped-token pattern used by check_file_entropy - a source
# map's "sourcesContent" is effectively the developer's original,
# unminified code, so it's worth running the same entropy check against
# it as we would any other config/JS file.
_SECRET_KEYWORD_PATTERN = re.compile(
    r"(AWS_SECRET|DB_PASSWORD|JWT_SECRET|API_KEY|PRIVATE_KEY|ACCESS_TOKEN)",
    re.IGNORECASE,
)


async def check_source_map_leak(js_url: str) -> dict | None:
    """
    If `js_url` is a JS bundle, checks whether the matching `.js.map`
    source map is also publicly exposed. If it is, and the reconstructed
    source contains secret-shaped tokens or known secret keyword names,
    flags it - this is the case that actually matters. A source map with
    no secrets in it just tells you the code structure, which is a
    real but much lower-value finding, so we deliberately don't report
    that case at all here (avoids padding your report queue with weak
    Informative-risk findings).
    """
    if not js_url.lower().split("?")[0].endswith(".js"):
        return None

    map_url = js_url + ".map"
    logger.info("detective: checking source map leak for %s", map_url)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(map_url)
    except httpx.HTTPError as exc:
        logger.info("detective: source map check failed for %s: %s", map_url, exc)
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    if "sources" not in data:
        return None  # not actually a source map, just a 200 on that path

    sources_content = data.get("sourcesContent") or []
    combined = "\n".join(s for s in sources_content if isinstance(s, str))
    if not combined:
        return None

    keyword_hits = set(_SECRET_KEYWORD_PATTERN.findall(combined))
    entropy_hits = []
    for match in _TOKEN_PATTERN.finditer(combined):
        key_name, value = match.group(1), match.group(2)
        if _shannon_entropy(value) > 4.0:
            entropy_hits.append(key_name)

    if not keyword_hits and not entropy_hits:
        return None

    findings_summary = ", ".join(sorted(keyword_hits | set(entropy_hits))[:8])
    return {
        "vuln_type": "leaked_source_map",
        "severity": "high",
        "evidence": (
            f"{map_url} is publicly exposed and reconstructs to original source "
            f"containing likely secrets: {findings_summary}. Original bundle: {js_url}"
        ),
    }


# ---------------------------------------------------------------------
# 7. Open redirect
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
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


# ---------------------------------------------------------------------
# 8. CSP weakness analysis (recon-only - see module docstring)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
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


# ---------------------------------------------------------------------
# 9. GraphQL introspection mapper
# ---------------------------------------------------------------------
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"]
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
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


# ---------------------------------------------------------------------
# 10. Exposed Firebase database
# ---------------------------------------------------------------------
_FIREBASE_URL_PATTERN = re.compile(
    r"https?://([a-z0-9\-]+)\.firebaseio\.com", re.IGNORECASE
)


async def check_firebase_exposure(js_url: str) -> dict | None:
    """
    Downloads a JS bundle looking for a hardcoded Firebase databaseURL
    (a routine finding - Firebase config is client-side by design). The
    actual check is whether that database allows anonymous reads: if
    appending /.json to the databaseURL returns real data instead of
    `null` or a permission-denied error, the whole dataset is public.
    """
    if not js_url.lower().split("?")[0].endswith(".js"):
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(js_url)
    except httpx.HTTPError as exc:
        logger.info("detective: firebase check fetch failed for %s: %s", js_url, exc)
        return None

    if resp.status_code != 200:
        return None

    matches = set(_FIREBASE_URL_PATTERN.findall(resp.text))
    if not matches:
        return None

    logger.info(
        "detective: checking Firebase exposure for %d project(s) found in %s",
        len(matches), js_url,
    )
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for project in list(matches)[:2]:
                db_url = f"https://{project}.firebaseio.com/.json"
                try:
                    db_resp = await client.get(db_url)
                except httpx.HTTPError:
                    continue
                body = db_resp.text.strip()
                if db_resp.status_code == 200 and body and body != "null":
                    preview = body[:200].replace("\n", " ")
                    return {
                        "vuln_type": "exposed_firebase_database",
                        "severity": "critical",
                        "evidence": (
                            f"Firebase project '{project}' (found in {js_url}) allows "
                            f"anonymous reads at {db_url}. Data preview: {preview}..."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: firebase DB check failed: %s", exc)
    return None


# ---------------------------------------------------------------------
# 11. Exposed Docker/Kubernetes control API
# ---------------------------------------------------------------------
# (port, kind, path) - default ports for each service's unauthenticated
# API. A short connect timeout matters a lot here: most hosts simply
# don't have these ports open, and we don't want that (expected, common)
# case to slow down the pipeline while it waits on a dead connection.
_CONTAINER_API_TARGETS = [
    (2375, "docker", "/version", "http"),
    (2376, "docker", "/version", "https"),
    (10250, "kubelet", "/pods", "https"),
    (10255, "kubelet", "/pods", "http"),
]
_CONTAINER_PROBE_TIMEOUT = httpx.Timeout(4.0, connect=2.5)


async def check_exposed_container_api(host: str) -> dict | None:
    """
    Probes the default Docker daemon and Kubernetes kubelet ports for
    an unauthenticated control API. A live match here is about as
    critical as findings get - full container/pod control with zero
    auth - so this is intentionally conservative: it only fires on a
    response shape that's essentially impossible to get by accident
    (ApiVersion field for Docker, items array for kubelet).
    """
    hostname = _extract_hostname(host)
    if hostname is None:
        return None

    try:
        async with httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, verify=False) as client:
            for port, kind, path, scheme in _CONTAINER_API_TARGETS:
                url = f"{scheme}://{hostname}:{port}{path}"
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue  # port closed/filtered/refused - the overwhelmingly common case

                if resp.status_code != 200:
                    continue

                if kind == "docker" and '"ApiVersion"' in resp.text:
                    return {
                        "vuln_type": "exposed_docker_api",
                        "severity": "critical",
                        "evidence": (
                            f"{url} responds with a live Docker daemon API version string - "
                            f"unauthenticated Docker control endpoint exposed."
                        ),
                    }
                if kind == "kubelet" and '"items"' in resp.text:
                    return {
                        "vuln_type": "exposed_kubelet_api",
                        "severity": "critical",
                        "evidence": (
                            f"{url} responds with a live pod listing - "
                            f"unauthenticated kubelet API exposed."
                        ),
                    }
    except Exception as exc:  # noqa: BLE001 - this check touches raw sockets on
        # arbitrary ports across many hosts; a narrow except here would miss
        # legitimate low-level connection failures that httpx doesn't always
        # wrap as httpx.HTTPError (e.g. some TLS/socket edge cases)
        logger.info("detective: container API check failed for %s: %s", hostname, exc)
    return None


# ---------------------------------------------------------------------
# 12. Exposed .git directory
# ---------------------------------------------------------------------

async def check_git_exposure(host: str) -> dict | None:
    """
    Checks whether `host` publicly serves its .git/HEAD file - the
    single most reliable, lowest-cost signal that a deployed app's full
    .git directory (and with it, complete source history) is exposed.
    Full source reconstruction from an exposed .git directory (walking
    the object store, rebuilding the tree) is a meaningfully bigger task
    than this single check - this function only confirms exposure exists
    so you know where reconstruction effort is worth spending.
    """
    url = host.rstrip("/") + "/.git/HEAD"
    logger.info("detective: checking git exposure for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: git exposure check failed for %s: %s", url, exc)
        return None

    body = resp.text.strip()
    if resp.status_code == 200 and body.startswith("ref:"):
        return {
            "vuln_type": "exposed_git_directory",
            "severity": "high",
            "evidence": (
                f"{url} is publicly accessible and returns a valid git HEAD reference "
                f"({body[:100]}) - the full .git directory (source history, and "
                f"potentially hardcoded secrets in old commits) is exposed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 13. Exposed Elasticsearch index
# ---------------------------------------------------------------------

async def check_elasticsearch_exposure(host: str) -> dict | None:
    """
    Elasticsearch's default config (still common in the wild) binds to
    0.0.0.0:9200 with zero authentication. _cat/indices?format=json is
    the single cheapest confirmation - a real Elasticsearch cluster with
    no auth returns the full index catalog to anyone who asks.
    """
    hostname = _extract_hostname(host)
    if hostname is None:
        return None

    url = f"http://{hostname}:9200/_cat/indices?format=json"
    logger.info("detective: checking Elasticsearch exposure for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, verify=False) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: Elasticsearch check failed for %s: %s", url, exc)
        return None

    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None

    if isinstance(data, list) and data and all(isinstance(d, dict) and "index" in d for d in data[:1]):
        index_names = [d.get("index") for d in data][:10]
        return {
            "vuln_type": "exposed_elasticsearch",
            "severity": "critical",
            "evidence": (
                f"{url} returns {len(data)} index name(s) with zero authentication: "
                f"{', '.join(str(n) for n in index_names)}"
            ),
        }
    return None


# ---------------------------------------------------------------------
# 14. Exposed Prometheus / Spring Actuator metrics
# ---------------------------------------------------------------------
_ACTUATOR_PATHS = ["/actuator/env", "/actuator", "/actuator/prometheus", "/metrics"]


async def check_actuator_exposure(host: str) -> dict | None:
    """
    /actuator/env on an exposed Spring Boot app dumps the entire runtime
    configuration - property sources, env vars, sometimes connection
    strings - which is why it's checked first and treated as the more
    severe case. The other actuator/metrics paths are checked too but
    scored lower, since a bare metrics dump alone is a weaker finding
    unless it happens to contain secret-shaped values (reusing the same
    entropy/keyword detection as check_file_entropy).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            for path in _ACTUATOR_PATHS:
                url = base + path
                logger.info("detective: checking actuator/metrics exposure for %s", url)
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text

                if path == "/actuator/env" and '"propertySources"' in body:
                    keyword_hits = set(_SECRET_KEYWORD_PATTERN.findall(body))
                    entropy_hits = {
                        m.group(1) for m in _TOKEN_PATTERN.finditer(body)
                        if _shannon_entropy(m.group(2)) > 4.0
                    }
                    all_hits = keyword_hits | entropy_hits
                    severity = "critical" if all_hits else "high"
                    hits_note = (
                        f" Includes secret-shaped values: {', '.join(sorted(all_hits)[:5])}."
                        if all_hits else ""
                    )
                    return {
                        "vuln_type": "exposed_spring_actuator_env",
                        "severity": severity,
                        "evidence": (
                            f"{url} exposes the full Spring Boot runtime environment "
                            f"(config, property sources) with no authentication.{hits_note}"
                        ),
                    }

                if path in ("/actuator", "/actuator/prometheus", "/metrics") and (
                    '"_links"' in body or body.startswith("# HELP") or body.startswith("# TYPE")
                ):
                    return {
                        "vuln_type": "exposed_actuator_metrics",
                        "severity": "medium",
                        "evidence": (
                            f"{url} exposes application metrics/actuator endpoints with no "
                            f"authentication - review the raw output manually for anything sensitive."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: actuator check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 15. Exposed NoSQL database port (CouchDB, MongoDB)
# ---------------------------------------------------------------------

async def _check_couchdb_exposure(hostname: str) -> dict | None:
    url = f"http://{hostname}:5984/_all_dbs"
    logger.info("detective: checking CouchDB exposure for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, verify=False) as client:
            resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    if isinstance(data, list):
        return {
            "vuln_type": "exposed_couchdb",
            "severity": "critical",
            "evidence": f"{url} returns the full database list with zero authentication: {data[:10]}",
        }
    return None


def _bson_int32_command(field_name: str) -> bytes:
    """Hand-encodes a minimal single-field BSON document like
    {field_name: 1} - just enough BSON to speak MongoDB's wire protocol
    for one specific command, without pulling in a BSON library."""
    name_bytes = field_name.encode() + b"\x00"
    body = b"\x10" + name_bytes + (1).to_bytes(4, "little")
    doc = body + b"\x00"
    return (len(doc) + 4).to_bytes(4, "little") + doc


def _mongo_op_query(collection: str, bson_doc: bytes) -> bytes:
    """Wraps a BSON command document in a MongoDB OP_QUERY wire message
    (opCode 2004) targeting `collection` (e.g. 'admin.$cmd')."""
    coll_bytes = collection.encode() + b"\x00"
    body = (
        (1).to_bytes(4, "little")       # requestID
        + (0).to_bytes(4, "little")     # responseTo
        + (2004).to_bytes(4, "little")  # opCode: OP_QUERY
        + (0).to_bytes(4, "little")     # flags
        + coll_bytes
        + (0).to_bytes(4, "little")     # numberToSkip
        + (1).to_bytes(4, "little", signed=True)  # numberToReturn
        + bson_doc
    )
    return (len(body) + 4).to_bytes(4, "little") + body


async def _check_mongodb_exposure(hostname: str) -> dict | None:
    """
    Sends a raw, hand-encoded listDatabases command over MongoDB's wire
    protocol with no credentials. isMaster is deliberately NOT used as
    the signal here - MongoDB always answers isMaster pre-auth by design
    (it's part of the driver handshake), so a successful isMaster proves
    nothing about whether auth is actually required. listDatabases does
    require auth on a properly configured instance, so a real database
    list coming back with no error is the actual signal.

    This is a best-effort, defensively-wrapped check: any parsing
    failure or unexpected response just returns None rather than
    raising, since a hand-rolled wire-protocol client is inherently more
    fragile than an HTTP-based check.
    """
    port = 27017
    logger.info("detective: checking MongoDB exposure for %s:%d", hostname, port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=3.0
        )
    except (OSError, asyncio.TimeoutError):
        return None

    try:
        cmd_doc = _bson_int32_command("listDatabases")
        message = _mongo_op_query("admin.$cmd", cmd_doc)
        writer.write(message)
        await writer.drain()

        raw_len = await asyncio.wait_for(reader.readexactly(4), timeout=3.0)
        total_len = int.from_bytes(raw_len, "little")
        if total_len <= 4 or total_len > 65536:
            return None
        rest = await asyncio.wait_for(reader.readexactly(total_len - 4), timeout=3.0)
        response = raw_len + rest

        looks_unauthenticated = (
            b"databases" in response
            and b"not authorized" not in response
            and b"requires authentication" not in response
            and b"errmsg" not in response
        )
        if looks_unauthenticated:
            return {
                "vuln_type": "exposed_mongodb",
                "severity": "critical",
                "evidence": (
                    f"{hostname}:{port} answers an unauthenticated listDatabases command - "
                    f"MongoDB instance has no authentication enabled. Verify manually with "
                    f"'mongosh --host {hostname} --eval \"db.adminCommand({{listDatabases:1}})\"' "
                    f"before reporting, since this check uses a hand-rolled wire-protocol client."
                ),
            }
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - best-effort cleanup, never let this raise
            pass
    return None


async def check_nosql_db_exposure(host: str) -> dict | None:
    """Tries CouchDB (HTTP-based, straightforward) then MongoDB
    (raw wire-protocol, best-effort) against `host`'s default ports."""
    hostname = _extract_hostname(host)
    if hostname is None:
        return None

    couch_result = await _check_couchdb_exposure(hostname)
    if couch_result is not None:
        return couch_result
    return await _check_mongodb_exposure(hostname)


# ---------------------------------------------------------------------
# 16. Swagger / OpenAPI doc parser
# ---------------------------------------------------------------------
_SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json",
]
_SENSITIVE_API_PATH_HINTS = re.compile(
    r"admin|internal|debug|manage|actuator|private|staff|superuser|backdoor",
    re.IGNORECASE,
)


async def check_swagger_exposure(host: str) -> dict | None:
    """
    Probes common Swagger/OpenAPI spec paths. A live spec by itself is
    routinely low-value/Informative (most programs expect API docs to
    be somewhat public) - so this only files a finding when the spec
    itself lists admin/internal-looking paths, meaning the documentation
    is revealing functionality that arguably shouldn't be discoverable
    at all, not just documenting an already-public API.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            for path in _SWAGGER_PATHS:
                url = base + path
                logger.info("detective: checking Swagger/OpenAPI exposure for %s", url)
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    spec = resp.json()
                except ValueError:
                    continue

                paths = spec.get("paths") if isinstance(spec, dict) else None
                if not isinstance(paths, dict) or not paths:
                    continue

                sensitive_paths = [p for p in paths if _SENSITIVE_API_PATH_HINTS.search(p)][:10]
                if not sensitive_paths:
                    continue  # a plain public API spec alone isn't worth filing

                return {
                    "vuln_type": "exposed_api_documentation",
                    "severity": "medium",
                    "evidence": (
                        f"{url} is a publicly accessible API spec ({len(paths)} total paths) "
                        f"including admin/internal-looking endpoints with no visible auth "
                        f"requirement documented: {', '.join(sensitive_paths)}"
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: Swagger exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 17. WAF/honeypot fingerprinting (recon-only - see module docstring)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(host)
    except httpx.HTTPError:
        return None

    header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    body_sample = resp.text[:2000].lower()
    for waf_name, signatures in _WAF_SIGNATURES.items():
        if any(sig in header_blob or sig in body_sample for sig in signatures):
            return f"{host}: WAF/CDN detected - {waf_name}"
    return None


# ---------------------------------------------------------------------
# 18. Exposed heapdump
# ---------------------------------------------------------------------
_HEAPDUMP_PATHS = ["/actuator/heapdump", "/heapdump", "/heapdump.json"]
# Heapdumps can be multi-gigabyte files. We only need enough of the
# start to catch secret-shaped strings without pulling the whole thing -
# Java stores strings inline in the heap, so plaintext credentials near
# the start are common when they exist at all. This is a real coverage
# tradeoff (secrets further into the dump will be missed), not a
# complete secret scan.
_HEAPDUMP_MAX_BYTES = 500_000


async def check_heapdump_exposure(host: str) -> dict | None:
    """
    Checks common heapdump paths and, if one is publicly served, samples
    the first _HEAPDUMP_MAX_BYTES bytes and reuses the same secret
    keyword/entropy detection as check_actuator_exposure. Only reports
    when actual secret-shaped values are found in that sample - a bare
    "heapdump file exists" without visible secrets in the sampled portion
    isn't reported here (consistent with how check_source_map_leak and
    check_swagger_exposure are calibrated elsewhere in this file).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
            for path in _HEAPDUMP_PATHS:
                url = base + path
                logger.info("detective: checking heapdump exposure for %s", url)
                chunk = b""
                try:
                    async with client.stream("GET", url) as resp:
                        if resp.status_code != 200:
                            continue
                        async for data in resp.aiter_bytes():
                            chunk += data
                            if len(chunk) >= _HEAPDUMP_MAX_BYTES:
                                break
                except httpx.HTTPError:
                    continue

                if len(chunk) < 1000:
                    continue  # too small to be a real heapdump - likely a 404/error page

                # Heapdumps are binary, but Java stores strings as
                # contiguous readable runs - lenient latin-1 decode lets
                # the existing regex-based detectors work against it.
                text_sample = chunk.decode("latin-1", errors="ignore")
                keyword_hits = set(_SECRET_KEYWORD_PATTERN.findall(text_sample))
                entropy_hits = {
                    m.group(1) for m in _TOKEN_PATTERN.finditer(text_sample)
                    if _shannon_entropy(m.group(2)) > 4.0
                }
                all_hits = keyword_hits | entropy_hits
                if not all_hits:
                    continue

                return {
                    "vuln_type": "exposed_heapdump",
                    "severity": "critical",
                    "evidence": (
                        f"{url} serves a heapdump file. Secret-shaped values found in the "
                        f"first {len(chunk)} bytes sampled: {', '.join(sorted(all_hits)[:5])}. "
                        f"Note: only a small prefix of the file was analyzed - the full dump "
                        f"likely contains more."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: heapdump check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 19. CRLF / HTTP response-splitting
# ---------------------------------------------------------------------
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


async def check_crlf_injection(url: str) -> dict | None:
    """
    Injects a CRLF sequence + a marker Set-Cookie into each of the
    first 2 query parameters on `url`. The only thing that counts as
    confirmation is the marker actually showing up in the RAW response
    headers httpx parsed back out - meaning the server split our input
    into a real second header line, not just reflected a literal
    newline character somewhere in the response body (which has no
    security impact and isn't CRLF injection).
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return None

    param_names = list(query_params.keys())[:2]
    logger.info("detective: checking CRLF injection for %s", url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
            for param in param_names:
                mutated = _inject_raw_query_param(url, param, _CRLF_PAYLOAD)
                try:
                    resp = await client.get(mutated)
                except httpx.HTTPError:
                    continue

                injected = any(_CRLF_MARKER in v for v in resp.headers.values())
                if injected:
                    return {
                        "vuln_type": "crlf_injection",
                        "severity": "medium",
                        "evidence": (
                            f"{url} param '{param}': injecting a CRLF sequence produced a forged "
                            f"'{_CRLF_MARKER}' header/cookie in the raw response - confirmed HTTP "
                            f"response splitting, not just a reflected newline in the body."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: CRLF injection check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 20. WebSocket hijacking (CSWSH)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 21 & 22 share candidate paths and a confirmation pattern: send a
# baseline request with garbage credentials (expected to fail, no
# session), then a payload request (NoSQL operator or type-confused
# value), and only confirm a bypass if the payload response looks
# authenticated in a way the baseline didn't - a new session cookie
# AND a success-shaped status where the baseline had neither. Neither
# check trusts status code alone, since plenty of apps return 200 with
# an error body.
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 21. Blind NoSQL injection
# ---------------------------------------------------------------------

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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
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


# ---------------------------------------------------------------------
# 22. JSON type confusion
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
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


# ---------------------------------------------------------------------
# 23. HTTP Parameter Pollution (recon-only - see module docstring)
# ---------------------------------------------------------------------

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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, verify=False) as client:
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


# ---------------------------------------------------------------------
# 24. Apache OptionsBleed (CVE-2017-9798)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
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
