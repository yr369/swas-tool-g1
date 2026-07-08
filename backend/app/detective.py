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

Every function here is read-only / non-destructive - no writes, no
exploitation, just detection. Each returns None when nothing is found, or
a dict describing the finding when something is. Callers (pipeline.py)
decide what to do with that.
"""

import logging
import math
import re
import time
from collections import Counter
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("swas.detective")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


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
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
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
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0)) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
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
