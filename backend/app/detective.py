"""
detective.py - "detective mindset" checks: pure-Python, zero-new-binary
vulnerability detectors that don't need a CLI tool (unlike tools.py,
which shells out to subfinder/nuclei/etc.).

Plain-language explanation: these are small, focused checks SWAS can run
against a host or URL to catch a few specific, well-known, high-payout bug
classes that generic scanners don't reliably find:

  1. Subdomain takeover (CNAME points to an unclaimed third-party service)
  2. CORS misconfiguration (server blindly trusts any Origin header)
  3. Web cache deception (private data cached under a fake static URL)
  4. Sensitive file entropy (leaked API keys/secrets sitting in plain JS
     or config files that were never meant to be public)

Every function here is read-only / non-destructive - no writes, no
exploitation, just detection. Each returns None when nothing is found, or
a dict describing the finding when something is. Callers (pipeline.py)
decide what to do with that.
"""

import logging
import math
import re
from collections import Counter

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
        logger.debug("takeover check failed for %s: %s", hostname, exc)
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
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers={"Origin": fake_origin})
    except httpx.HTTPError as exc:
        logger.debug("CORS check failed for %s: %s", url, exc)
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
        logger.debug("cache deception check failed for %s: %s", url, exc)
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

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.debug("entropy check fetch failed for %s: %s", url, exc)
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
