"""
Shared helpers/constants used by 2+ check categories below.

Split out of the original monolithic detective.py - see detective/__init__.py
for the package-level docstring and full batch history.
"""

import logging
import math
import re

import httpx

logger = logging.getLogger("swas.detective")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# --------------------------------------------------------------------------
# Shared connection pool
# --------------------------------------------------------------------------
# Every check in this package used to open its own `httpx.AsyncClient()`,
# meaning every single check did its own fresh TCP+TLS handshake even when
# ten other checks were about to (or had just) hit the exact same host.
# With 140+ checks per target that's a lot of redundant handshakes - slower
# scans, more load on our own box, and more repeated-connection noise that
# can trip a target's rate limiting before we've even gotten to the checks
# that matter.
#
# get_transport() hands back one process-wide httpx.AsyncHTTPTransport
# whose underlying connection pool is what actually gets reused. Callers
# still create their own `httpx.AsyncClient(transport=get_transport())` per
# check (cheap - it's just a thin wrapper), but MUST NOT call
# `client.aclose()` / use `async with ... as client:` on it, because
# AsyncClient.aclose() unconditionally closes its transport - including one
# it doesn't own - which would tear down the shared pool for every other
# in-flight check. The per-check client object itself is left for the
# garbage collector; the pooled connections it borrowed live on in the
# shared transport for the next check to reuse.
_shared_transport: httpx.AsyncHTTPTransport | None = None


def get_transport() -> httpx.AsyncHTTPTransport:
    global _shared_transport
    if _shared_transport is None:
        _shared_transport = httpx.AsyncHTTPTransport(
            verify=False,
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
            retries=0,
        )
    return _shared_transport


async def close_shared_transport() -> None:
    """Call once from app shutdown. Not needed between individual checks."""
    global _shared_transport
    if _shared_transport is not None:
        await _shared_transport.aclose()
        _shared_transport = None

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


# Paths that are near-certain to hold test fixtures / example code rather
# than real shipped secrets - open-source repos routinely hardcode
# high-entropy-looking dummy tokens in exactly these locations (the
# Vercel sveltejs/kit dead-end: a fake uploadToken sitting in a test
# fixture, not a live credential).
_TEST_FIXTURE_PATH_HINTS = re.compile(
    r"(?:^|/)(?:__tests__|test|tests|testing|spec|specs|fixture|fixtures|"
    r"example|examples|mock|mocks|__mocks__|sample|samples|demo|playground|"
    r"e2e|stories)(?:/|$|\.)",
    re.IGNORECASE,
)

# Value substrings that mark a token as an obvious placeholder/dummy
# rather than a real secret, regardless of how "random" it looks by
# entropy alone (e.g. "sk_test_51H8x...", "fake-upload-token-abc123").
_PLACEHOLDER_VALUE_HINTS = re.compile(
    r"(?:^|[_\-])(?:test|dummy|fake|sample|example|placeholder|xxxx|changeme|"
    r"your[_\-]?)|sk_test_|pk_test_",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _replace_query_param(parsed, query_params: dict, target_param: str, value: str) -> str:
    """Rebuilds `url` with `target_param`'s value swapped for `value`,
    leaving every other query parameter untouched."""
    new_params = {k: v[0] for k, v in query_params.items()}
    new_params[target_param] = value
    new_query = urlencode(new_params)
    return urlunparse(parsed._replace(query=new_query))


_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"]


