"""
Infrastructure/config exposure checks: leaked git/docker/k8s/CI
config, debug endpoints, admin consoles for DBs and dev tools,
backup/dump files, missing security headers, and related disclosure bugs.

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
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
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


async def _check_couchdb_exposure(hostname: str) -> dict | None:
    url = f"http://{hostname}:5984/_all_dbs"
    logger.info("detective: checking CouchDB exposure for %s", url)
    try:
        client = httpx.AsyncClient(timeout=_CONTAINER_PROBE_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_exposed_elmah_axd(host: str) -> dict | None:
    """
    Checks for a live elmah.axd endpoint - ELMAH logs full unhandled
    .NET exceptions including stack traces, request details, and
    sometimes cookies/session data for every error the application has
    ever thrown, all in one unauthenticated feed.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_exposed_trace_axd(host: str) -> dict | None:
    """
    Checks for a live trace.axd endpoint - ASP.NET's built-in request
    trace viewer, which can disclose session IDs, ViewState, full
    request/response headers, and application internals for recent
    requests when left enabled in production.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_exposed_couchdb_fauxton(host: str) -> dict | None:
    """
    Complements check_nosql_db_exposure (batch 1, which tests CouchDB's
    REST API root) by checking specifically for the Fauxton web admin
    UI being served - a different exposure surface (the UI layer, not
    just the API), reachable at /_utils/ on a standard CouchDB install.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=False)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_travis_yml_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible .travis.yml. Travis CI configs
    occasionally contain plaintext deploy keys or misconfigured
    `env: global:` secrets that were meant to stay encrypted -
    disclosing CI/CD pipeline structure at minimum, credentials at worst.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_circleci_config_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible .circleci/config.yml. Same
    reasoning as check_travis_yml_exposure - CircleCI configs disclose
    build/deploy pipeline structure and occasionally embed values meant
    to come only from CircleCI's encrypted contexts.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


async def check_helm_values_exposure(host: str) -> dict | None:
    """
    Checks for a publicly-accessible Helm values.yaml at common paths -
    Kubernetes deployment configuration that sometimes includes inline
    secrets (DB connection strings, API keys) when a chart wasn't
    properly set up to pull them from a Secret resource instead.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport(), follow_redirects=True)
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


_GRAPHQL_SENSITIVE_FIELD_KEYWORDS = (
    "password", "passwordhash", "password_hash", "hash", "salt", "secret",
    "token", "apikey", "api_key", "ssn", "socialsecuritynumber", "creditcard",
    "credit_card", "cvv", "privatekey", "private_key",
)


async def check_graphql_sensitive_field_exposure(host: str) -> dict | None:
    """
    Complements check_graphql_introspection (batch 3), which only proves
    the schema is readable. Parses that same schema for field names that
    are sensitive by NAME (password, ssn, secret, token, etc. - the same
    keyword class check_excessive_data_exposure_api flags), picks the
    query root's first object type that exposes one, and issues ONE real
    query for that field with a small guessed-ID range. Fires only if
    the response actually contains a non-null, non-empty value for that
    field - proving the schema doesn't just DESCRIBE a sensitive field,
    it will hand the value over on request, with zero extra
    authorization check.
    """
    base = host.rstrip("/")
    try:
        client = httpx.AsyncClient(timeout=_TIMEOUT, transport=get_transport())
        for path in _GRAPHQL_PATHS:
            url = base + path
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

            for gql_type in schema["types"]:
                type_name = gql_type.get("name")
                fields = gql_type.get("fields") or []
                if not type_name or type_name.startswith("__") or not fields:
                    continue
                field_names = [f["name"] for f in fields if f.get("name")]
                sensitive_field = next(
                    (f for f in field_names if any(kw in f.lower() for kw in _GRAPHQL_SENSITIVE_FIELD_KEYWORDS)),
                    None,
                )
                id_field = next((f for f in field_names if f.lower() == "id"), None)
                if not sensitive_field or not id_field:
                    continue

                query_field = type_name[0].lower() + type_name[1:]
                for guess_id in ("1", "2"):
                    query = {
                        "query": (
                            f"{{ {query_field}(id: \"{guess_id}\") "
                            f"{{ {id_field} {sensitive_field} }} }}"
                        )
                    }
                    try:
                        q_resp = await client.post(url, json=query)
                    except httpx.HTTPError:
                        continue
                    try:
                        q_data = q_resp.json()
                    except ValueError:
                        continue
                    obj = (q_data.get("data") or {}).get(query_field)
                    if isinstance(obj, dict) and obj.get(sensitive_field):
                        value_preview = str(obj[sensitive_field])[:6] + "…"
                        return {
                            "vuln_type": "graphql_sensitive_field_overexposure",
                            "severity": "high",
                            "evidence": (
                                f"{url}: querying `{query_field}(id: {guess_id!r})` for "
                                f"type '{type_name}' returned a non-empty value for the "
                                f"sensitive-named field '{sensitive_field}' ({value_preview}) "
                                f"with no additional authorization - unauthenticated "
                                f"over-fetch of sensitive data via GraphQL, not just an "
                                f"exposed schema."
                            ),
                        }
    except httpx.HTTPError as exc:
        logger.info("detective: GraphQL sensitive field exposure check failed for %s: %s", host, exc)
    return None


