"""
pipeline.py - the orchestrator. This is what actually runs a scan: it
takes a target, runs it through the 5 phases in order (recon, probe,
fuzz, scan, notify), using checkpoint.py to track progress safely and
tools.py to do the real work.

Plain-language explanation: think of this as the project manager. It
doesn't do the scanning itself (tools.py does that) and it doesn't do
the record-keeping itself (checkpoint.py does that) - it just calls
them in the right order, for the right target, and decides what happens
next if something fails.

Phase 1 keeps the "what happens next on failure" logic simple: retry
once, then mark needs_attention and move to the next target. The
smarter signal-based budgeting / early-abort logic discussed for later
phases is NOT in this file yet - this is the straightforward version
that proves the foundation works.
"""

import asyncio
import json
import logging
import os
import re

import asyncpg

from . import checkpoint, detective, fp_filter, tools

# Caps on how many hosts/urls each detective check runs against per
# target, mirroring the existing live_hosts[:10] pattern elsewhere in
# this file - these are cheap checks, but "cheap x thousands of
# subdomains" is still not free, so Phase 1 keeps a conservative ceiling.
_TAKEOVER_CHECK_CAP = 15
_SENSITIVE_URL_CHECK_CAP = 15
_SQLI_TIMING_CHECK_CAP = 8      # each test costs a deliberate multi-second delay - keep tight
_SOURCE_MAP_CHECK_CAP = 10
_OPEN_REDIRECT_CHECK_CAP = 15
_CRLF_CHECK_CAP = 15
_HPP_CHECK_CAP = 15
_SSRF_CHECK_CAP = 15
_SSTI_CHECK_CAP = 10           # multiple payloads tried per param - keep tighter
_IDOR_CANDIDATE_CHECK_CAP = 40 # pure regex match, no network request - cheap
_XSS_CHECK_CAP = 15
_SQLI_ERROR_CHECK_CAP = 10     # extra baseline request per URL on top of per-param probes
_XXE_CHECK_CAP = 10
_DESERIALIZATION_CHECK_CAP = 20
_PATH_TRAVERSAL_CHECK_CAP = 15
_CMDI_CHECK_CAP = 8            # each real hit costs a deliberate multi-second delay - keep tight
_BUCKET_EXPOSURE_CHECK_CAP = 15
_METHOD_OVERRIDE_CHECK_CAP = 15
_REFERRER_LEAK_CHECK_CAP = 15
_OPEN_REDIRECT_ENCODING_CHECK_CAP = 15
_SRI_CHECK_CAP = 15

logger = logging.getLogger("swas.pipeline")

PHASES = ["recon", "probe", "fuzz", "scan", "notify"]


async def run_target_pipeline(
    pool: asyncpg.Pool, project_id: int, target_id: int, target: str
) -> None:
    """
    Runs all 5 phases, in order, for a single target. This function is
    meant to be run concurrently for multiple targets at once (the
    caller decides how many targets run in parallel) - everything in
    here is async and non-blocking.

    If a phase fails after its retry, we stop processing THIS target
    (no point fuzzing a host that recon never found is alive) but we
    do NOT raise an exception out of this function - a problem with one
    target must never crash or block the rest of the queue.
    """
    logger.info("Starting pipeline for target_id=%s (%s)", target_id, target)

    discovered_subdomains: list[str] = []
    live_hosts: list[str] = []
    discovered_urls: list[str] = []
    params_found: dict[str, bool] = {}
    tech_stack: dict[str, list[str]] = {}  # host -> list of detected technologies

    for phase_name in PHASES:
        success = await _run_phase_with_retry(
            pool, project_id, target_id, phase_name, target,
            discovered_subdomains, live_hosts, discovered_urls, params_found, tech_stack,
        )
        if not success:
            logger.warning(
                "Stopping pipeline for target_id=%s after %s phase failed",
                target_id, phase_name,
            )
            break

        # Signal-based budgeting: if probe found zero live hosts, every
        # later phase (fuzz, scan) would just run pointlessly against
        # nothing. Stop here rather than burning time/compute on a dead
        # target - this is the "don't waste resources" behavior we
        # specifically designed for.
        if phase_name == "probe" and not live_hosts:
            logger.info(
                "target_id=%s: no live hosts found, skipping remaining phases (dead target)",
                target_id,
            )
            async with pool.acquire() as conn:
                await checkpoint.mark_remaining_phases_skipped(
                    conn, project_id, target_id, after_phase="probe"
                )
            break

        # Out-of-scope drift check: scope can change mid-engagement (a
        # program updates its brief while a scan is already running).
        # Before the more invasive phases (fuzz/scan) run, re-read the
        # CURRENT in_scope value from the database rather than trusting
        # whatever it was when the scan started. This is a real safety
        # behavior, not just an efficiency one - it stops us from
        # actively fuzzing/scanning something that just got pulled out
        # of scope.
        if phase_name == "probe":
            async with pool.acquire() as conn:
                still_in_scope = await conn.fetchval(
                    "SELECT in_scope FROM scope_targets WHERE id = $1", target_id
                )
            if not still_in_scope:
                logger.warning(
                    "target_id=%s: target was marked out-of-scope after the scan started - "
                    "stopping before fuzz/scan phases run",
                    target_id,
                )
                async with pool.acquire() as conn:
                    await checkpoint.mark_remaining_phases_skipped(
                        conn, project_id, target_id, after_phase="probe"
                    )
                break

    logger.info("Finished pipeline for target_id=%s", target_id)


async def _run_phase_with_retry(
    pool: asyncpg.Pool,
    project_id: int,
    target_id: int,
    phase_name: str,
    target: str,
    discovered_subdomains: list[str],
    live_hosts: list[str],
    discovered_urls: list[str],
    params_found: dict[str, bool],
    tech_stack: dict[str, list[str]],
) -> bool:
    """
    Runs one phase, retrying once if it fails, then giving up and
    marking it needs_attention. Returns True if the phase ultimately
    succeeded, False if it didn't (after using up the retry).
    """
    attempt = 0
    max_attempts = checkpoint.MAX_RETRIES + 1

    while attempt < max_attempts:
        attempt += 1
        async with pool.acquire() as conn:
            phase_run_id = await checkpoint.create_pending_run(
                conn, project_id, target_id, phase_name
            )

            try:
                async with checkpoint.run_phase(conn, phase_run_id, project_id, target_id, phase_name):
                    await _execute_phase(
                        conn, project_id, target_id, phase_name, target,
                        discovered_subdomains, live_hosts, discovered_urls, params_found, tech_stack,
                    )
                return True  # checkpoint.run_phase already marked it completed

            except Exception:
                # checkpoint.run_phase already logged this and marked the
                # row 'failed'. We just decide here whether to retry.
                if attempt >= max_attempts:
                    await checkpoint.mark_needs_attention(
                        conn,
                        phase_run_id,
                        f"Failed after {attempt} attempt(s), giving up on this phase",
                        project_id=project_id,
                        target_id=target_id,
                        phase_name=phase_name,
                    )
                    return False
                logger.info(
                    "Retrying %s for target_id=%s (attempt %s/%s)",
                    phase_name, target_id, attempt + 1, max_attempts,
                )

    return False


async def _execute_phase(
    conn: asyncpg.Connection,
    project_id: int,
    target_id: int,
    phase_name: str,
    target: str,
    discovered_subdomains: list[str],
    live_hosts: list[str],
    discovered_urls: list[str],
    params_found: dict[str, bool],
    tech_stack: dict[str, list[str]],
) -> None:
    """
    The actual work for each phase. Raises an exception if something
    goes wrong - checkpoint.run_phase (the caller) handles catching,
    logging, and recording that.
    """
    if phase_name == "recon":
        await _phase_recon(conn, project_id, target_id, target, discovered_subdomains)

    elif phase_name == "probe":
        await _phase_probe(target, discovered_subdomains, live_hosts, discovered_urls, tech_stack)

    elif phase_name == "fuzz":
        await _phase_fuzz(live_hosts, params_found)

    elif phase_name == "scan":
        await _phase_scan(conn, project_id, target_id, live_hosts, discovered_urls, params_found, tech_stack)

    elif phase_name == "notify":
        await _phase_notify(target)

    else:
        raise ValueError(f"Unknown phase: {phase_name}")


async def _phase_recon(
    conn: asyncpg.Connection,
    project_id: int,
    target_id: int,
    target: str,
    discovered_subdomains: list[str],
) -> None:
    """Subdomain enumeration, then check which ones are actually alive."""
    result = await tools.run_subfinder(target)
    if not result.success:
        raise RuntimeError(f"subfinder failed: {result.error}")

    found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    discovered_subdomains.extend(found or [target])  # fall back to the target itself
    logger.info("recon: found %d subdomains for %s", len(discovered_subdomains), target)

    # Detective check: subdomain takeover via CNAME fingerprinting. Cheap
    # (one DoH lookup + one conditional HTTP fetch per host) and among
    # the highest payout-to-effort ratios in bug bounty, so it runs here
    # unconditionally rather than being gated behind a later phase.
    candidates = discovered_subdomains[:_TAKEOVER_CHECK_CAP]
    logger.info("detective: running takeover check against %d candidate(s)", len(candidates))
    takeover_results = await asyncio.gather(
        *(detective.check_subdomain_takeover(host) for host in candidates),
        return_exceptions=True,
    )
    for res in takeover_results:
        if isinstance(res, Exception):
            logger.debug("takeover check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)


async def _phase_probe(
    target: str,
    discovered_subdomains: list[str],
    live_hosts: list[str],
    discovered_urls: list[str],
    tech_stack: dict[str, list[str]],
) -> None:
    """Check which discovered hosts are alive, and gather historical URLs.

    httpx now runs with -json -td (tech-detect), so each output line is a
    JSON object with the host's URL and its detected tech stack, instead
    of a plain hostname string. We parse that here once - this is the
    "fingerprint once, reuse everywhere" behavior: every other tool
    downstream gets tech_stack instead of re-detecting independently.
    """
    hosts_to_check = discovered_subdomains or [target]

    httpx_result = await tools.run_httpx(hosts_to_check)
    if httpx_result.success:
        for line in httpx_result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                url = record.get("url", "").strip()
                if url:
                    live_hosts.append(url)
                    tech_stack[url] = record.get("tech", [])
            except json.JSONDecodeError:
                # Fall back to treating the raw line as a plain host -
                # never silently drop a live host just because one line
                # wasn't valid JSON (e.g. a stray log line mixed into
                # stdout). No tech info for this one, that's fine.
                live_hosts.append(line)
    # A non-fatal httpx failure shouldn't kill the whole phase - URL
    # discovery below can still proceed even without a live host list.
    # We still raise if BOTH httpx and the URL tools fail (see below).

    gau_result = await tools.run_gau(target)
    if gau_result.success:
        discovered_urls.extend(
            line.strip() for line in gau_result.stdout.splitlines() if line.strip()
        )

    if not httpx_result.success and not gau_result.success:
        raise RuntimeError(
            f"probe phase found nothing usable: httpx={httpx_result.error}, "
            f"gau={gau_result.error}"
        )

    logger.info(
        "probe: %d live hosts, %d historical URLs for %s",
        len(live_hosts), len(discovered_urls), target,
    )


async def _phase_fuzz(live_hosts: list[str], params_found: dict[str, bool]) -> None:
    """
    Discover parameters on live hosts. This determines which hosts are
    worth running sqlmap/dalfox against in the scan phase - we don't run
    those expensive tools blindly against every host.
    """
    for host in live_hosts[:10]:  # Phase 1: cap how many hosts get deep-probed
        result = await tools.run_arjun(host)
        if result.success and result.stdout.strip():
            params_found[host] = True

    logger.info("fuzz: %d hosts have discoverable parameters", len(params_found))
    # Note: we deliberately don't raise here even if nothing was found -
    # "no parameters on this target" is a valid, useful result, not a
    # failure.


async def _phase_scan(
    conn: asyncpg.Connection,
    project_id: int,
    target_id: int,
    live_hosts: list[str],
    discovered_urls: list[str],
    params_found: dict[str, bool],
    tech_stack: dict[str, list[str]],
) -> None:
    """
    Run the actual vulnerability scanners. nuclei runs against all live
    hosts (it's broad and relatively cheap). dalfox and sqlmap ONLY run
    against hosts known to have parameters - this is the rule from the
    spec that avoids wasting time running injection tools against hosts
    with nothing to inject into.

    tech_stack (from probe's httpx -td) is logged here for visibility -
    knowing "this host runs Apache 2.4.7" alongside its findings is
    useful context. We deliberately do NOT use it to skip tools yet
    (e.g. "no CMS detected, skip CMS-specific templates") - that's a
    real future optimization, but doing it safely needs care about which
    detections are reliable enough to gate on. The proven params_found
    check above stays as the sole gating logic for now.
    """
    for host in live_hosts[:10]:  # Phase 1: cap scope for the first working version
        if tech_stack.get(host):
            logger.info("scan: %s detected tech: %s", host, ", ".join(tech_stack[host]))

        _log_aem_pivot_hint(host, tech_stack.get(host, []))

        nuclei_result = await tools.run_nuclei(host)
        if tools.looks_like_real_output(nuclei_result):
            await _save_nuclei_findings(conn, project_id, target_id, nuclei_result.stdout)

        if params_found.get(host):
            dalfox_result = await tools.run_dalfox(host)
            if tools.looks_like_real_output(dalfox_result):
                await _save_finding(conn, project_id, target_id, "dalfox", dalfox_result.stdout)

            sqlmap_result = await tools.run_sqlmap(host)
            if tools.looks_like_real_output(sqlmap_result):
                await _save_finding(conn, project_id, target_id, "sqlmap", sqlmap_result.stdout)

        # Detective checks: CORS misconfiguration and web cache deception.
        # Both are pure-Python, no-new-binary checks (see detective.py) -
        # they run per live host alongside the existing tool-based scans.
        cors_result = await detective.check_cors_misconfig(host)
        if cors_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cors_result)

        cache_result = await detective.check_cache_deception(host)
        if cache_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cache_result)

        # CSP weakness check is recon-only by design - see detective.py's
        # module docstring and check_csp_weakness's own docstring for why
        # this deliberately never becomes a findings-table row.
        csp_note = await detective.check_csp_weakness(host)
        if csp_note is not None:
            logger.info("detective: CSP recon note: %s", csp_note)

        # Batch 3 per-host checks: GraphQL introspection, exposed
        # container control APIs, exposed .git directory.
        graphql_result = await detective.check_graphql_introspection(host)
        if graphql_result is not None:
            await _save_detective_finding(conn, project_id, target_id, graphql_result)

        # Batch 11: GraphQL field-suggestion schema leak. Complements
        # the introspection check right above - some APIs disable
        # __schema introspection but leave "did you mean X?" errors on.
        logger.info("detective: running GraphQL field suggestion check for %s", host)
        graphql_suggestion_result = await detective.check_graphql_field_suggestion_leak(
            host.rstrip("/") + "/graphql"
        )
        if graphql_suggestion_result is not None:
            await _save_detective_finding(conn, project_id, target_id, graphql_suggestion_result)

        container_api_result = await detective.check_exposed_container_api(host)
        if container_api_result is not None:
            await _save_detective_finding(conn, project_id, target_id, container_api_result)

        git_result = await detective.check_git_exposure(host)
        if git_result is not None:
            await _save_detective_finding(conn, project_id, target_id, git_result)

        # Batch 4 per-host checks: exposed Elasticsearch, Prometheus/
        # Spring Actuator, NoSQL DB ports, and Swagger/OpenAPI docs.
        es_result = await detective.check_elasticsearch_exposure(host)
        if es_result is not None:
            await _save_detective_finding(conn, project_id, target_id, es_result)

        actuator_result = await detective.check_actuator_exposure(host)
        if actuator_result is not None:
            await _save_detective_finding(conn, project_id, target_id, actuator_result)

        nosql_result = await detective.check_nosql_db_exposure(host)
        if nosql_result is not None:
            await _save_detective_finding(conn, project_id, target_id, nosql_result)

        swagger_result = await detective.check_swagger_exposure(host)
        if swagger_result is not None:
            await _save_detective_finding(conn, project_id, target_id, swagger_result)

        # Batch 5 per-host checks: WAF fingerprint (recon-only, same
        # pattern as CSP - never saved as a finding), exposed heapdump,
        # WebSocket CSWSH.
        waf_note = await detective.check_waf_fingerprint(host)
        if waf_note is not None:
            logger.info("detective: WAF recon note: %s", waf_note)

        heapdump_result = await detective.check_heapdump_exposure(host)
        if heapdump_result is not None:
            await _save_detective_finding(conn, project_id, target_id, heapdump_result)

        cswsh_result = await detective.check_websocket_cswsh(host)
        if cswsh_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cswsh_result)

        # Batch 6 per-host checks: blind NoSQL injection, JSON type
        # confusion, Apache OptionsBleed. HTTP Parameter Pollution
        # (recon-only) runs separately below against discovered_urls,
        # not per-host, since it needs a real query parameter to work with.
        nosql_bypass_result = await detective.check_blind_nosql_injection(host)
        if nosql_bypass_result is not None:
            await _save_detective_finding(conn, project_id, target_id, nosql_bypass_result)

        type_confusion_result = await detective.check_json_type_confusion(host)
        if type_confusion_result is not None:
            await _save_detective_finding(conn, project_id, target_id, type_confusion_result)

        optionsbleed_result = await detective.check_apache_optionsbleed(host)
        if optionsbleed_result is not None:
            await _save_detective_finding(conn, project_id, target_id, optionsbleed_result)

        # Batch 7 per-host checks: JWT alg confusion, host header
        # injection, exposed framework debug console.
        logger.info("detective: running JWT alg confusion check for %s", host)
        jwt_result = await detective.check_jwt_alg_confusion(host)
        if jwt_result is not None:
            await _save_detective_finding(conn, project_id, target_id, jwt_result)

        # Batch 12: JWT weak/common HMAC signing secret. Pure local
        # cryptography, no extra network requests - kept right next
        # to the alg-confusion check since both work off the same
        # discovered JWT.
        logger.info("detective: running JWT weak secret check for %s", host)
        jwt_weak_secret_result = await detective.check_jwt_weak_secret(host)
        if jwt_weak_secret_result is not None:
            await _save_detective_finding(conn, project_id, target_id, jwt_weak_secret_result)

        logger.info("detective: running host header injection check for %s", host)
        hhi_result = await detective.check_host_header_injection(host)
        if hhi_result is not None:
            await _save_detective_finding(conn, project_id, target_id, hhi_result)

        logger.info("detective: running debug console exposure check for %s", host)
        debug_console_result = await detective.check_debug_console_exposure(host)
        if debug_console_result is not None:
            await _save_detective_finding(conn, project_id, target_id, debug_console_result)

        # Batch 12: exposed admin/management panel. Recon-only - see
        # check_exposed_admin_panel's own docstring - never attempts
        # credentials.
        logger.info("detective: running admin panel exposure check for %s", host)
        admin_panel_note = await detective.check_exposed_admin_panel(host)
        if admin_panel_note is not None:
            logger.info("detective: admin panel note: %s", admin_panel_note)

        # Batch 8 per-host check: prototype pollution via a JSON
        # __proto__ gadget POSTed to the host root. (The other three
        # batch 8 checks - SSTI, API key signature, IDOR candidate
        # flagging - need an actual query-string URL to work with, so
        # they run in the URL-candidate section below instead.)
        logger.info("detective: running prototype pollution check for %s", host)
        proto_pollution_result = await detective.check_prototype_pollution(host)
        if proto_pollution_result is not None:
            await _save_detective_finding(conn, project_id, target_id, proto_pollution_result)

        # Batch 10 per-host check: exposed .env file.
        logger.info("detective: running .env exposure check for %s", host)
        env_file_result = await detective.check_env_file_exposure(host)
        if env_file_result is not None:
            await _save_detective_finding(conn, project_id, target_id, env_file_result)

    # Pre-filter discovered_urls once for all the URL-based checks below.
    # gau/waybackurls output is often messy - malformed concatenated URLs,
    # scope-import junk, etc. - and the SQLi timing check especially
    # shouldn't burn several deliberate seconds on garbage input.
    sane_discovered_urls = [u for u in discovered_urls if detective._looks_like_sane_url(u)]

    # Detective check: sensitive file entropy. Runs against discovered
    # historical URLs (gau/waybackurls output) that look like JS bundles,
    # config files, or backups - capped, since this involves an actual
    # file download per candidate URL rather than a header-only check.
    sensitive_candidates = [
        url for url in sane_discovered_urls if detective._SENSITIVE_FILE_HINTS.search(url)
    ][:_SENSITIVE_URL_CHECK_CAP]
    logger.info(
        "detective: running entropy check against %d sensitive-looking URL(s) out of %d discovered",
        len(sensitive_candidates), len(discovered_urls),
    )
    entropy_results = await asyncio.gather(
        *(detective.check_file_entropy(url) for url in sensitive_candidates),
        return_exceptions=True,
    )
    for res in entropy_results:
        if isinstance(res, Exception):
            logger.debug("entropy check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: leaked source maps. Only worth trying against
    # discovered URLs that look like JS bundles.
    js_candidates = [
        url for url in sane_discovered_urls if url.lower().split("?")[0].endswith(".js")
    ][:_SOURCE_MAP_CHECK_CAP]
    logger.info("detective: running source map check against %d JS bundle URL(s)", len(js_candidates))
    source_map_results = await asyncio.gather(
        *(detective.check_source_map_leak(url) for url in js_candidates),
        return_exceptions=True,
    )
    for res in source_map_results:
        if isinstance(res, Exception):
            logger.debug("source map check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: exposed Firebase database. Reuses the same
    # js_candidates list gathered for the source map check above - both
    # checks are "download this JS bundle and inspect it" operations, no
    # reason to build the candidate list twice.
    logger.info("detective: running Firebase exposure check against %d JS bundle URL(s)", len(js_candidates))
    firebase_results = await asyncio.gather(
        *(detective.check_firebase_exposure(url) for url in js_candidates),
        return_exceptions=True,
    )
    for res in firebase_results:
        if isinstance(res, Exception):
            logger.debug("firebase exposure check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: open redirect. check_open_redirect() itself only
    # acts when a query param name looks redirect-related, so we just
    # need to feed it every URL with a query string and let it decide -
    # filtering here again would just duplicate that logic.
    redirect_candidates = [url for url in sane_discovered_urls if "=" in url][
        :_OPEN_REDIRECT_CHECK_CAP
    ]
    logger.info(
        "detective: running open redirect check against %d candidate URL(s)", len(redirect_candidates)
    )
    redirect_results = await asyncio.gather(
        *(detective.check_open_redirect(url) for url in redirect_candidates),
        return_exceptions=True,
    )
    for res in redirect_results:
        if isinstance(res, Exception):
            logger.debug("open redirect check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: blind SQL injection via timing. The most
    # expensive check here (each real hit costs several deliberate
    # seconds of wait), so it only runs against URLs that already have
    # query parameters worth injecting into, and is capped tighter than
    # the others (_SQLI_TIMING_CHECK_CAP).
    param_candidates = [url for url in sane_discovered_urls if "=" in url][:_SQLI_TIMING_CHECK_CAP]
    logger.info(
        "detective: running blind SQLi timing check against %d parameterized URL(s)",
        len(param_candidates),
    )
    sqli_results = await asyncio.gather(
        *(detective.check_blind_sqli_timing(url) for url in param_candidates),
        return_exceptions=True,
    )
    for res in sqli_results:
        if isinstance(res, Exception):
            logger.debug("blind SQLi timing check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: CRLF injection / HTTP response splitting. Same
    # candidate source as open redirect - any URL with a query string is
    # worth trying, check_crlf_injection() itself only confirms real
    # header injection, not just a URL that happens to contain "=".
    crlf_candidates = [url for url in sane_discovered_urls if "=" in url][:_CRLF_CHECK_CAP]
    logger.info(
        "detective: running CRLF injection check against %d candidate URL(s)", len(crlf_candidates)
    )
    crlf_results = await asyncio.gather(
        *(detective.check_crlf_injection(url) for url in crlf_candidates),
        return_exceptions=True,
    )
    for res in crlf_results:
        if isinstance(res, Exception):
            logger.debug("CRLF injection check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: HTTP Parameter Pollution. Recon-only (see
    # check_http_param_pollution's own docstring) - logs a note when
    # duplicate params change server behavior, never files a finding.
    hpp_candidates = [url for url in sane_discovered_urls if "=" in url][:_HPP_CHECK_CAP]
    logger.info(
        "detective: running HTTP parameter pollution check against %d candidate URL(s)",
        len(hpp_candidates),
    )
    hpp_results = await asyncio.gather(
        *(detective.check_http_param_pollution(url) for url in hpp_candidates),
        return_exceptions=True,
    )
    for res in hpp_results:
        if isinstance(res, Exception):
            logger.debug("HTTP parameter pollution check raised: %s", res)
            continue
        if res is not None:
            logger.info("detective: HPP recon note: %s", res)

    # Detective check: reflected SSRF (batch 7) - non-blind only,
    # requires an existing query parameter to redirect at cloud
    # metadata/localhost.
    ssrf_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSRF_CHECK_CAP]
    logger.info(
        "detective: running reflected SSRF check against %d candidate URL(s)", len(ssrf_candidates)
    )
    ssrf_results = await asyncio.gather(
        *(detective.check_ssrf_reflected(url) for url in ssrf_candidates),
        return_exceptions=True,
    )
    for res in ssrf_results:
        if isinstance(res, Exception):
            logger.debug("reflected SSRF check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: server-side template injection (batch 8).
    ssti_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSTI_CHECK_CAP]
    logger.info(
        "detective: running SSTI check against %d candidate URL(s)", len(ssti_candidates)
    )
    ssti_results = await asyncio.gather(
        *(detective.check_ssti(url) for url in ssti_candidates),
        return_exceptions=True,
    )
    for res in ssti_results:
        if isinstance(res, Exception):
            logger.debug("SSTI check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: known API key/secret signature leak (batch 8).
    # Reuses js_candidates - both this and source-map/Firebase checks
    # are "download this JS bundle and inspect it" operations.
    logger.info(
        "detective: running API key signature check against %d JS bundle URL(s)", len(js_candidates)
    )
    api_key_results = await asyncio.gather(
        *(detective.check_api_key_leak_signature(url) for url in js_candidates),
        return_exceptions=True,
    )
    for res in api_key_results:
        if isinstance(res, Exception):
            logger.debug("API key signature check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: IDOR candidate flagging (batch 8). Recon-only -
    # see check_idor_candidate's own docstring - never becomes a
    # findings-table row, just a log line pointing at manual-
    # verification targets. Pure URL-pattern matching, no network
    # request per candidate, so this can safely run against a larger
    # slice of sane_discovered_urls than the request-issuing checks.
    idor_candidates = sane_discovered_urls[:_IDOR_CANDIDATE_CHECK_CAP]
    logger.info(
        "detective: running IDOR candidate flagging against %d URL(s)", len(idor_candidates)
    )
    idor_notes = await asyncio.gather(
        *(detective.check_idor_candidate(url) for url in idor_candidates),
        return_exceptions=True,
    )
    for res in idor_notes:
        if isinstance(res, Exception):
            logger.debug("IDOR candidate check raised: %s", res)
            continue
        if res is not None:
            logger.info("detective: IDOR candidate note: %s", res)

    # Detective check: reflected XSS (batch 9).
    xss_candidates = [url for url in sane_discovered_urls if "=" in url][:_XSS_CHECK_CAP]
    logger.info(
        "detective: running reflected XSS check against %d candidate URL(s)", len(xss_candidates)
    )
    xss_results = await asyncio.gather(
        *(detective.check_reflected_xss(url) for url in xss_candidates),
        return_exceptions=True,
    )
    for res in xss_results:
        if isinstance(res, Exception):
            logger.debug("reflected XSS check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: error-based SQL injection (batch 9). Complements
    # the timing-based check above with a higher-confidence signature
    # match; kept as its own capped candidate list since it issues an
    # extra baseline request per URL on top of the per-param probes.
    sqli_error_candidates = [url for url in sane_discovered_urls if "=" in url][:_SQLI_ERROR_CHECK_CAP]
    logger.info(
        "detective: running error-based SQLi check against %d candidate URL(s)", len(sqli_error_candidates)
    )
    sqli_error_results = await asyncio.gather(
        *(detective.check_sqli_error_based(url) for url in sqli_error_candidates),
        return_exceptions=True,
    )
    for res in sqli_error_results:
        if isinstance(res, Exception):
            logger.debug("error-based SQLi check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: XXE, error-based detection only (batch 9). Only
    # worth trying against real endpoints, so this reuses the same "="
    # candidate list as a reasonable-cost slice rather than trying
    # every discovered URL.
    xxe_candidates = [url for url in sane_discovered_urls if "=" in url][:_XXE_CHECK_CAP]
    logger.info(
        "detective: running XXE check against %d candidate URL(s)", len(xxe_candidates)
    )
    xxe_results = await asyncio.gather(
        *(detective.check_xxe_error_based(url) for url in xxe_candidates),
        return_exceptions=True,
    )
    for res in xxe_results:
        if isinstance(res, Exception):
            logger.debug("XXE check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: insecure deserialization signature (batch 9).
    # Recon-only - see check_insecure_deserialization_signature's own
    # docstring - never becomes a findings-table row on its own, just
    # a log line pointing at manual gadget-chain testing targets.
    deserialization_candidates = sane_discovered_urls[:_DESERIALIZATION_CHECK_CAP]
    logger.info(
        "detective: running deserialization signature check against %d URL(s)",
        len(deserialization_candidates),
    )
    deserialization_notes = await asyncio.gather(
        *(detective.check_insecure_deserialization_signature(url) for url in deserialization_candidates),
        return_exceptions=True,
    )
    for res in deserialization_notes:
        if isinstance(res, Exception):
            logger.debug("deserialization signature check raised: %s", res)
            continue
        if res is not None:
            logger.info("detective: deserialization signature note: %s", res)

    # Detective check: path traversal / LFI (batch 10).
    path_traversal_candidates = [url for url in sane_discovered_urls if "=" in url][:_PATH_TRAVERSAL_CHECK_CAP]
    logger.info(
        "detective: running path traversal check against %d candidate URL(s)", len(path_traversal_candidates)
    )
    path_traversal_results = await asyncio.gather(
        *(detective.check_path_traversal_lfi(url) for url in path_traversal_candidates),
        return_exceptions=True,
    )
    for res in path_traversal_results:
        if isinstance(res, Exception):
            logger.debug("path traversal check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: OS command injection, blind timing-based
    # (batch 10). Same cost profile as the SQLi timing check - each
    # real hit costs several deliberate seconds - so capped tighter.
    cmdi_candidates = [url for url in sane_discovered_urls if "=" in url][:_CMDI_CHECK_CAP]
    logger.info(
        "detective: running OS command injection check against %d parameterized URL(s)",
        len(cmdi_candidates),
    )
    cmdi_results = await asyncio.gather(
        *(detective.check_os_command_injection(url) for url in cmdi_candidates),
        return_exceptions=True,
    )
    for res in cmdi_results:
        if isinstance(res, Exception):
            logger.debug("OS command injection check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: publicly-listable cloud storage bucket
    # (batch 10). Runs against any page that might reference a
    # bucket name, not just parameterized URLs - reuses
    # sane_discovered_urls directly rather than the "=" filter.
    bucket_candidates = sane_discovered_urls[:_BUCKET_EXPOSURE_CHECK_CAP]
    logger.info(
        "detective: running cloud storage bucket exposure check against %d URL(s)",
        len(bucket_candidates),
    )
    bucket_results = await asyncio.gather(
        *(detective.check_cloud_storage_bucket_exposure(url) for url in bucket_candidates),
        return_exceptions=True,
    )
    for res in bucket_results:
        if isinstance(res, Exception):
            logger.debug("cloud storage bucket exposure check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: DOM XSS sink flagging (batch 11). Recon-only -
    # reuses js_candidates, same "download and inspect" shape as
    # check_api_key_leak_signature and the source-map/Firebase checks.
    logger.info(
        "detective: running DOM XSS sink check against %d JS bundle URL(s)", len(js_candidates)
    )
    dom_xss_notes = await asyncio.gather(
        *(detective.check_dom_xss_sink_flagging(url) for url in js_candidates),
        return_exceptions=True,
    )
    for res in dom_xss_notes:
        if isinstance(res, Exception):
            logger.debug("DOM XSS sink check raised: %s", res)
            continue
        if res is not None:
            logger.info("detective: DOM XSS sink note: %s", res)

    # Detective check: auth bypass via method/path override headers
    # (batch 11). Runs against any discovered URL, not just
    # parameterized ones - it self-filters by requiring a 401/403
    # baseline before trying anything, so pointing it at URLs that
    # were never protected in the first place just costs one cheap
    # request and returns None.
    method_override_candidates = sane_discovered_urls[:_METHOD_OVERRIDE_CHECK_CAP]
    logger.info(
        "detective: running auth bypass (method override) check against %d URL(s)",
        len(method_override_candidates),
    )
    method_override_results = await asyncio.gather(
        *(detective.check_auth_bypass_via_method_override(url) for url in method_override_candidates),
        return_exceptions=True,
    )
    for res in method_override_results:
        if isinstance(res, Exception):
            logger.debug("auth bypass method override check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: sensitive data leaking via Referer (batch 11).
    # Needs an actual query parameter to have anything to check.
    referrer_leak_candidates = [url for url in sane_discovered_urls if "=" in url][:_REFERRER_LEAK_CHECK_CAP]
    logger.info(
        "detective: running Referrer-Policy leak check against %d candidate URL(s)",
        len(referrer_leak_candidates),
    )
    referrer_leak_results = await asyncio.gather(
        *(detective.check_referrer_policy_sensitive_leak(url) for url in referrer_leak_candidates),
        return_exceptions=True,
    )
    for res in referrer_leak_results:
        if isinstance(res, Exception):
            logger.debug("Referrer-Policy leak check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: open redirect via encoding/parsing bypass
    # (batch 12). Complements the batch-1 open redirect check.
    open_redirect_encoding_candidates = [url for url in sane_discovered_urls if "=" in url][:_OPEN_REDIRECT_ENCODING_CHECK_CAP]
    logger.info(
        "detective: running open redirect encoding bypass check against %d candidate URL(s)",
        len(open_redirect_encoding_candidates),
    )
    open_redirect_encoding_results = await asyncio.gather(
        *(detective.check_open_redirect_encoding_bypass(url) for url in open_redirect_encoding_candidates),
        return_exceptions=True,
    )
    for res in open_redirect_encoding_results:
        if isinstance(res, Exception):
            logger.debug("open redirect encoding bypass check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: missing Subresource Integrity (batch 12).
    # Recon-only - see check_missing_sri's own docstring.
    sri_candidates = sane_discovered_urls[:_SRI_CHECK_CAP]
    logger.info(
        "detective: running missing SRI check against %d URL(s)", len(sri_candidates)
    )
    sri_notes = await asyncio.gather(
        *(detective.check_missing_sri(url) for url in sri_candidates),
        return_exceptions=True,
    )
    for res in sri_notes:
        if isinstance(res, Exception):
            logger.debug("missing SRI check raised: %s", res)
            continue
        if res is not None:
            logger.info("detective: missing SRI note: %s", res)


# A hostname like "aem-prod.example.com" or a tech-stack detection
# ("AEM", "Adobe Experience Manager") is a strong recon signal, not a
# vulnerability by itself. When it shows up, it's worth pointing manual
# testing effort at AEM-specific attack surface (exposed dispatcher
# config, /crx/de and other default admin interfaces, SSRF via AEM's
# own fetch/import features) instead of spending time on generic
# TLS/cert scanner output for that host.
_AEM_HOSTNAME_PATTERN = re.compile(r"\baem\b|aem[-_]?(prod|stage|dev|author|publish)", re.IGNORECASE)
_AEM_TECH_PATTERN = re.compile(r"aem|adobe experience manager", re.IGNORECASE)


def _log_aem_pivot_hint(host: str, tech: list[str]) -> None:
    """
    Zero-cost recon nudge: if this host looks like it's running Adobe
    Experience Manager (by hostname convention or by httpx -td tech
    detection), log a note pointing at AEM-specific manual testing
    rather than letting the host just blend in as "another target for
    generic nuclei/dalfox/sqlmap runs". This does not change what scans
    are run in Phase 1 - it's a visibility aid so a human reviewing logs
    knows where the higher-value manual effort is likely to pay off.
    """
    hostname_hit = bool(_AEM_HOSTNAME_PATTERN.search(host))
    tech_hit = any(_AEM_TECH_PATTERN.search(t) for t in tech)
    if hostname_hit or tech_hit:
        logger.info(
            "recon: %s looks like Adobe Experience Manager (AEM) - consider pivoting "
            "manual testing to dispatcher config exposure, default/misconfigured admin "
            "interfaces (e.g. /crx/de), and SSRF opportunities, rather than reporting "
            "generic TLS/cert findings for this host",
            host,
        )


# nuclei's own severity tags map directly onto our schema's severity
# values - no AI needed to know that nuclei already says "[medium]".
_NUCLEI_SEVERITY_TAGS = {"critical", "high", "medium", "low", "info"}


async def _save_nuclei_findings(
    conn: asyncpg.Connection, project_id: int, target_id: int, raw_output: str
) -> None:
    """
    Splits nuclei's bundled multi-line output into individual findings,
    one per template match, instead of one blended finding for everything
    nuclei found. This matters because nuclei already tells us the real
    severity per line (e.g. "[CVE-2023-48795] ... [medium] ...") - bundling
    27 results of mixed severity into one finding meant AI triage had to
    guess at one verdict for a mix of info-level noise and a real CVE,
    which is exactly the inconsistency we saw in real testing (the same
    bundle got triaged as medium one time, high another). Splitting lets
    each line get scored on its own merits.

    Falls back to saving the whole block as one finding if a line doesn't
    match nuclei's expected bracket format - never silently drops output
    just because it didn't parse as expected.
    """
    strict_mode = os.environ.get("FP_FILTER_STRICT_MODE", "").lower() in ("1", "true", "yes")
    cleaned_output, removed = fp_filter.filter_noise("nuclei", raw_output, strict_mode=strict_mode)
    if removed:
        logger.info("fp_filter: dropped %d noisy line(s) from nuclei output", removed)

    unparsed_lines = []
    saved_count = 0

    for line in cleaned_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # nuclei -silent format: [template-id:tag] [protocol] [severity] target [extras]
        # The severity is always the SECOND bracketed group after the
        # template id and protocol.
        brackets = re.findall(r"\[([^\]]*)\]", line)
        severity = None
        if len(brackets) >= 3 and brackets[2].lower() in _NUCLEI_SEVERITY_TAGS:
            severity = brackets[2].lower()

        vuln_type = brackets[0].split(":")[0] if brackets else "nuclei"

        if severity is None:
            unparsed_lines.append(line)
            continue

        await conn.execute(
            """
            INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
            VALUES ($1, $2, 'nuclei', $3, $4, $5)
            """,
            project_id, target_id, vuln_type, severity, line[:1000],
        )
        saved_count += 1

    if unparsed_lines:
        # Anything that didn't match the expected format still gets
        # saved, just bundled and left as 'unknown' for triage to handle
        # - we never want a parsing miss to mean lost data.
        await _save_finding(conn, project_id, target_id, "nuclei", "\n".join(unparsed_lines))

    logger.info("nuclei: saved %d individual findings, %d unparsed line(s) bundled separately",
                saved_count, len(unparsed_lines))


async def _save_finding(
    conn: asyncpg.Connection, project_id: int, target_id: int, tool_name: str, raw_output: str
) -> None:
    """
    Writes a candidate finding to the database. Phase 1 keeps severity
    as 'unknown' and vuln_type as the tool name - the AI-assisted
    triage that assigns real severity/VRT categories comes in a later
    phase. This just makes sure no tool output is silently lost.

    Known-noisy lines (per fp_filter.py) are stripped before storage -
    zero-cost, no AI call, based on well-documented FP patterns. If
    filtering removes EVERYTHING, we skip saving a finding at all rather
    than storing an empty/useless row.
    """
    strict_mode = os.environ.get("FP_FILTER_STRICT_MODE", "").lower() in ("1", "true", "yes")
    cleaned_output, removed = fp_filter.filter_noise(tool_name, raw_output, strict_mode=strict_mode)
    if removed:
        logger.info("fp_filter: dropped %d noisy line(s) from %s output", removed, tool_name)

    if not cleaned_output.strip():
        logger.info("fp_filter: all %s output was noise, skipping finding", tool_name)
        return

    await conn.execute(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, $3, $4, 'unknown', $5)
        """,
        project_id,
        target_id,
        tool_name,
        tool_name,  # Phase 1: vuln_type defaults to the tool name until triage exists
        cleaned_output[:5000],  # cap stored evidence length
    )


async def _save_detective_finding(
    conn: asyncpg.Connection, project_id: int, target_id: int, result: dict
) -> None:
    """
    Saves a finding produced by detective.py's checks (subdomain takeover,
    CORS misconfig, cache deception, entropy). Unlike _save_finding /
    _save_nuclei_findings, these don't go through fp_filter or get
    stored as 'unknown' severity - each detective check already did its
    own confirmation logic before returning a result at all, and already
    knows its own severity/vuln_type, so there's nothing left to filter
    or triage.
    """
    await conn.execute(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, 'detective', $3, $4, $5)
        """,
        project_id,
        target_id,
        result["vuln_type"],
        result["severity"],
        result["evidence"][:5000],
    )
    logger.info(
        "detective: saved %s finding (severity=%s) for target_id=%s",
        result["vuln_type"], result["severity"], target_id,
    )


async def _phase_notify(target: str) -> None:
    """
    Best-effort notification. A failure here should not be treated as a
    pipeline failure - it's a courtesy, not a critical step.

    Phase 1 has no notification destination configured yet (no Slack/
    Discord webhook, etc.) - rather than calling the notify tool and
    logging a confusing-looking error every single scan, we skip it
    cleanly and say so. Once a real destination is set up (a later,
    deliberate decision - see NOTIFY_WEBHOOK_URL in .env), this will
    start actually sending alerts.
    """
    if not os.environ.get("NOTIFY_WEBHOOK_URL"):
        logger.info("notify: skipped (no notification destination configured yet)")
        return

    result = await tools.run_notify(f"Scan completed for {target}")
    if not result.success:
        logger.info("notify phase had a non-fatal issue: %s", result.error)
