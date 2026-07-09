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
