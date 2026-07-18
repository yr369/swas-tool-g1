"""
pipeline.py - the orchestrator. This is what actually runs a scan: it
takes a target, runs it through the 6 phases in order (recon, probe,
fuzz, scan, triage, notify), using checkpoint.py to track progress
safely and tools.py to do the real work.

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

from . import checkpoint, detective, fp_filter, gate, git_dumper, logic_hunter, tools, triage

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
_SSRF_PORT_SCAN_CHECK_CAP = 15
_MASS_ASSIGNMENT_CHECK_CAP = 15
_VERB_TAMPERING_CHECK_CAP = 15
_NEGATIVE_NUMBER_CHECK_CAP = 15
_PREDICTABLE_TOKEN_CHECK_CAP = 25  # pure pattern match, no extra requests beyond the URL's own
_CLICKJACKING_CHECK_CAP = 15
_HARDCODED_SECRETS_CHECK_CAP = 15
_LFI_PHP_WRAPPER_CHECK_CAP = 10
_LDAP_INJECTION_CHECK_CAP = 10
_XPATH_INJECTION_CHECK_CAP = 10
_CACHE_POISONING_CHECK_CAP = 15
_CSRF_TOKEN_CHECK_CAP = 15
_FILE_UPLOAD_CANDIDATE_CHECK_CAP = 15
_WEBSOCKET_DOWNGRADE_CHECK_CAP = 15
_EXCESSIVE_EXPOSURE_CHECK_CAP = 15
_API_VERSION_DOWNGRADE_CHECK_CAP = 15
_SQLI_BOOLEAN_CHECK_CAP = 10
_SVG_UPLOAD_CHECK_CAP = 15
_JSONP_XSS_CHECK_CAP = 15
_BACKUP_FILE_CHECK_CAP = 15
_AZURE_BLOB_CHECK_CAP = 15
_CORS_SUBDOMAIN_BYPASS_CHECK_CAP = 15
_HSTS_CHECK_CAP = 15
_COOKIE_SAMESITE_CHECK_CAP = 15
_SESSION_ID_URL_CHECK_CAP = 25  # pure pattern match, no extra requests
_META_REFRESH_CHECK_CAP = 15
_WSDL_CHECK_CAP = 15
_UUID_VERSION_CHECK_CAP = 25  # pure pattern match, no extra requests
_OAUTH_STATE_CHECK_CAP = 15
_BASIC_AUTH_HTTP_CHECK_CAP = 15
_COOKIE_SECURE_CHECK_CAP = 15
_FIREBASE_RTDB_CHECK_CAP = 15
_SSRF_GCP_CHECK_CAP = 10
_SSRF_AZURE_CHECK_CAP = 10
_SSRF_DO_CHECK_CAP = 10
_XFF_BYPASS_CHECK_CAP = 15
_REFERER_BYPASS_CHECK_CAP = 15
_APIKEY_IN_URL_CHECK_CAP = 25  # pure pattern match, no extra requests
_PW_RESET_ENUM_CHECK_CAP = 10

logger = logging.getLogger("swas.pipeline")

PHASES = ["recon", "probe", "fuzz", "scan", "gate", "logic_hunter", "triage", "notify"]


async def run_target_pipeline(
    pool: asyncpg.Pool, project_id: int, target_id: int, target: str
) -> None:
    """
    Runs all 6 phases, in order, for a single target. This function is
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

        # Stamped unconditionally here (not per-phase) - this marks "a scan
    # attempt happened and finished" for the host, regardless of whether
    # every phase succeeded, some were skipped as a dead target, or scope
    # drifted mid-run. That is what "last scanned" should mean to an
    # operator glancing at the host list - not "last fully clean run".
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE scope_targets SET last_scanned_at = now() WHERE id = $1", target_id
        )
    
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

    elif phase_name == "gate":
        await _phase_gate(conn, project_id)

    elif phase_name == "logic_hunter":
        await _phase_logic_hunter(conn, project_id)

    elif phase_name == "triage":
        await _phase_triage(conn, project_id)

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

        # Batch 14: two narrower, deterministic CORS variants grouped
        # with the generic misconfig check above.
        logger.info("detective: running CORS null-origin bypass check for %s", host)
        cors_null_origin_result = await detective.check_cors_null_origin_bypass(host)
        if cors_null_origin_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cors_null_origin_result)

        logger.info("detective: running CORS wildcard+credentials check for %s", host)
        cors_wildcard_creds_result = await detective.check_cors_wildcard_with_credentials(host)
        if cors_wildcard_creds_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cors_wildcard_creds_result)

        cache_result = await detective.check_cache_deception(host)
        if cache_result is not None:
            await _save_detective_finding(conn, project_id, target_id, cache_result)

        # CSP weakness check is recon-only by design - see detective.py's
        # module docstring and check_csp_weakness's own docstring for why
        # this deliberately never becomes a findings-table row.
        csp_note = await detective.check_csp_weakness(host)
        if csp_note is not None:
            await _save_scan_note(conn, project_id, target_id, "csp_weakness", csp_note)

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

        # Batch 13: unauthenticated GraphQL mutation execution.
        # Grouped with the other GraphQL checks above.
        logger.info("detective: running unauthenticated GraphQL mutation check for %s", host)
        graphql_mutation_result = await detective.check_unauthenticated_graphql_mutation(
            host.rstrip("/") + "/graphql"
        )
        if graphql_mutation_result is not None:
            await _save_detective_finding(conn, project_id, target_id, graphql_mutation_result)

        # Batch 15: GraphQL query via GET. Recon-only - grouped with
        # the other GraphQL checks above.
        logger.info("detective: running GraphQL GET query check for %s", host)
        graphql_get_note = await detective.check_graphql_query_via_get(host.rstrip("/") + "/graphql")
        if graphql_get_note is not None:
            await _save_scan_note(conn, project_id, target_id, "graphql_query_via_get", graphql_get_note)

        container_api_result = await detective.check_exposed_container_api(host)
        if container_api_result is not None:
            await _save_detective_finding(conn, project_id, target_id, container_api_result)

        git_result = await detective.check_git_exposure(host)
        if git_result is not None:
            await _save_detective_finding(conn, project_id, target_id, git_result)

            # Confirmed-exposed .git directory - worth the extra time/
            # disk I/O to actually reconstruct the source, not just flag
            # that it's exposed. Gated behind a confirmed exposure so
            # this never runs speculatively on every host.
            logger.info("detective: .git exposure confirmed on %s, attempting full reconstruction", host)
            dump_result = await git_dumper.dump_git_repository(host, project_id, target_id)
            if dump_result.success:
                secret_note = (
                    f" {len(dump_result.secret_candidates)} recovered file(s) matched "
                    f"hardcoded-secret patterns: {'; '.join(dump_result.secret_candidates[:5])}"
                    if dump_result.secret_candidates else ""
                )
                await _save_detective_finding(conn, project_id, target_id, {
                    "vuln_type": "exposed_git_directory_reconstructed",
                    "severity": "critical",
                    "evidence": (
                        f"{host}: full source reconstruction from the exposed .git directory "
                        f"succeeded via {dump_result.method} - {dump_result.file_count} file(s) "
                        f"recovered to {dump_result.dump_path}. {dump_result.note}{secret_note}"
                    ),
                })
            else:
                await _save_scan_note(conn, project_id, target_id, "git_exposure", f"{host}: {dump_result.note}")

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
            await _save_scan_note(conn, project_id, target_id, "waf_fingerprint", waf_note)

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

        # Batch 14: JWT 'kid' header injection candidate. Recon-only -
        # grouped with the other JWT checks above.
        logger.info("detective: running JWT kid injection check for %s", host)
        jwt_kid_note = await detective.check_jwt_kid_header_injection_candidate(host)
        if jwt_kid_note is not None:
            await _save_scan_note(conn, project_id, target_id, "jwt_kid_header_injection_candidate", jwt_kid_note)

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
            await _save_scan_note(conn, project_id, target_id, "exposed_admin_panel", admin_panel_note)

        # Batches 15/17: infra-level checks grouped together.
        logger.info("detective: running SPF/DMARC check for %s", host)
        spf_dmarc_note = await detective.check_missing_spf_dmarc(host)
        if spf_dmarc_note is not None:
            await _save_scan_note(conn, project_id, target_id, "missing_spf_dmarc", spf_dmarc_note)

        logger.info("detective: running origin IP WAF bypass check for %s", host)
        origin_ip_result = await detective.check_origin_ip_waf_bypass(host)
        if origin_ip_result is not None:
            await _save_detective_finding(conn, project_id, target_id, origin_ip_result)

        logger.info("detective: running Prometheus metrics exposure check for %s", host)
        prometheus_result = await detective.check_exposed_prometheus_metrics(host)
        if prometheus_result is not None:
            await _save_detective_finding(conn, project_id, target_id, prometheus_result)

        # ---- Batches 18-22 host-level checks (14 total) ----

        logger.info("detective: running dependency manifest exposure check for %s", host)
        dep_manifest_result = await detective.check_dependency_manifest_exposure(host)
        if dep_manifest_result is not None:
            await _save_detective_finding(conn, project_id, target_id, dep_manifest_result)

        logger.info("detective: running Swagger path enumeration check for %s", host)
        swagger_enum_note = await detective.check_swagger_path_enumeration_unauth(host)
        if swagger_enum_note is not None:
            await _save_scan_note(conn, project_id, target_id, "swagger_exposure_enum", swagger_enum_note)

        logger.info("detective: running TRACE method check for %s", host)
        trace_method_note = await detective.check_http_trace_method_enabled(host)
        if trace_method_note is not None:
            await _save_scan_note(conn, project_id, target_id, "http_trace_method_enabled", trace_method_note)

        logger.info("detective: running docker-compose exposure check for %s", host)
        docker_compose_result = await detective.check_exposed_docker_compose_file(host)
        if docker_compose_result is not None:
            await _save_detective_finding(conn, project_id, target_id, docker_compose_result)

        logger.info("detective: running WordPress config backup check for %s", host)
        wp_config_result = await detective.check_wordpress_config_backup_exposure(host)
        if wp_config_result is not None:
            await _save_detective_finding(conn, project_id, target_id, wp_config_result)

        logger.info("detective: running GraphQL error stack trace check for %s", host)
        graphql_stack_trace_result = await detective.check_graphql_error_stack_trace_leak(
            host.rstrip("/") + "/graphql"
        )
        if graphql_stack_trace_result is not None:
            await _save_detective_finding(conn, project_id, target_id, graphql_stack_trace_result)

        logger.info("detective: running DevOps tool panel check for %s", host)
        devops_panel_result = await detective.check_exposed_devops_tool_panel(host)
        if devops_panel_result is not None:
            await _save_detective_finding(conn, project_id, target_id, devops_panel_result)

        logger.info("detective: running phpMyAdmin exposure check for %s", host)
        phpmyadmin_result = await detective.check_exposed_phpmyadmin(host)
        if phpmyadmin_result is not None:
            await _save_detective_finding(conn, project_id, target_id, phpmyadmin_result)

        logger.info("detective: running ELMAH exposure check for %s", host)
        elmah_result = await detective.check_exposed_elmah_axd(host)
        if elmah_result is not None:
            await _save_detective_finding(conn, project_id, target_id, elmah_result)

        logger.info("detective: running Trace.axd exposure check for %s", host)
        trace_axd_result = await detective.check_exposed_trace_axd(host)
        if trace_axd_result is not None:
            await _save_detective_finding(conn, project_id, target_id, trace_axd_result)

        logger.info("detective: running Laravel debug mode check for %s", host)
        laravel_debug_result = await detective.check_laravel_debug_mode_exposure(host)
        if laravel_debug_result is not None:
            await _save_detective_finding(conn, project_id, target_id, laravel_debug_result)

        logger.info("detective: running .git/config credentials check for %s", host)
        git_config_creds_result = await detective.check_git_config_credentials_leak(host)
        if git_config_creds_result is not None:
            await _save_detective_finding(conn, project_id, target_id, git_config_creds_result)

        logger.info("detective: running AWS credentials file check for %s", host)
        aws_creds_result = await detective.check_aws_credentials_file_exposure(host)
        if aws_creds_result is not None:
            await _save_detective_finding(conn, project_id, target_id, aws_creds_result)

        logger.info("detective: running kubeconfig exposure check for %s", host)
        kubeconfig_result = await detective.check_kubeconfig_exposure(host)
        if kubeconfig_result is not None:
            await _save_detective_finding(conn, project_id, target_id, kubeconfig_result)

        # ---- Batches 23-28 host-level checks (24 total) ----

        logger.info("detective: running Nexus/Artifactory exposure check for %s", host)
        nexus_result = await detective.check_exposed_nexus_artifactory(host)
        if nexus_result is not None:
            await _save_detective_finding(conn, project_id, target_id, nexus_result)

        logger.info("detective: running RabbitMQ management exposure check for %s", host)
        rabbitmq_result = await detective.check_exposed_rabbitmq_management(host)
        if rabbitmq_result is not None:
            await _save_detective_finding(conn, project_id, target_id, rabbitmq_result)

        logger.info("detective: running Grafana exposure check for %s", host)
        grafana_result = await detective.check_exposed_grafana(host)
        if grafana_result is not None:
            await _save_detective_finding(conn, project_id, target_id, grafana_result)

        logger.info("detective: running MinIO console exposure check for %s", host)
        minio_result = await detective.check_exposed_minio_console(host)
        if minio_result is not None:
            await _save_detective_finding(conn, project_id, target_id, minio_result)

        logger.info("detective: running Redis no-auth exposure check for %s", host)
        redis_result = await detective.check_exposed_redis_no_auth(host)
        if redis_result is not None:
            await _save_detective_finding(conn, project_id, target_id, redis_result)

        logger.info("detective: running Memcached no-auth exposure check for %s", host)
        memcached_result = await detective.check_exposed_memcached_no_auth(host)
        if memcached_result is not None:
            await _save_detective_finding(conn, project_id, target_id, memcached_result)

        logger.info("detective: running FTP anonymous login check for %s", host)
        ftp_anon_result = await detective.check_exposed_ftp_anonymous_login(host)
        if ftp_anon_result is not None:
            await _save_detective_finding(conn, project_id, target_id, ftp_anon_result)

        logger.info("detective: running CouchDB Fauxton exposure check for %s", host)
        couchdb_fauxton_result = await detective.check_exposed_couchdb_fauxton(host)
        if couchdb_fauxton_result is not None:
            await _save_detective_finding(conn, project_id, target_id, couchdb_fauxton_result)

        logger.info("detective: running Zookeeper exposure check for %s", host)
        zookeeper_result = await detective.check_exposed_zookeeper(host)
        if zookeeper_result is not None:
            await _save_detective_finding(conn, project_id, target_id, zookeeper_result)

        logger.info("detective: running Solr admin exposure check for %s", host)
        solr_result = await detective.check_exposed_solr_admin(host)
        if solr_result is not None:
            await _save_detective_finding(conn, project_id, target_id, solr_result)

        logger.info("detective: running Jenkins script console check for %s", host)
        jenkins_script_result = await detective.check_jenkins_script_console_unauth(host)
        if jenkins_script_result is not None:
            await _save_detective_finding(conn, project_id, target_id, jenkins_script_result)

        logger.info("detective: running CouchDB _all_dbs listing check for %s", host)
        couchdb_alldbs_result = await detective.check_couchdb_all_dbs_unauth(host)
        if couchdb_alldbs_result is not None:
            await _save_detective_finding(conn, project_id, target_id, couchdb_alldbs_result)

        logger.info("detective: running Spring Boot env exposure check for %s", host)
        spring_env_result = await detective.check_spring_boot_env_exposure(host)
        if spring_env_result is not None:
            await _save_detective_finding(conn, project_id, target_id, spring_env_result)

        logger.info("detective: running Django debug mode check for %s", host)
        django_debug_result = await detective.check_django_debug_mode_exposure(host)
        if django_debug_result is not None:
            await _save_detective_finding(conn, project_id, target_id, django_debug_result)

        logger.info("detective: running ASP.NET debug mode check for %s", host)
        aspnet_debug_result = await detective.check_aspnet_debug_mode_exposure(host)
        if aspnet_debug_result is not None:
            await _save_detective_finding(conn, project_id, target_id, aspnet_debug_result)

        logger.info("detective: running Express stack trace leak check for %s", host)
        express_stack_result = await detective.check_express_stack_trace_leak(host)
        if express_stack_result is not None:
            await _save_detective_finding(conn, project_id, target_id, express_stack_result)

        logger.info("detective: running npm-debug.log exposure check for %s", host)
        npm_debug_result = await detective.check_npm_debug_log_exposure(host)
        if npm_debug_result is not None:
            await _save_detective_finding(conn, project_id, target_id, npm_debug_result)

        logger.info("detective: running .travis.yml exposure check for %s", host)
        travis_yml_result = await detective.check_travis_yml_exposure(host)
        if travis_yml_result is not None:
            await _save_detective_finding(conn, project_id, target_id, travis_yml_result)

        logger.info("detective: running CircleCI config exposure check for %s", host)
        circleci_result = await detective.check_circleci_config_exposure(host)
        if circleci_result is not None:
            await _save_detective_finding(conn, project_id, target_id, circleci_result)

        logger.info("detective: running GitHub workflow exposure check for %s", host)
        github_workflow_result = await detective.check_github_workflow_exposure(host)
        if github_workflow_result is not None:
            await _save_detective_finding(conn, project_id, target_id, github_workflow_result)

        logger.info("detective: running Terraform state exposure check for %s", host)
        terraform_state_result = await detective.check_terraform_state_exposure(host)
        if terraform_state_result is not None:
            await _save_detective_finding(conn, project_id, target_id, terraform_state_result)

        logger.info("detective: running Ansible Vault exposure check for %s", host)
        ansible_vault_result = await detective.check_ansible_vault_exposure(host)
        if ansible_vault_result is not None:
            await _save_detective_finding(conn, project_id, target_id, ansible_vault_result)

        logger.info("detective: running Helm values.yaml exposure check for %s", host)
        helm_values_result = await detective.check_helm_values_exposure(host)
        if helm_values_result is not None:
            await _save_detective_finding(conn, project_id, target_id, helm_values_result)

        logger.info("detective: running serverless.yml exposure check for %s", host)
        serverless_yml_result = await detective.check_serverless_yml_exposure(host)
        if serverless_yml_result is not None:
            await _save_detective_finding(conn, project_id, target_id, serverless_yml_result)

        # ---- Batches 29-33 host-level checks (9 total) ----

        logger.info("detective: running Docker daemon API exposure check for %s", host)
        docker_daemon_result = await detective.check_exposed_docker_daemon_api(host)
        if docker_daemon_result is not None:
            await _save_detective_finding(conn, project_id, target_id, docker_daemon_result)

        logger.info("detective: running Postgres trust-auth exposure check for %s", host)
        postgres_trust_result = await detective.check_exposed_postgres_trust_auth(host)
        if postgres_trust_result is not None:
            await _save_detective_finding(conn, project_id, target_id, postgres_trust_result)

        logger.info("detective: running InfluxDB no-auth exposure check for %s", host)
        influxdb_result = await detective.check_exposed_influxdb_no_auth(host)
        if influxdb_result is not None:
            await _save_detective_finding(conn, project_id, target_id, influxdb_result)

        logger.info("detective: running Kibana no-auth exposure check for %s", host)
        kibana_result = await detective.check_exposed_kibana_no_auth(host)
        if kibana_result is not None:
            await _save_detective_finding(conn, project_id, target_id, kibana_result)

        logger.info("detective: running backup archive exposure check for %s", host)
        backup_archive_result = await detective.check_backup_archive_exposure(host)
        if backup_archive_result is not None:
            await _save_detective_finding(conn, project_id, target_id, backup_archive_result)

        logger.info("detective: running SQL dump file exposure check for %s", host)
        sql_dump_result = await detective.check_sql_dump_file_exposure(host)
        if sql_dump_result is not None:
            await _save_detective_finding(conn, project_id, target_id, sql_dump_result)

        logger.info("detective: running log file exposure check for %s", host)
        log_file_result = await detective.check_log_file_exposure(host)
        if log_file_result is not None:
            await _save_detective_finding(conn, project_id, target_id, log_file_result)

        logger.info("detective: running .htpasswd exposure check for %s", host)
        htpasswd_result = await detective.check_htpasswd_exposure(host)
        if htpasswd_result is not None:
            await _save_detective_finding(conn, project_id, target_id, htpasswd_result)

        logger.info("detective: running weak TLS protocol check for %s", host)
        weak_tls_result = await detective.check_insecure_tls_weak_protocol(host)
        if weak_tls_result is not None:
            await _save_detective_finding(conn, project_id, target_id, weak_tls_result)

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
            await _save_scan_note(conn, project_id, target_id, "http_param_pollution", res)

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
            await _save_scan_note(conn, project_id, target_id, "idor_candidate", res)

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
            await _save_scan_note(conn, project_id, target_id, "insecure_deserialization_signature", res)

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
            await _save_scan_note(conn, project_id, target_id, "dom_xss_sink_flagging", res)

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
            await _save_scan_note(conn, project_id, target_id, "missing_sri", res)

    # ---- Batch 13 (larger batch, 8 checks) ----

    # Detective check: SSRF-driven internal port/service fingerprinting.
    ssrf_port_scan_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSRF_PORT_SCAN_CHECK_CAP]
    logger.info(
        "detective: running SSRF internal port scan against %d candidate URL(s)",
        len(ssrf_port_scan_candidates),
    )
    ssrf_port_scan_results = await asyncio.gather(
        *(detective.check_ssrf_internal_port_scan(url) for url in ssrf_port_scan_candidates),
        return_exceptions=True,
    )
    for res in ssrf_port_scan_results:
        if isinstance(res, Exception):
            logger.debug("SSRF internal port scan raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: mass assignment / privilege escalation.
    mass_assignment_candidates = sane_discovered_urls[:_MASS_ASSIGNMENT_CHECK_CAP]
    logger.info(
        "detective: running mass assignment check against %d URL(s)", len(mass_assignment_candidates)
    )
    mass_assignment_results = await asyncio.gather(
        *(detective.check_mass_assignment_privilege_escalation(url) for url in mass_assignment_candidates),
        return_exceptions=True,
    )
    for res in mass_assignment_results:
        if isinstance(res, Exception):
            logger.debug("mass assignment check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: auth bypass via HTTP verb tampering.
    verb_tampering_candidates = sane_discovered_urls[:_VERB_TAMPERING_CHECK_CAP]
    logger.info(
        "detective: running verb tampering auth bypass check against %d URL(s)",
        len(verb_tampering_candidates),
    )
    verb_tampering_results = await asyncio.gather(
        *(detective.check_auth_bypass_via_verb_tampering(url) for url in verb_tampering_candidates),
        return_exceptions=True,
    )
    for res in verb_tampering_results:
        if isinstance(res, Exception):
            logger.debug("verb tampering auth bypass check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: negative-number business logic candidate.
    # Recon-only - see the check's own docstring.
    negative_number_candidates = [url for url in sane_discovered_urls if "=" in url][:_NEGATIVE_NUMBER_CHECK_CAP]
    logger.info(
        "detective: running negative number business logic check against %d candidate URL(s)",
        len(negative_number_candidates),
    )
    negative_number_notes = await asyncio.gather(
        *(detective.check_negative_number_business_logic_candidate(url) for url in negative_number_candidates),
        return_exceptions=True,
    )
    for res in negative_number_notes:
        if isinstance(res, Exception):
            logger.debug("negative number business logic check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "negative_number_business_logic_candidate", res)

    # Detective check: predictable/weak token pattern. Recon-only,
    # pure pattern match on URLs already fetched elsewhere - no extra
    # requests, so capped higher.
    predictable_token_candidates = sane_discovered_urls[:_PREDICTABLE_TOKEN_CHECK_CAP]
    logger.info(
        "detective: running predictable token pattern check against %d URL(s)",
        len(predictable_token_candidates),
    )
    predictable_token_notes = await asyncio.gather(
        *(detective.check_predictable_token_pattern(url) for url in predictable_token_candidates),
        return_exceptions=True,
    )
    for res in predictable_token_notes:
        if isinstance(res, Exception):
            logger.debug("predictable token pattern check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "predictable_token_pattern", res)

    # Detective check: missing clickjacking protection. Recon-only -
    # almost always Informative alone, see the check's own docstring.
    clickjacking_candidates = sane_discovered_urls[:_CLICKJACKING_CHECK_CAP]
    logger.info(
        "detective: running clickjacking protection check against %d URL(s)",
        len(clickjacking_candidates),
    )
    clickjacking_notes = await asyncio.gather(
        *(detective.check_clickjacking_missing_protection(url) for url in clickjacking_candidates),
        return_exceptions=True,
    )
    for res in clickjacking_notes:
        if isinstance(res, Exception):
            logger.debug("clickjacking protection check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "clickjacking_missing_protection", res)

    # Detective check: hardcoded secrets / internal infra disclosure.
    # Recon-only - broader/less format-specific than
    # check_api_key_leak_signature.
    hardcoded_secrets_candidates = sane_discovered_urls[:_HARDCODED_SECRETS_CHECK_CAP]
    logger.info(
        "detective: running hardcoded secrets check against %d URL(s)",
        len(hardcoded_secrets_candidates),
    )
    hardcoded_secrets_notes = await asyncio.gather(
        *(detective.check_hardcoded_secrets_and_internal_disclosure(url) for url in hardcoded_secrets_candidates),
        return_exceptions=True,
    )
    for res in hardcoded_secrets_notes:
        if isinstance(res, Exception):
            logger.debug("hardcoded secrets check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "hardcoded_secrets_and_internal_disclosure", res)

    # ---- Batch 14 (bulkier still, 10 checks) ----

    # Detective check: LFI via PHP wrapper (source disclosure).
    lfi_wrapper_candidates = [url for url in sane_discovered_urls if "=" in url][:_LFI_PHP_WRAPPER_CHECK_CAP]
    logger.info(
        "detective: running PHP wrapper LFI check against %d candidate URL(s)",
        len(lfi_wrapper_candidates),
    )
    lfi_wrapper_results = await asyncio.gather(
        *(detective.check_lfi_via_php_wrapper(url) for url in lfi_wrapper_candidates),
        return_exceptions=True,
    )
    for res in lfi_wrapper_results:
        if isinstance(res, Exception):
            logger.debug("PHP wrapper LFI check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: LDAP injection, error-based.
    ldap_injection_candidates = [url for url in sane_discovered_urls if "=" in url][:_LDAP_INJECTION_CHECK_CAP]
    logger.info(
        "detective: running LDAP injection check against %d candidate URL(s)",
        len(ldap_injection_candidates),
    )
    ldap_injection_results = await asyncio.gather(
        *(detective.check_ldap_injection_error_based(url) for url in ldap_injection_candidates),
        return_exceptions=True,
    )
    for res in ldap_injection_results:
        if isinstance(res, Exception):
            logger.debug("LDAP injection check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: XPath injection, error-based.
    xpath_injection_candidates = [url for url in sane_discovered_urls if "=" in url][:_XPATH_INJECTION_CHECK_CAP]
    logger.info(
        "detective: running XPath injection check against %d candidate URL(s)",
        len(xpath_injection_candidates),
    )
    xpath_injection_results = await asyncio.gather(
        *(detective.check_xpath_injection_error_based(url) for url in xpath_injection_candidates),
        return_exceptions=True,
    )
    for res in xpath_injection_results:
        if isinstance(res, Exception):
            logger.debug("XPath injection check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: web cache poisoning via unkeyed header.
    cache_poisoning_candidates = sane_discovered_urls[:_CACHE_POISONING_CHECK_CAP]
    logger.info(
        "detective: running cache poisoning check against %d URL(s)", len(cache_poisoning_candidates)
    )
    cache_poisoning_results = await asyncio.gather(
        *(detective.check_web_cache_poisoning_unkeyed_header(url) for url in cache_poisoning_candidates),
        return_exceptions=True,
    )
    for res in cache_poisoning_results:
        if isinstance(res, Exception):
            logger.debug("cache poisoning check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: missing CSRF token on POST forms. Recon-only -
    # see the check's own docstring.
    csrf_token_candidates = sane_discovered_urls[:_CSRF_TOKEN_CHECK_CAP]
    logger.info(
        "detective: running CSRF token check against %d URL(s)", len(csrf_token_candidates)
    )
    csrf_token_notes = await asyncio.gather(
        *(detective.check_csrf_token_missing(url) for url in csrf_token_candidates),
        return_exceptions=True,
    )
    for res in csrf_token_notes:
        if isinstance(res, Exception):
            logger.debug("CSRF token check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "csrf_token_missing", res)

    # Detective check: file upload form candidate. Recon-only, never
    # attempts an actual upload - see the check's own docstring.
    file_upload_candidates = sane_discovered_urls[:_FILE_UPLOAD_CANDIDATE_CHECK_CAP]
    logger.info(
        "detective: running file upload form check against %d URL(s)", len(file_upload_candidates)
    )
    file_upload_notes = await asyncio.gather(
        *(detective.check_file_upload_form_candidate(url) for url in file_upload_candidates),
        return_exceptions=True,
    )
    for res in file_upload_notes:
        if isinstance(res, Exception):
            logger.debug("file upload form check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "file_upload_form_candidate", res)

    # Detective check: WebSocket loaded over unencrypted ws:// from
    # an HTTPS page.
    websocket_downgrade_candidates = sane_discovered_urls[:_WEBSOCKET_DOWNGRADE_CHECK_CAP]
    logger.info(
        "detective: running WebSocket downgrade check against %d URL(s)",
        len(websocket_downgrade_candidates),
    )
    websocket_downgrade_results = await asyncio.gather(
        *(detective.check_websocket_downgrade(url) for url in websocket_downgrade_candidates),
        return_exceptions=True,
    )
    for res in websocket_downgrade_results:
        if isinstance(res, Exception):
            logger.debug("WebSocket downgrade check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # ---- Batches 15-17 (built together, 4 checks each) ----

    # Detective check: excessive data exposure in API JSON. Recon-only.
    excessive_exposure_candidates = sane_discovered_urls[:_EXCESSIVE_EXPOSURE_CHECK_CAP]
    logger.info(
        "detective: running excessive data exposure check against %d URL(s)",
        len(excessive_exposure_candidates),
    )
    excessive_exposure_notes = await asyncio.gather(
        *(detective.check_excessive_data_exposure_api(url) for url in excessive_exposure_candidates),
        return_exceptions=True,
    )
    for res in excessive_exposure_notes:
        if isinstance(res, Exception):
            logger.debug("excessive data exposure check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "excessive_data_exposure_api", res)

    # Detective check: API version downgrade bypass.
    api_version_candidates = sane_discovered_urls[:_API_VERSION_DOWNGRADE_CHECK_CAP]
    logger.info(
        "detective: running API version downgrade check against %d URL(s)",
        len(api_version_candidates),
    )
    api_version_results = await asyncio.gather(
        *(detective.check_api_version_downgrade_bypass(url) for url in api_version_candidates),
        return_exceptions=True,
    )
    for res in api_version_results:
        if isinstance(res, Exception):
            logger.debug("API version downgrade check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: boolean-based blind SQL injection.
    sqli_boolean_candidates = [url for url in sane_discovered_urls if "=" in url][:_SQLI_BOOLEAN_CHECK_CAP]
    logger.info(
        "detective: running boolean-based SQLi check against %d candidate URL(s)",
        len(sqli_boolean_candidates),
    )
    sqli_boolean_results = await asyncio.gather(
        *(detective.check_sql_injection_boolean_based(url) for url in sqli_boolean_candidates),
        return_exceptions=True,
    )
    for res in sqli_boolean_results:
        if isinstance(res, Exception):
            logger.debug("boolean-based SQLi check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: SVG upload flagging. Recon-only.
    svg_upload_candidates = sane_discovered_urls[:_SVG_UPLOAD_CHECK_CAP]
    logger.info(
        "detective: running SVG upload flagging check against %d URL(s)", len(svg_upload_candidates)
    )
    svg_upload_notes = await asyncio.gather(
        *(detective.check_insecure_svg_upload_flagging(url) for url in svg_upload_candidates),
        return_exceptions=True,
    )
    for res in svg_upload_notes:
        if isinstance(res, Exception):
            logger.debug("SVG upload flagging check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "insecure_svg_upload_flagging", res)

    # Detective check: JSONP callback XSS.
    jsonp_xss_candidates = sane_discovered_urls[:_JSONP_XSS_CHECK_CAP]
    logger.info(
        "detective: running JSONP callback XSS check against %d URL(s)", len(jsonp_xss_candidates)
    )
    jsonp_xss_results = await asyncio.gather(
        *(detective.check_jsonp_callback_xss(url) for url in jsonp_xss_candidates),
        return_exceptions=True,
    )
    for res in jsonp_xss_results:
        if isinstance(res, Exception):
            logger.debug("JSONP callback XSS check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: backup/temp file disclosure.
    backup_file_candidates = sane_discovered_urls[:_BACKUP_FILE_CHECK_CAP]
    logger.info(
        "detective: running backup/temp file check against %d URL(s)", len(backup_file_candidates)
    )
    backup_file_results = await asyncio.gather(
        *(detective.check_backup_temp_file_disclosure(url) for url in backup_file_candidates),
        return_exceptions=True,
    )
    for res in backup_file_results:
        if isinstance(res, Exception):
            logger.debug("backup/temp file check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: publicly-listable Azure Blob container.
    azure_blob_candidates = sane_discovered_urls[:_AZURE_BLOB_CHECK_CAP]
    logger.info(
        "detective: running Azure blob exposure check against %d URL(s)", len(azure_blob_candidates)
    )
    azure_blob_results = await asyncio.gather(
        *(detective.check_azure_blob_public_exposure(url) for url in azure_blob_candidates),
        return_exceptions=True,
    )
    for res in azure_blob_results:
        if isinstance(res, Exception):
            logger.debug("Azure blob exposure check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: CORS subdomain-suffix bypass.
    cors_subdomain_candidates = sane_discovered_urls[:_CORS_SUBDOMAIN_BYPASS_CHECK_CAP]
    logger.info(
        "detective: running CORS subdomain suffix bypass check against %d URL(s)",
        len(cors_subdomain_candidates),
    )
    cors_subdomain_results = await asyncio.gather(
        *(detective.check_cors_subdomain_suffix_bypass(url) for url in cors_subdomain_candidates),
        return_exceptions=True,
    )
    for res in cors_subdomain_results:
        if isinstance(res, Exception):
            logger.debug("CORS subdomain suffix bypass check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # ---- Batches 18-22 URL-level checks (6 total) ----

    # Detective check: missing HSTS. Recon-only.
    hsts_candidates = sane_discovered_urls[:_HSTS_CHECK_CAP]
    logger.info("detective: running HSTS check against %d URL(s)", len(hsts_candidates))
    hsts_notes = await asyncio.gather(
        *(detective.check_hsts_missing(url) for url in hsts_candidates),
        return_exceptions=True,
    )
    for res in hsts_notes:
        if isinstance(res, Exception):
            logger.debug("HSTS check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "hsts", res)

    # Detective check: session cookie missing SameSite. Recon-only.
    cookie_samesite_candidates = sane_discovered_urls[:_COOKIE_SAMESITE_CHECK_CAP]
    logger.info(
        "detective: running cookie SameSite check against %d URL(s)", len(cookie_samesite_candidates)
    )
    cookie_samesite_notes = await asyncio.gather(
        *(detective.check_insecure_cookie_without_samesite(url) for url in cookie_samesite_candidates),
        return_exceptions=True,
    )
    for res in cookie_samesite_notes:
        if isinstance(res, Exception):
            logger.debug("cookie SameSite check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "cookie_samesite", res)

    # Detective check: session identifier in URL. Recon-only, pure
    # pattern match - no extra requests, capped higher.
    session_id_url_candidates = sane_discovered_urls[:_SESSION_ID_URL_CHECK_CAP]
    logger.info(
        "detective: running session-ID-in-URL check against %d URL(s)", len(session_id_url_candidates)
    )
    session_id_url_notes = await asyncio.gather(
        *(detective.check_session_id_in_url(url) for url in session_id_url_candidates),
        return_exceptions=True,
    )
    for res in session_id_url_notes:
        if isinstance(res, Exception):
            logger.debug("session ID in URL check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "session_id_in_url", res)

    # Detective check: open redirect via meta-refresh.
    meta_refresh_candidates = [url for url in sane_discovered_urls if "=" in url][:_META_REFRESH_CHECK_CAP]
    logger.info(
        "detective: running meta-refresh open redirect check against %d candidate URL(s)",
        len(meta_refresh_candidates),
    )
    meta_refresh_results = await asyncio.gather(
        *(detective.check_open_redirect_via_meta_refresh(url) for url in meta_refresh_candidates),
        return_exceptions=True,
    )
    for res in meta_refresh_results:
        if isinstance(res, Exception):
            logger.debug("meta-refresh open redirect check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: exposed WSDL/SOAP service.
    wsdl_candidates = sane_discovered_urls[:_WSDL_CHECK_CAP]
    logger.info("detective: running WSDL exposure check against %d URL(s)", len(wsdl_candidates))
    wsdl_results = await asyncio.gather(
        *(detective.check_exposed_wsdl_soap_service(url) for url in wsdl_candidates),
        return_exceptions=True,
    )
    for res in wsdl_results:
        if isinstance(res, Exception):
            logger.debug("WSDL exposure check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: predictable UUIDv1 resource identifier.
    # Recon-only, pure pattern match - no extra requests, capped higher.
    uuid_version_candidates = sane_discovered_urls[:_UUID_VERSION_CHECK_CAP]
    logger.info(
        "detective: running predictable UUID version check against %d URL(s)",
        len(uuid_version_candidates),
    )
    uuid_version_notes = await asyncio.gather(
        *(detective.check_predictable_uuid_version(url) for url in uuid_version_candidates),
        return_exceptions=True,
    )
    for res in uuid_version_notes:
        if isinstance(res, Exception):
            logger.debug("predictable UUID version check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "predictable_uuid_version", res)

    # ---- Batches 29-33 URL-level checks (11 total) ----

    # Detective check: OAuth missing state parameter. Recon-only.
    oauth_state_candidates = sane_discovered_urls[:_OAUTH_STATE_CHECK_CAP]
    logger.info("detective: running OAuth state param check against %d URL(s)", len(oauth_state_candidates))
    oauth_state_notes = await asyncio.gather(
        *(detective.check_oauth_missing_state_parameter(url) for url in oauth_state_candidates),
        return_exceptions=True,
    )
    for res in oauth_state_notes:
        if isinstance(res, Exception):
            logger.debug("OAuth state param check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "oauth_missing_state_parameter", res)

    # Detective check: Basic Auth over plaintext HTTP.
    basic_auth_http_candidates = sane_discovered_urls[:_BASIC_AUTH_HTTP_CHECK_CAP]
    logger.info("detective: running Basic Auth over HTTP check against %d URL(s)", len(basic_auth_http_candidates))
    basic_auth_http_results = await asyncio.gather(
        *(detective.check_basic_auth_over_http(url) for url in basic_auth_http_candidates),
        return_exceptions=True,
    )
    for res in basic_auth_http_results:
        if isinstance(res, Exception):
            logger.debug("Basic Auth over HTTP check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: cookie missing Secure flag over HTTPS. Recon-only.
    cookie_secure_candidates = sane_discovered_urls[:_COOKIE_SECURE_CHECK_CAP]
    logger.info("detective: running cookie Secure flag check against %d URL(s)", len(cookie_secure_candidates))
    cookie_secure_notes = await asyncio.gather(
        *(detective.check_cookie_missing_secure_flag(url) for url in cookie_secure_candidates),
        return_exceptions=True,
    )
    for res in cookie_secure_notes:
        if isinstance(res, Exception):
            logger.debug("cookie Secure flag check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "cookie_missing_secure_flag", res)

    # Detective check: Firebase Realtime DB open read rules.
    firebase_rtdb_candidates = sane_discovered_urls[:_FIREBASE_RTDB_CHECK_CAP]
    logger.info("detective: running Firebase RTDB open rules check against %d URL(s)", len(firebase_rtdb_candidates))
    firebase_rtdb_results = await asyncio.gather(
        *(detective.check_firebase_realtime_db_open_rules(url) for url in firebase_rtdb_candidates),
        return_exceptions=True,
    )
    for res in firebase_rtdb_results:
        if isinstance(res, Exception):
            logger.debug("Firebase RTDB check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: SSRF targeting GCP metadata (header-gated).
    ssrf_gcp_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSRF_GCP_CHECK_CAP]
    logger.info("detective: running GCP metadata SSRF check against %d candidate URL(s)", len(ssrf_gcp_candidates))
    ssrf_gcp_results = await asyncio.gather(
        *(detective.check_ssrf_gcp_metadata(url) for url in ssrf_gcp_candidates),
        return_exceptions=True,
    )
    for res in ssrf_gcp_results:
        if isinstance(res, Exception):
            logger.debug("GCP metadata SSRF check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: SSRF targeting Azure IMDS (header-gated).
    ssrf_azure_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSRF_AZURE_CHECK_CAP]
    logger.info("detective: running Azure metadata SSRF check against %d candidate URL(s)", len(ssrf_azure_candidates))
    ssrf_azure_results = await asyncio.gather(
        *(detective.check_ssrf_azure_metadata(url) for url in ssrf_azure_candidates),
        return_exceptions=True,
    )
    for res in ssrf_azure_results:
        if isinstance(res, Exception):
            logger.debug("Azure metadata SSRF check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: SSRF targeting DigitalOcean metadata.
    ssrf_do_candidates = [url for url in sane_discovered_urls if "=" in url][:_SSRF_DO_CHECK_CAP]
    logger.info("detective: running DigitalOcean metadata SSRF check against %d candidate URL(s)", len(ssrf_do_candidates))
    ssrf_do_results = await asyncio.gather(
        *(detective.check_ssrf_digitalocean_metadata(url) for url in ssrf_do_candidates),
        return_exceptions=True,
    )
    for res in ssrf_do_results:
        if isinstance(res, Exception):
            logger.debug("DigitalOcean metadata SSRF check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: IP restriction bypass via spoofed X-Forwarded-For.
    xff_bypass_candidates = sane_discovered_urls[:_XFF_BYPASS_CHECK_CAP]
    logger.info("detective: running XFF IP restriction bypass check against %d URL(s)", len(xff_bypass_candidates))
    xff_bypass_results = await asyncio.gather(
        *(detective.check_ip_restriction_bypass_via_xff(url) for url in xff_bypass_candidates),
        return_exceptions=True,
    )
    for res in xff_bypass_results:
        if isinstance(res, Exception):
            logger.debug("XFF IP restriction bypass check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: Referer-based access control bypass.
    referer_bypass_candidates = sane_discovered_urls[:_REFERER_BYPASS_CHECK_CAP]
    logger.info("detective: running Referer-based access control bypass check against %d URL(s)", len(referer_bypass_candidates))
    referer_bypass_results = await asyncio.gather(
        *(detective.check_referer_based_access_control_bypass(url) for url in referer_bypass_candidates),
        return_exceptions=True,
    )
    for res in referer_bypass_results:
        if isinstance(res, Exception):
            logger.debug("Referer-based access control bypass check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding(conn, project_id, target_id, res)

    # Detective check: API key/token in URL query param. Recon-only,
    # pure pattern match - no extra requests, capped higher.
    apikey_url_candidates = sane_discovered_urls[:_APIKEY_IN_URL_CHECK_CAP]
    logger.info("detective: running API key in URL check against %d URL(s)", len(apikey_url_candidates))
    apikey_url_notes = await asyncio.gather(
        *(detective.check_api_key_in_url_query_param(url) for url in apikey_url_candidates),
        return_exceptions=True,
    )
    for res in apikey_url_notes:
        if isinstance(res, Exception):
            logger.debug("API key in URL check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "api_key_in_url_query_param", res)

    # Detective check: password-reset user-enumeration candidate.
    # Recon-only.
    pw_reset_enum_candidates = sane_discovered_urls[:_PW_RESET_ENUM_CHECK_CAP]
    logger.info("detective: running password reset enumeration check against %d URL(s)", len(pw_reset_enum_candidates))
    pw_reset_enum_notes = await asyncio.gather(
        *(detective.check_password_reset_user_enumeration_candidate(url) for url in pw_reset_enum_candidates),
        return_exceptions=True,
    )
    for res in pw_reset_enum_notes:
        if isinstance(res, Exception):
            logger.debug("password reset enumeration check raised: %s", res)
            continue
        if res is not None:
            await _save_scan_note(conn, project_id, target_id, "password_reset_user_enumeration_candidate", res)


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

        finding_id = await conn.fetchval(
            """
            INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
            VALUES ($1, $2, 'nuclei', $3, $4, $5)
            RETURNING id
            """,
            project_id, target_id, vuln_type, severity, line[:1000],
        )
        await _upsert_finding_cluster(conn, target_id, finding_id, 'nuclei')
        saved_count += 1

    if unparsed_lines:
        # Anything that didn't match the expected format still gets
        # saved, just bundled and left as 'unknown' for triage to handle
        # - we never want a parsing miss to mean lost data.
        await _save_finding(conn, project_id, target_id, "nuclei", "\n".join(unparsed_lines))

    logger.info("nuclei: saved %d individual findings, %d unparsed line(s) bundled separately",
                saved_count, len(unparsed_lines))


async def _upsert_finding_cluster(
    conn: asyncpg.Connection, target_id: int, finding_id: int, source: str
) -> None:
    """
    Links a newly-saved finding into its target's cluster row, creating
    the cluster row on first insert for that target. This is what
    populates finding_clusters / finding_cluster_members so the
    correlation layer (high_potential_clusters view) actually has data
    instead of sitting empty.
    """
    cluster_id = await conn.fetchval(
        """
        INSERT INTO finding_clusters (target_id)
        VALUES ($1)
        ON CONFLICT (target_id) DO UPDATE SET updated_at = now()
        RETURNING id
        """,
        target_id,
    )
    await conn.execute(
        """
        INSERT INTO finding_cluster_members (cluster_id, finding_id, source)
        VALUES ($1, $2, $3)
        ON CONFLICT (cluster_id, finding_id) DO NOTHING
        """,
        cluster_id, finding_id, source,
    )


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

    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, $3, $4, 'unknown', $5)
        RETURNING id
        """,
        project_id,
        target_id,
        tool_name,
        tool_name,  # Phase 1: vuln_type defaults to the tool name until triage exists
        cleaned_output[:5000],  # cap stored evidence length
    )
    await _upsert_finding_cluster(conn, target_id, finding_id, tool_name)


async def _save_scan_note(
    conn: asyncpg.Connection, project_id: int, target_id: int, check_name: str, note: str
) -> None:
    """
    Persists a detective.py signal that was deliberately NOT auto-filed
    as a finding (see each check's own docstring, and add_scan_notes.sql
    for the full reasoning) - candidates for manual review, or confirmed
    gaps that are almost always Informative alone.

    This replaces what used to be a bare logger.info() call: computed,
    correctly classified as "worth a human look, not a formal finding,"
    then thrown away into a Docker log nobody reads. Same classification,
    same restraint about not treating it as a graded finding - just
    actually visible now (GET /api/projects/{id}/notes) instead of gone.
    """
    await conn.execute(
        """
        INSERT INTO scan_notes (project_id, target_id, check_name, note)
        VALUES ($1, $2, $3, $4)
        """,
        project_id, target_id, check_name, note[:2000],
    )


async def _save_detective_finding(
    conn: asyncpg.Connection, project_id: int, target_id: int, result: dict
) -> None:
    """
    Saves a finding produced by detective.py's checks (subdomain takeover,
    CORS misconfig, cache deception, entropy, and 100+ others).

    IMPORTANT - this used to trust each check's own self-declared
    severity as final and skip triage entirely ("each detective check
    already did its own confirmation logic ... nothing left to filter
    or triage"). That was the actual reason detective.py findings were
    noisy: a check's own confirmation logic can still be a single-signal
    heuristic, and a self-graded "critical" never got a second,
    independent look the way every other tool's findings do.

    Now these are stored the same way tool/nuclei findings are:
    severity='unknown', so the automatic post-scan "triage" phase (and
    the on-demand /triage-all endpoint) picks them up and runs them
    through triage.triage_finding() - independent AI review, VRT
    mapping, and the policy-exclusion guidance baked into triage.py's
    prompt. The check's own severity verdict isn't thrown away, just
    demoted from "final answer" to "input": it's embedded at the front
    of the evidence text and triage.py strips it back out to feed the
    model as context (see triage._extract_self_declared_severity).
    """
    self_declared_prefix = f"[self-declared-severity: {result['severity']}]\n"
    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, 'detective', $3, 'unknown', $4)
        RETURNING id
        """,
        project_id,
        target_id,
        result["vuln_type"],
        (self_declared_prefix + result["evidence"])[:5000],
    )
    await _upsert_finding_cluster(conn, target_id, finding_id, 'detective')
    logger.info(
        "detective: saved %s finding (self-declared severity=%s, pending triage) for target_id=%s",
        result["vuln_type"], result["severity"], target_id,
    )


async def _phase_gate(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs the cheap 7-Question Gate (see gate.py) on every 'unknown'-
    severity finding in this project, right after scan and before the
    more expensive logic_hunter/triage phases. Findings that fail the
    gate are never deleted - they stay in the table with
    gate_status='failed' for visibility - but triage.py skips them, so
    a scan full of scanner noise doesn't burn a full triage call per
    line. Checkpointed/retried like every other phase; a gate failure
    itself fails open per-finding (see gate.run_gate), so this can only
    ever cost extra triage calls, never silently drop a real finding.
    """
    gated = await gate.gate_project_findings(conn, project_id)
    logger.info("gate: reviewed %s finding(s) for project_id=%s", gated, project_id)


async def _phase_logic_hunter(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs logic_hunter.py's LLM business-logic/auth-bypass reasoning
    over this project's high-potential clusters (see
    high_potential_clusters) - the targets where correlation already
    found 2+ findings or 2+ distinct sources, which is where a chained
    logic bug is actually likely to be findable from existing evidence.
    Runs after gate (so it's reasoning over signal, not raw noise) and
    before triage (so any hypothesis it saves gets the same independent
    triage review every other finding gets). Idempotent to re-run: each
    cluster is only hunted once (finding_clusters.logic_hunter_status),
    so this never double-spends the expensive reasoning call.
    """
    hunted = await logic_hunter.hunt_project(conn, project_id)
    logger.info("logic_hunter: saved %s hypothesis/hypotheses for project_id=%s", hunted, project_id)


async def _phase_triage(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs AI triage on every 'unknown'-severity finding in this project -
    this now includes detective.py findings (see _save_detective_finding),
    which used to skip triage entirely. Kept as its own phase, after
    scan and before notify, so:

    - it's checkpointed/retried the same as every other phase (a triage
      failure doesn't silently lose findings, it retries once then
      marks needs_attention like anything else)
    - it runs automatically at the end of every scan, so findings get
      an independent AI look without you needing to remember to call
      /triage-all yourself
    - it's idempotent to re-run: it only ever processes rows still
      marked 'unknown', so if multiple targets in the same project
      finish around the same time this just triages whatever's new
      each time, nothing gets triaged twice

    Failures inside triage_finding() itself are already caught per-
    finding (falls back to severity='unknown' with a logged reason,
    see triage.py) so one bad finding can't take down the whole batch.

    After individual findings are scored, also runs cluster-aware
    triage (triage.triage_project_clusters) - this is the second pass
    that reasons about the COMBINATION of findings per target (e.g.
    info disclosure + weak auth = higher severity than either alone),
    reading from high_potential_clusters. It runs second on purpose:
    cluster reasoning is more meaningful once each member finding
    already has a real severity to reason on top of, rather than a
    placeholder 'unknown'.
    """
    triaged = await triage.triage_project_findings(conn, project_id)
    clustered = await triage.triage_project_clusters(conn, project_id)
    logger.info(
        "triage: reviewed %s finding(s), scored %s cluster(s) for project_id=%s",
        triaged, clustered, project_id,
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
