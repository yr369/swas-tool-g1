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

import logging
import os

import asyncpg

from . import checkpoint, fp_filter, tools

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

    for phase_name in PHASES:
        success = await _run_phase_with_retry(
            pool, project_id, target_id, phase_name, target,
            discovered_subdomains, live_hosts, discovered_urls, params_found,
        )
        if not success:
            logger.warning(
                "Stopping pipeline for target_id=%s after %s phase failed",
                target_id, phase_name,
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
                async with checkpoint.run_phase(conn, phase_run_id):
                    await _execute_phase(
                        conn, project_id, target_id, phase_name, target,
                        discovered_subdomains, live_hosts, discovered_urls, params_found,
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
) -> None:
    """
    The actual work for each phase. Raises an exception if something
    goes wrong - checkpoint.run_phase (the caller) handles catching,
    logging, and recording that.
    """
    if phase_name == "recon":
        await _phase_recon(target, discovered_subdomains)

    elif phase_name == "probe":
        await _phase_probe(target, discovered_subdomains, live_hosts, discovered_urls)

    elif phase_name == "fuzz":
        await _phase_fuzz(live_hosts, params_found)

    elif phase_name == "scan":
        await _phase_scan(conn, project_id, target_id, live_hosts, discovered_urls, params_found)

    elif phase_name == "notify":
        await _phase_notify(target)

    else:
        raise ValueError(f"Unknown phase: {phase_name}")


async def _phase_recon(target: str, discovered_subdomains: list[str]) -> None:
    """Subdomain enumeration, then check which ones are actually alive."""
    result = await tools.run_subfinder(target)
    if not result.success:
        raise RuntimeError(f"subfinder failed: {result.error}")

    found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    discovered_subdomains.extend(found or [target])  # fall back to the target itself
    logger.info("recon: found %d subdomains for %s", len(discovered_subdomains), target)


async def _phase_probe(
    target: str,
    discovered_subdomains: list[str],
    live_hosts: list[str],
    discovered_urls: list[str],
) -> None:
    """Check which discovered hosts are alive, and gather historical URLs."""
    hosts_to_check = discovered_subdomains or [target]

    httpx_result = await tools.run_httpx(hosts_to_check)
    if httpx_result.success:
        live_hosts.extend(
            line.strip() for line in httpx_result.stdout.splitlines() if line.strip()
        )
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
) -> None:
    """
    Run the actual vulnerability scanners. nuclei runs against all live
    hosts (it's broad and relatively cheap). dalfox and sqlmap ONLY run
    against hosts known to have parameters - this is the rule from the
    spec that avoids wasting time running injection tools against hosts
    with nothing to inject into.
    """
    for host in live_hosts[:10]:  # Phase 1: cap scope for the first working version
        nuclei_result = await tools.run_nuclei(host)
        if tools.looks_like_real_output(nuclei_result):
            await _save_finding(conn, project_id, target_id, "nuclei", nuclei_result.stdout)

        if params_found.get(host):
            dalfox_result = await tools.run_dalfox(host)
            if tools.looks_like_real_output(dalfox_result):
                await _save_finding(conn, project_id, target_id, "dalfox", dalfox_result.stdout)

            sqlmap_result = await tools.run_sqlmap(host)
            if tools.looks_like_real_output(sqlmap_result):
                await _save_finding(conn, project_id, target_id, "sqlmap", sqlmap_result.stdout)


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
    cleaned_output, removed = fp_filter.filter_noise(tool_name, raw_output)
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
