"""
pipeline/orchestrator.py - the top-level state machine: run_target_pipeline
(the public entry point main.py calls), _run_phase_with_retry, and
_execute_phase's dispatch table. Split out of the former monolithic
pipeline.py; this is the piece that used to be interleaved with all
six phases' full bodies in one file, which is exactly what made the
3,134-line file hard to navigate - now it's ~310 lines that just show
the control flow, with each phase's actual work one import away.
"""

import asyncio
import json
import logging
import os
import re

import asyncpg

from .. import auth_policy, auth_sessions, checkpoint, detective, evidence_lifecycle, finding_dedup, fp_filter, gate, git_dumper, logic_hunter, oob, screenshots, target_intelligence, tools, triage, verify

from .shared import logger, PHASES
from .persistence import _persist_pipeline_state
from .phase_fuzz import _phase_fuzz
from .phase_post import _phase_gate, _phase_logic_hunter, _phase_notify, _phase_triage, _phase_verify
from .phase_probe import _phase_probe
from .phase_recon import _phase_recon
from .phase_scan import _phase_scan


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

    # Batch 24: dead-target pre-flight check. Cheap - samples a few
    # PREVIOUSLY known hosts (if any cache exists) before spending a
    # full recon pass finding out the same thing the slow way. A
    # first-ever scan of this target always passes through (nothing
    # cached to sample against yet).
    async with pool.acquire() as conn:
        alive = await evidence_lifecycle.check_target_alive_before_scan(conn, target_id, target)
    if not alive:
        async with pool.acquire() as conn:
            await checkpoint.mark_remaining_phases_skipped(
                conn, project_id, target_id, after_phase=None,
                reason="target appears dead - all previously-known hosts unreachable (batch 24 pre-flight check)",
            )
        logger.info(
            "target_id=%s (%s): appears dead (all previously-known hosts unreachable) - "
            "skipping this scan run entirely",
            target_id, target,
        )
        return

    # Attack persona: a short AI-written plan for what to prioritize on
    # THIS target (see target_intelligence.py). Generated once per
    # target and reused on every later scan - failures here are
    # swallowed (returns None) since a missing persona just means
    # logic_hunter reasons without it, same fail-open pattern as gate.py.
    async with pool.acquire() as conn:
        target_row = await conn.fetchrow(
            "SELECT target_type, reward_range FROM scope_targets WHERE id = $1", target_id,
        )
        if target_row:
            await target_intelligence.get_or_generate_persona(
                conn, target_id, target,
                target_row["target_type"], reward_range=target_row["reward_range"],
            )

    discovered_subdomains: list[str] = []
    live_hosts: list[str] = []
    discovered_urls: list[str] = []
    params_found: dict[str, bool] = {}
    tech_stack: dict[str, list[str]] = {}  # host -> list of detected technologies

    # Batch 26 item 4: idempotent scan resume. Cheap to always check -
    # recently_completed_phases is empty for the overwhelmingly common
    # case (a fresh scan, nothing to resume), in which case every phase
    # just runs normally below, unchanged from before this feature.
    # When phases WERE recently completed (this run was interrupted by
    # a crash/redeploy and got re-triggered), rehydrate the state those
    # phases produced so later phases have what they need without
    # re-running the ones that already finished.
    async with pool.acquire() as conn:
        recently_completed_phases = await checkpoint.get_recently_completed_phases(conn, target_id)
        if "recon" in recently_completed_phases:
            # recon already has its own cache mechanism (_get_recon_cache_if_fresh) -
            # reuse it directly rather than re-deriving subdomains another way.
            cached_subdomains = await _get_recon_cache_if_fresh(pool, target_id)
            if cached_subdomains:
                discovered_subdomains.extend(cached_subdomains)
            else:
                # Cache expired/missing even though a 'completed' row exists
                # recently (edge case - cache TTL and resume window can
                # differ) - can't safely skip recon without its output, so
                # let it re-run rather than leave probe with nothing.
                recently_completed_phases.discard("recon")
        if recently_completed_phases & {"probe", "fuzz"}:
            state_row = await conn.fetchrow(
                "SELECT state_live_hosts, state_discovered_urls, state_params_found, state_tech_stack "
                "FROM scope_targets WHERE id = $1",
                target_id,
            )
            if state_row:
                if state_row["state_live_hosts"]:
                    live_hosts.extend(json.loads(state_row["state_live_hosts"]))
                if state_row["state_discovered_urls"]:
                    discovered_urls.extend(json.loads(state_row["state_discovered_urls"]))
                if state_row["state_params_found"]:
                    params_found.update(json.loads(state_row["state_params_found"]))
                if state_row["state_tech_stack"]:
                    tech_stack.update(json.loads(state_row["state_tech_stack"]))
    if recently_completed_phases:
        logger.info(
            "target_id=%s (%s): resuming - phase(s) %s already completed within the last "
            "%d minutes, skipping re-run",
            target_id, target, sorted(recently_completed_phases), checkpoint.RESUME_WINDOW_MINUTES,
        )

    for phase_name in PHASES:
        if phase_name in recently_completed_phases:
            # Already done this scan attempt (see above) - counts as a
            # success for the purposes of the loop below (scope-drift
            # check, dead-target-after-probe check, etc. all still run
            # normally using the rehydrated state).
            success = True
        else:
            success = await _run_phase_with_retry(
                pool, project_id, target_id, phase_name, target,
                discovered_subdomains, live_hosts, discovered_urls, params_found, tech_stack,
            )
            if success and phase_name in ("probe", "fuzz"):
                # Snapshot state right after the two phases that
                # populate it, so a crash during a LATER phase
                # (scan/verify/...) can still resume without re-doing
                # probe/fuzz's work.
                async with pool.acquire() as conn:
                    await _persist_pipeline_state(
                        conn, target_id, live_hosts, discovered_urls, params_found, tech_stack
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
        # conn released here, BEFORE the actual scan work starts - the
        # whole point of this refactor (see checkpoint.run_phase and
        # _phase_scan/_phase_recon) is that nothing holds a pool
        # connection across slow outbound network calls anymore.

        try:
            async with checkpoint.run_phase(pool, phase_run_id, project_id, target_id, phase_name):
                await _execute_phase(
                    pool, project_id, target_id, phase_name, target,
                    discovered_subdomains, live_hosts, discovered_urls, params_found, tech_stack,
                )
            return True  # checkpoint.run_phase already marked it completed

        except Exception:
            # checkpoint.run_phase already logged this and marked the
            # row 'failed'. We just decide here whether to retry.
            if attempt >= max_attempts:
                async with pool.acquire() as conn:
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
) -> None:
    """
    The actual work for each phase. Raises an exception if something
    goes wrong - checkpoint.run_phase (the caller) handles catching,
    logging, and recording that.

    recon and scan take `pool` directly and acquire short-lived
    connections only at the moment they actually write (see
    _save_detective_finding_pooled etc.) - these are the two phases
    that interleave DB writes with many slow outbound HTTP calls
    (subdomain takeover checks, the ~130 detective.py checks), so
    holding one connection for the whole phase was starving the rest
    of the app's pool on any project with several targets scanning at
    once (confirmed live on OCI - see the pool-exhaustion incident this
    fixes). gate/logic_hunter/triage each still acquire one connection
    for their own single call below - smaller, contained version of the
    same pattern, not touched in this pass since they weren't the
    confirmed offender, but worth the same treatment in a follow-up if
    they start showing the same symptom (triage in particular makes an
    LLM call per finding, which is the same shape of risk).
    """
    if phase_name == "recon":
        await _phase_recon(pool, project_id, target_id, target, discovered_subdomains)

    elif phase_name == "probe":
        await _phase_probe(pool, target_id, target, discovered_subdomains, live_hosts, discovered_urls, tech_stack)

    elif phase_name == "fuzz":
        await _phase_fuzz(pool, target_id, live_hosts, params_found)

    elif phase_name == "scan":
        await _phase_scan(pool, project_id, target_id, live_hosts, discovered_urls, params_found, tech_stack)

    elif phase_name == "verify":
        async with pool.acquire() as conn:
            await _phase_verify(conn, project_id)

    elif phase_name == "gate":
        async with pool.acquire() as conn:
            await _phase_gate(conn, project_id)

    elif phase_name == "logic_hunter":
        async with pool.acquire() as conn:
            await _phase_logic_hunter(conn, project_id)

    elif phase_name == "triage":
        async with pool.acquire() as conn:
            await _phase_triage(conn, project_id)

    elif phase_name == "notify":
        await _phase_notify(pool, project_id, target)

    else:
        raise ValueError(f"Unknown phase: {phase_name}")


