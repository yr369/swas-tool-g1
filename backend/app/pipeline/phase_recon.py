"""
pipeline/phase_recon.py - the recon phase (subdomain enumeration etc.),
split out of the former monolithic pipeline.py (batch: pipeline split).
"""

import asyncio
import json
import logging
import os
import re

import asyncpg

from .. import auth_policy, auth_sessions, checkpoint, detective, evidence_lifecycle, finding_dedup, fp_filter, gate, git_dumper, logic_hunter, oob, screenshots, target_intelligence, tools, triage, verify

from .shared import logger
from .persistence import _get_recon_cache_if_fresh, _save_detective_finding_pooled, _save_recon_cache_pooled


async def _phase_recon(
    pool: asyncpg.Pool,
    project_id: int,
    target_id: int,
    target: str,
    discovered_subdomains: list[str],
) -> None:
    """
    Subdomain enumeration, then check which ones are actually alive.

    Reuses a recent subfinder result (see _get_recon_cache_if_fresh)
    when one exists within RECON_CACHE_HOURS instead of re-querying
    every OSINT source again - see that function's docstring for why.
    The takeover check below still runs every single time regardless of
    cache hit/miss: CNAME state (the thing that check actually cares
    about) can change independently of the subdomain list itself, and
    it's cheap enough that skipping it would save little while risking
    a missed takeover.
    """
    cached = await _get_recon_cache_if_fresh(pool, target_id)
    if cached is not None:
        discovered_subdomains.extend(cached)
        logger.info(
            "recon: reused cached subdomain list (%d found, within %.0fh) for target_id=%s - skipped subfinder",
            len(cached), _RECON_CACHE_HOURS, target_id,
        )
    else:
        result = await tools.run_subfinder(target)
        if not result.success:
            raise RuntimeError(f"subfinder failed: {result.error}")

        found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        discovered_subdomains.extend(found or [target])  # fall back to the target itself
        logger.info("recon: found %d subdomains for %s", len(discovered_subdomains), target)
        await _save_recon_cache_pooled(pool, target_id, discovered_subdomains)

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
            await _save_detective_finding_pooled(pool, project_id, target_id, res)

    # Detective check: dangling NS delegation takeover (batch 23).
    # Different, rarer technique than the CNAME check above - reuses the
    # same candidate list/cap since both are cheap DoH-only lookups.
    logger.info("detective: running dangling NS delegation check against %d candidate(s)", len(candidates))
    ns_takeover_results = await asyncio.gather(
        *(detective.check_dangling_ns_delegation_takeover(host) for host in candidates),
        return_exceptions=True,
    )
    for res in ns_takeover_results:
        if isinstance(res, Exception):
            logger.debug("dangling NS delegation check raised: %s", res)
            continue
        if res is not None:
            await _save_detective_finding_pooled(pool, project_id, target_id, res)


