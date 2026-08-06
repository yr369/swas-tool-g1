"""
pipeline/phase_probe.py - the probe phase (httpx liveness/tech-detection
pass), split out of the former monolithic pipeline.py.
"""

import asyncio
import json
import logging
import os
import re

import asyncpg

from .. import auth_policy, auth_sessions, checkpoint, detective, evidence_lifecycle, finding_dedup, fp_filter, gate, git_dumper, logic_hunter, oob, screenshots, target_intelligence, tools, triage, verify

from .shared import logger
from .persistence import _save_surface_endpoints_pooled


async def _phase_probe(
    pool: asyncpg.Pool,
    target_id: int,
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

    Also persists every observed URL into attack_surface_endpoints (see
    attack_surface_model.sql) - this is the one place that data stops
    being thrown away at the end of the scan run.
    """
    hosts_to_check = discovered_subdomains or [target]
    surface_endpoints: list[dict] = []

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
                    surface_endpoints.append({
                        "url": url,
                        "source": "httpx",
                        "is_live": True,
                        "status_code": record.get("status_code"),
                        "tech_stack": record.get("tech", []),
                    })
            except json.JSONDecodeError:
                # Fall back to treating the raw line as a plain host -
                # never silently drop a live host just because one line
                # wasn't valid JSON (e.g. a stray log line mixed into
                # stdout). No tech info for this one, that's fine.
                live_hosts.append(line)
                surface_endpoints.append({"url": line, "source": "httpx", "is_live": True})
    # A non-fatal httpx failure shouldn't kill the whole phase - URL
    # discovery below can still proceed even without a live host list.
    # We still raise if BOTH httpx and the URL tools fail (see below).

    gau_result = await tools.run_gau(target)
    if gau_result.success:
        gau_urls = [line.strip() for line in gau_result.stdout.splitlines() if line.strip()]
        discovered_urls.extend(gau_urls)
        # is_live intentionally omitted (stays NULL/unknown on first
        # insert, or whatever a prior scan already determined on
        # conflict) - gau returns historical archive URLs, not
        # confirmed-live ones.
        surface_endpoints.extend({"url": u, "source": "gau"} for u in gau_urls)

    if not httpx_result.success and not gau_result.success:
        raise RuntimeError(
            f"probe phase found nothing usable: httpx={httpx_result.error}, "
            f"gau={gau_result.error}"
        )

    await _save_surface_endpoints_pooled(pool, target_id, surface_endpoints)

    logger.info(
        "probe: %d live hosts, %d historical URLs for %s",
        len(live_hosts), len(discovered_urls), target,
    )

    # Rescan/freshness trigger (#14): compare this scan's live-host +
    # tech-stack fingerprint to the last one seen. A real change (new
    # host went live, stack changed) resets this target's clusters back
    # to 'pending' so logic_hunter/triage re-examine it with fresh eyes,
    # instead of relying solely on "a new finding showed up" to trigger
    # a re-hunt.
    async with pool.acquire() as conn:
        await target_intelligence.check_and_reset_on_change(conn, target_id, live_hosts, tech_stack)

    # Screenshot (#7) - opt-in, see screenshots.py. One per target
    # (the first live host is representative enough for a quick visual
    # triage glance; capturing every discovered subdomain would be a
    # lot of Chromium launches for marginal extra signal).
    if screenshots.is_enabled() and live_hosts:
        await screenshots.capture(target_id, live_hosts[0])


