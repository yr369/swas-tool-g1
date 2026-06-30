"""
vrt.py - fetches and caches Bugcrowd's real Vulnerability Rating Taxonomy
(VRT), and provides it to triage so severity gets mapped into Bugcrowd's
actual scoring language (P1-P5 + category names) instead of just our
generic critical/high/medium/low/info scale.

Plain-language: our triage already says "this is high severity" - but
Bugcrowd doesn't pay based on that word, they pay based on which VRT
category and priority (P1 Critical down to P5 Informational) a finding
falls into. This module pulls the REAL, current VRT directly from
Bugcrowd's official open-source repo (not a hardcoded snapshot that goes
stale), and gives triage the closest-matching categories to choose from.
"""

import json
import logging
import time

import httpx

logger = logging.getLogger("swas.vrt")

_VRT_URL = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
_CACHE_TTL_SECONDS = 24 * 60 * 60  # re-fetch at most once a day - the VRT
# changes infrequently (it's on v1.18 as of writing), no need to hit
# GitHub on every triage call.

_cache: dict = {"flattened": None, "fetched_at": 0.0}


def _flatten(node: dict, path: list[str]) -> list[dict]:
    """Walks the category -> subcategory -> variant tree into a flat list
    of {path, priority, id} - much easier to search/match against than
    the nested structure."""
    current_path = path + [node["name"]]
    results = []
    if node.get("type") == "variant":
        results.append({
            "path": " > ".join(current_path),
            "priority": node.get("priority", "Varies"),
            "id": node["id"],
        })
    for child in node.get("children", []):
        results.extend(_flatten(child, current_path))
    return results


async def get_vrt_entries() -> list[dict]:
    """
    Returns the flattened VRT as a list of {path, priority, id} dicts,
    fetching fresh from GitHub if the cache is empty or stale. If the
    fetch fails (network issue, GitHub down), falls back to whatever's
    cached - even stale data is more useful than nothing, and this
    should never be the reason a triage call fails outright.
    """
    now = time.time()
    if _cache["flattened"] is not None and (now - _cache["fetched_at"]) < _CACHE_TTL_SECONDS:
        return _cache["flattened"]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(_VRT_URL)
            response.raise_for_status()
            data = response.json()

        flattened = []
        for category in data["content"]:
            flattened.extend(_flatten(category, []))

        _cache["flattened"] = flattened
        _cache["fetched_at"] = now
        logger.info("Fetched fresh VRT: %d entries (release %s)", len(flattened), data.get("metadata", {}).get("release_date"))
        return flattened

    except Exception as exc:
        if _cache["flattened"] is not None:
            logger.warning("VRT fetch failed, using stale cache: %s", exc)
            return _cache["flattened"]
        logger.warning("VRT fetch failed and no cache available: %s", exc)
        return []


def format_vrt_context(entries: list[dict], max_entries: int = 40) -> str:
    """
    Formats a (small, token-budgeted) subset of VRT entries for inclusion
    in a triage prompt. We don't dump all 315 entries into every prompt -
    that would be expensive and mostly irrelevant. Phase 2 keeps this
    simple: a representative sample across priorities, capped, so the
    model has Bugcrowd's actual scoring vocabulary to choose from without
    blowing up token cost. A more targeted, finding-specific subset is a
    reasonable future improvement.
    """
    if not entries:
        return ""

    sample = entries[:max_entries]
    lines = [f'- {e["path"]} (Priority: P{e["priority"]})' if isinstance(e["priority"], int)
             else f'- {e["path"]} (Priority: Varies)' for e in sample]
    return (
        "\nBugcrowd VRT reference (a sample of real categories and their "
        "baseline priority, P1=Critical to P5=Informational):\n"
        + "\n".join(lines)
        + "\n\nIf this finding clearly matches one of these categories, mention "
        "the closest matching VRT category name and its priority in your reasoning."
    )
