"""
pipeline/phase_fuzz.py - the fuzz phase (arjun param discovery), split
out of the former monolithic pipeline.py.
"""

import asyncpg

from .. import tools

from .shared import logger
from .persistence import _parse_arjun_params, _save_surface_params_pooled


async def _phase_fuzz(pool: asyncpg.Pool, target_id: int, live_hosts: list[str], params_found: dict[str, bool]) -> None:
    """
    Discover parameters on live hosts. This determines which hosts are
    worth running sqlmap/dalfox against in the scan phase - we don't run
    those expensive tools blindly against every host.

    Also parses arjun's actual output (best-effort - see
    _parse_arjun_params) and merges the real param names into the
    matching attack_surface_endpoints row, instead of only recording the
    yes/no "this host has some params" flag that params_found tracks.
    """
    for host in live_hosts[:10]:  # Phase 1: cap how many hosts get deep-probed
        result = await tools.run_arjun(host)
        if result.success and result.stdout.strip():
            params_found[host] = True
            param_names = _parse_arjun_params(result.stdout)
            if param_names:
                await _save_surface_params_pooled(pool, target_id, host, param_names)

    logger.info("fuzz: %d hosts have discoverable parameters", len(params_found))
    # Note: we deliberately don't raise here even if nothing was found -
    # "no parameters on this target" is a valid, useful result, not a
    # failure.


