"""
oob.py - out-of-band interaction confirmation (the "Burp Collaborator"
piece of the pipeline).

Plain-language: for blind vulns (SSRF to internal services, blind XXE,
blind SSTI, some blind RCE), the target never reflects anything back in
its HTTP response - the only proof is that the TARGET SERVER ITSELF made
a network call to a canary domain we control, days or seconds later,
out-of-band from the original request/response. That's what Burp
Collaborator does, and it's the single biggest lever for turning a
guess into a confirmed finding.

This wraps interactsh-client (ProjectDiscovery, same family as
subfinder/httpx/nuclei already in this image) rather than reimplementing
the interactsh wire protocol in Python - it already speaks it correctly,
and driving it as a subprocess matches how every other scanning tool in
tools.py is already used.

Usage pattern:
    domain, proc = await start_session()
    payload_url = f"http://{finding_id}.{domain}/"    # embed the canary
    ...send the payload to the target...
    await asyncio.sleep(_POLL_WAIT_SECONDS)            # give it time to fire
    hit = await check_interaction(proc, finding_id)
    await stop_session(proc)

One session is meant to be shared across every OOB-eligible finding in a
single verify-phase run (not one process per finding) - interactsh-client
logs every interaction it receives as a JSON line on stdout with the
full requested subdomain, so a shared session distinguishes findings by
the finding_id prefix embedded in the canary hostname.
"""

import asyncio
import json
import logging
import re

logger = logging.getLogger("swas.oob")

# How long to wait after sending a payload before polling for the
# callback. Real infra can take a few seconds (DNS propagation, the
# target's own outbound request latency) - too short a wait is the most
# likely cause of false "unconfirmed" results, so this errs generous.
_POLL_WAIT_SECONDS = 8
_STARTUP_TIMEOUT_SECONDS = 15

_DOMAIN_LINE_RE = re.compile(r"([a-z0-9]{20,40}\.oast\.[a-z]+)", re.IGNORECASE)


async def start_session() -> tuple[str | None, "asyncio.subprocess.Process | None"]:
    """
    Starts one interactsh-client process for the whole verify run and
    returns (canary_domain, process). Returns (None, None) if the
    binary isn't installed or startup fails - callers must treat that
    as "OOB confirmation unavailable this run", not an error, since a
    missing optional binary should never take down the pipeline (same
    fail-open principle as gate.py).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "interactsh-client", "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.info("oob: interactsh-client not installed - OOB confirmation skipped this run")
        return None, None

    try:
        domain = await asyncio.wait_for(_read_domain(proc), timeout=_STARTUP_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.info("oob: interactsh-client didn't report a domain within %ss - killing it", _STARTUP_TIMEOUT_SECONDS)
        proc.kill()
        return None, None

    if domain is None:
        proc.kill()
        return None, None

    logger.info("oob: session started, canary domain=%s", domain)
    return domain, proc


async def _read_domain(proc: "asyncio.subprocess.Process") -> str | None:
    """
    interactsh-client prints its assigned domain in its startup banner
    on stderr before any JSON interaction lines arrive on stdout. We
    scan stderr line-by-line until the domain pattern shows up.
    """
    assert proc.stderr is not None
    while True:
        line = await proc.stderr.readline()
        if not line:
            return None
        text = line.decode("utf-8", errors="ignore")
        match = _DOMAIN_LINE_RE.search(text)
        if match:
            return match.group(1)


async def wait_for_interaction(proc: "asyncio.subprocess.Process", finding_tag: str) -> dict | None:
    """
    Polls stdout for up to _POLL_WAIT_SECONDS for a JSON interaction
    line whose full-id/unique-id contains finding_tag (the finding_id
    or a short random suffix embedded in the canary hostname when the
    payload was built). Returns the parsed interaction dict (protocol,
    remote-address, raw-request) if found, else None - None means "no
    callback observed in the wait window", which is the honest signal
    for an unconfirmed/tentative result, not proof of absence.
    """
    assert proc.stdout is not None
    deadline = asyncio.get_event_loop().time() + _POLL_WAIT_SECONDS
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if not line:
            return None
        try:
            event = json.loads(line.decode("utf-8", errors="ignore"))
        except (ValueError, UnicodeDecodeError):
            continue
        full_id = str(event.get("full-id", "")) + str(event.get("unique-id", ""))
        if finding_tag in full_id:
            return event


async def stop_session(proc: "asyncio.subprocess.Process | None") -> None:
    if proc is None:
        return
    try:
        proc.kill()
        await proc.wait()
    except ProcessLookupError:
        pass
