"""
verify.py - the active-confirmation phase (the "make sure before you show
me" phase). Sits between scan and gate in the pipeline:

    recon -> probe -> fuzz -> scan -> verify -> gate -> logic_hunter -> triage -> notify

Plain-language: gate.py filters obvious garbage, triage.py judges
severity/policy fit - neither one goes back out and re-tests the target
to actually prove a finding is real. verify.py is the piece that does
what Burp Suite's active-scan confirmation does: re-attack with a second,
independent technique and only call something "confirmed" if that
second technique agrees. Everything else stays "tentative" - still
visible, just not presented as if it were already proven.

Three techniques implemented here, one per finding class:

1. Blind SSRF - handled in detective.py's check_ssrf_blind_oob (uses
   oob.py's collaborator client). Not re-verified here; it's already an
   OOB-confirmed result by the time it reaches the findings table.

2. host_header_injection consequence escalation - reflection alone
   (what detective.py's check_host_header_injection proves) is real but
   often gets called Informative by programs unless there's a
   demonstrable impact path. The two well-established impact paths are
   password-reset-link poisoning (can't automate - needs a real
   reset flow) and cache poisoning (CAN automate - checking whether the
   poisoned response is actually cacheable). This escalates confidence
   when the response carries cacheable headers, and leaves it at
   'tentative' otherwise rather than silently dropping it.

3. Reflected XSS execution proof - "the payload appears in the
   response" is not proof it runs. This uses a headless browser
   (Playwright) to actually load the URL and check whether the payload
   executed (e.g. via a page.on("dialog") hook for alert()-based
   payloads). Playwright is an OPTIONAL dependency - if it isn't
   installed, this step is skipped (verification_status stays whatever
   it already was) rather than breaking the phase. See the Dockerfile
   comment for the (nontrivial, ARM64 image-size) tradeoff of adding it.

Every technique fails open: an error, timeout, or missing optional
dependency downgrades to "we couldn't verify this" (tentative/pending),
never "this is fine" or a crash of the whole phase - same principle as
gate.py's fail-open design.
"""

import asyncio
import logging
import re
import uuid

import httpx

from . import oob

logger = logging.getLogger("swas.verify")

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")

# Cacheable-response markers used for the host-header-injection
# consequence check. Presence of any of these on the poisoned response
# is what turns "the value was reflected" into "and a CDN/proxy would
# actually cache and redistribute that poisoned response."
_CACHEABLE_MARKERS = ("public", "s-maxage", "cdn-cache-control")

_XSS_PAYLOAD_MARKER = "swasxss"


def _extract_url(evidence: str | None) -> str | None:
    """
    findings.evidence is free text (e.g. "https://x.example.com/path:
    the spoofed Host header was reflected..."), not a structured URL
    column - same convention gate.py and triage.py already work around.
    Takes the first URL-shaped token.
    """
    if not evidence:
        return None
    match = _URL_RE.search(evidence)
    return match.group(0).rstrip(":.,)") if match else None


async def _verify_host_header_injection(evidence: str) -> tuple[str, str]:
    """
    Re-sends the same probe and checks Cache-Control/CDN headers on the
    poisoned response. Returns (verification_status, verification_evidence).
    """
    url = _extract_url(evidence)
    if not url:
        return "tentative", "Could not extract a URL from the original evidence to re-test."

    marker = f"swas-verify-{uuid.uuid4().hex[:8]}.invalid"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(url, headers={"Host": marker, "X-Forwarded-Host": marker})
    except httpx.HTTPError as exc:
        logger.info("verify: host-header re-check failed for %s: %s", url, exc)
        return "tentative", f"Re-verification request failed ({exc}); original finding left unconfirmed."

    cache_control = resp.headers.get("cache-control", "").lower()
    reflected = marker in resp.text[:5000] or marker in resp.headers.get("location", "")
    if not reflected:
        return "unconfirmed", (
            f"Re-tested {url} and the spoofed Host value was NOT reflected this time - "
            f"original finding did not reproduce (could be a transient WAF/cache state)."
        )

    cacheable = any(m in cache_control for m in _CACHEABLE_MARKERS)
    if cacheable:
        return "confirmed", (
            f"Reflection reproduced AND the poisoned response carries cacheable headers "
            f"(Cache-Control: {cache_control!r}) - a CDN/reverse proxy would store and "
            f"redistribute this poisoned response to other users. Real cache-poisoning impact, "
            f"not just reflection."
        )
    return "tentative", (
        f"Reflection reproduced but the response is not cacheable (Cache-Control: "
        f"{cache_control!r}) - real bug, but likely needs a concrete secondary impact "
        f"(e.g. an actual password-reset link using this value) to avoid an Informative "
        f"close on most programs."
    )


async def _verify_xss_execution(evidence: str, vuln_type: str) -> tuple[str, str] | None:
    """
    Loads the finding's URL in a real headless browser and checks
    whether a distinctive payload actually executes, instead of trusting
    that it merely appears in the response body. Returns None (leave
    verification_status untouched) if Playwright isn't installed - this
    is an opt-in capability, not a hard requirement.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("verify: playwright not installed - skipping XSS execution proof")
        return None

    url = _extract_url(evidence)
    if not url or _XSS_PAYLOAD_MARKER not in evidence:
        return None

    fired = False

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            def _on_dialog(dialog):
                nonlocal fired
                if _XSS_PAYLOAD_MARKER in (dialog.message or ""):
                    fired = True
                asyncio.create_task(dialog.dismiss())

            page.on("dialog", _on_dialog)
            try:
                await page.goto(url, timeout=10000, wait_until="networkidle")
                await page.wait_for_timeout(1500)  # let deferred/onload payloads fire
            except Exception as exc:  # noqa: BLE001 - page load can fail many ways, all mean "inconclusive"
                logger.info("verify: headless load failed for %s: %s", url, exc)
            await browser.close()
    except Exception as exc:  # noqa: BLE001 - Playwright/browser install issues, treat as unavailable
        logger.info("verify: headless browser session failed: %s", exc)
        return None

    if fired:
        return "confirmed", (
            f"Loaded {url} in a real headless browser and the injected payload actually "
            f"executed (JS dialog containing the {_XSS_PAYLOAD_MARKER!r} marker fired) - "
            f"proven code execution, not just string reflection."
        )
    return "tentative", (
        f"Payload was reflected in the response but did NOT execute when {url} was loaded "
        f"in a real browser - likely broken by context (inside an attribute, HTML-escaped, "
        f"CSP-blocked) rather than exploitable. Worth a manual look before reporting as {vuln_type}."
    )


async def verify_finding(vuln_type: str, evidence: str, finding_tag: str, oob_domain, oob_proc) -> tuple[str, str] | None:
    """
    Dispatches to the right confirmation technique for this finding's
    vuln_type. Returns (verification_status, verification_evidence) or
    None if there's no verification technique for this vuln_type (most
    findings - this phase only covers the classes above so far).
    """
    if vuln_type == "host_header_injection":
        return await _verify_host_header_injection(evidence)

    if vuln_type in ("reflected_xss", "stored_xss", "dom_xss") and _XSS_PAYLOAD_MARKER in (evidence or ""):
        return await _verify_xss_execution(evidence, vuln_type)

    return None


async def verify_project_findings(conn, project_id: int) -> int:
    """
    Runs verification on every finding still pending verification
    review for a project. Shared OOB session (see oob.py) is started
    once for the whole run and reused across every SSRF-eligible
    finding, then torn down at the end - starting one interactsh-client
    process per finding would be wasteful and would fragment the canary
    domain space for no benefit.
    """
    rows = await conn.fetch(
        "SELECT id, vuln_type, evidence FROM findings "
        "WHERE project_id = $1 AND verification_status = 'pending'",
        project_id,
    )
    if not rows:
        return 0

    oob_domain, oob_proc = await oob.start_session()
    verified = 0
    try:
        for row in rows:
            finding_tag = f"f{row['id']}"
            result = await verify_finding(
                row["vuln_type"], row["evidence"] or "", finding_tag, oob_domain, oob_proc,
            )
            if result is None:
                # No technique for this vuln_type - leave it 'pending' so
                # it's visibly distinguishable from "we tried and
                # couldn't confirm" (tentative/unconfirmed).
                continue
            status, verify_evidence = result
            await conn.execute(
                "UPDATE findings SET verification_status = $1, verification_evidence = $2 WHERE id = $3",
                status, verify_evidence[:1000], row["id"],
            )
            verified += 1
    finally:
        await oob.stop_session(oob_proc)

    return verified
