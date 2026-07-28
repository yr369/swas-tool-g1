"""
tools.py - runs the actual command-line security tools (subfinder, httpx,
nuclei, etc.) as subprocesses, safely.

Plain-language explanation: each of these tools is a separate program
that normally you'd run by typing a command in a terminal. This module
does that automatically, from Python, and adds three safety nets that
matter a lot for a tool running unattended:

  1. A TIMEOUT - if a tool hangs (e.g. a target stopped responding), we
     don't wait forever. We give up after a set number of seconds.
  2. GUARANTEED CLEANUP - if we give up on a tool, we make sure its
     process is actually killed, not left running in the background
     forever (a "zombie process" - this was a known bug in an earlier
     version of this tool).
  3. OUTPUT VALIDATION - a tool exiting with output doesn't necessarily
     mean it found something real. We do a basic sanity check before
     trusting the result.

Every function here returns a ToolResult, which always tells you clearly
whether the run succeeded, timed out, or errored - the caller never has
to guess.
"""

import asyncio
import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger("swas.tools")

# Default timeout for any single tool invocation. Individual calls can
# override this, but everything gets SOME timeout - no tool runs forever.
DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes

# Many CLI security tools (nuclei, dalfox, etc.) colorize their terminal
# output by default using ANSI escape codes. Those codes are meant for a
# human looking at a terminal - they're useless and unreadable once
# stored as text in our database or shown in a web UI. NO_COLOR is a
# widely-supported convention (https://no-color.org/) that tells any
# tool respecting it to skip colorizing. We set this for every subprocess
# we launch, rather than hunting down each tool's own specific flag.
_SUBPROCESS_ENV = {**os.environ, "NO_COLOR": "1"}

# Many bug bounty programs require an identifying header on all traffic
# (e.g. Bugcrowd's "X-Bug-Bounty: <username>") so the target's security
# team can distinguish authorized researcher traffic from real attacks,
# and so testing isn't accidentally blocked/rate-limited as if it were
# malicious. This is configured once via .env and applied everywhere -
# never hardcoded, since the exact header name/value is program-specific.
_RESEARCH_HEADER_NAME = os.environ.get("RESEARCH_HEADER_NAME", "")
_RESEARCH_HEADER_VALUE = os.environ.get("RESEARCH_HEADER_VALUE", "")


def _research_header() -> str | None:
    """Returns 'Name: Value' if both env vars are set, else None - tools
    that build a header flag should skip adding one when this is None,
    rather than sending a malformed empty header."""
    if _RESEARCH_HEADER_NAME and _RESEARCH_HEADER_VALUE:
        return f"{_RESEARCH_HEADER_NAME}: {_RESEARCH_HEADER_VALUE}"
    return None


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    exit_code: int | None = None
    error: str | None = None


async def run_tool(
    tool_name: str,
    args: list[str],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ToolResult:
    """
    Runs a command-line tool asynchronously (non-blocking - other scans
    can run concurrently while this one is in progress) with a hard
    timeout and guaranteed process cleanup.

    args is the full command as a list, e.g.:
        run_tool("subfinder", ["subfinder", "-d", "example.com", "-silent"])

    Why pass tool_name separately from args[0]? Because it's used for
    logging/labeling results even if the actual binary path differs.
    """
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_SUBPROCESS_ENV,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            # The tool didn't finish in time. We MUST kill it explicitly -
            # asyncio does not do this automatically just because we
            # stopped waiting. This is exactly the fix for the zombie
            # process bug: without this, the process keeps running on
            # the server forever, invisible to the rest of the app.
            process.kill()
            await process.wait()  # confirm it's actually dead before moving on
            logger.warning(
                "%s timed out after %ds and was killed", tool_name, timeout_seconds
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                timed_out=True,
                error=f"Timed out after {timeout_seconds}s",
            )

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = process.returncode

        if exit_code != 0:
            logger.warning(
                "%s exited with code %s. stderr: %s", tool_name, exit_code, stderr[:500]
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                error=f"Non-zero exit code: {exit_code}",
            )

        return ToolResult(
            tool_name=tool_name,
            success=True,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        )

    except FileNotFoundError:
        # The tool binary isn't installed / not on PATH - a setup problem,
        # not a scan problem. Surface it clearly rather than crashing the
        # whole pipeline with a confusing traceback.
        logger.error("%s binary not found - is it installed in this container?", tool_name)
        return ToolResult(
            tool_name=tool_name,
            success=False,
            error=f"{tool_name} binary not found",
        )
    except Exception as exc:
        logger.exception("Unexpected error running %s", tool_name)
        # Defensive cleanup: if a process was started but something else
        # went wrong, make sure it's not left running.
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        return ToolResult(
            tool_name=tool_name,
            success=False,
            error=str(exc),
        )


def looks_like_real_output(result: ToolResult, min_length: int = 1) -> bool:
    """
    A basic sanity check before trusting a tool's output as a real
    finding. Phase 1 keeps this simple (non-empty, ran successfully);
    later phases will add tool-specific false-positive filtering here
    (e.g. detecting WAF block pages disguised as findings).
    """
    return result.success and len(result.stdout.strip()) >= min_length


# ---------------------------------------------------------------------
# Adaptive WAF/rate-limit backoff
# ---------------------------------------------------------------------
#
# Plain-language: a human hunter who gets a 429 or a Cloudflare
# challenge page backs off and slows down instead of hammering the
# same request again immediately. Most of this codebase's tools were
# either fully successful or fully failed with no middle ground - this
# adds that middle ground: detect the specific signals that mean "the
# target is blocking us, not that the request itself was wrong", and
# retry with real delay instead of treating it as a normal failure or
# (worse) a normal empty result.

_BLOCK_SIGNALS = [
    re.compile(r"\b429\b"),
    re.compile(r"rate[ -]?limit", re.IGNORECASE),
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"request blocked", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"attention required", re.IGNORECASE),  # Cloudflare challenge title
    re.compile(r"checking your browser", re.IGNORECASE),
    re.compile(r"\bcaptcha\b", re.IGNORECASE),
    re.compile(r"akamai", re.IGNORECASE),
    re.compile(r"incapsula", re.IGNORECASE),
]


def looks_blocked(result: ToolResult) -> bool:
    """
    Heuristic only - false positives just cost an extra backoff-retry
    (cheap), false negatives just mean this specific block goes
    untreated as one (same as before this existed). Checks stdout AND
    stderr since some tools (curl-based ones) put the response body in
    stdout while others surface HTTP status only in stderr/logs.
    """
    haystack = f"{result.stdout}\n{result.stderr}"
    return any(pattern.search(haystack) for pattern in _BLOCK_SIGNALS)


async def run_tool_with_backoff(
    tool_name: str,
    args: list[str],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = 3,
    base_delay_seconds: float = 5.0,
    mutate_args_fn=None,
) -> ToolResult:
    """
    Same contract as run_tool, but if the output looks like a WAF/
    rate-limit block (see looks_blocked), retries with exponential
    backoff (base_delay * 2**attempt, so 5s/10s/20s by default) instead
    of returning the blocked result as-is. Gives up after max_retries
    and returns the last (blocked) result - callers should still treat
    a returned blocked-looking result as a real signal worth recording
    via target_intelligence.record_technique_outcome(..., outcome=
    "blocked_by_waf"), not silently retry forever.

    Does NOT retry on ordinary failures (timeout, non-zero exit with no
    block signal, binary not found) - those are real errors, retrying
    them blindly would just waste time. Backoff is specifically for the
    "the target is actively pushing back" case.

    mutate_args_fn (#4 - technique mutation on failure): optional
    `(attempt: int, base_args: list[str]) -> list[str]` called before
    each retry to actually vary the request instead of just waiting
    longer and repeating the exact same thing that got blocked - the
    same instinct a human hunter has ("that got blocked, let me try a
    different rate/UA/encoding") rather than just hoping a longer wait
    fixes it. If None, retries replay the original args unchanged
    (backoff-only, same as before this parameter existed) - existing
    call sites that don't pass this keep their exact prior behavior.
    """
    result = await run_tool(tool_name, args, timeout_seconds=timeout_seconds)
    attempt = 0
    while looks_blocked(result) and attempt < max_retries:
        delay = base_delay_seconds * (2 ** attempt)
        retry_args = mutate_args_fn(attempt, args) if mutate_args_fn else args
        logger.warning(
            "%s looks blocked (WAF/rate-limit) - backing off %.0fs before retry %d/%d%s",
            tool_name, delay, attempt + 1, max_retries,
            " (with mutated args)" if mutate_args_fn else "",
        )
        await asyncio.sleep(delay)
        result = await run_tool(tool_name, retry_args, timeout_seconds=timeout_seconds)
        attempt += 1
    return result


# A small, genuinely different set of User-Agent strings for mutation
# retries - not trying to impersonate anything deceptive, just varying
# a fingerprint that some WAF rules key on. Real browser UAs, publicly
# common, nothing exotic.
_UA_ROTATION = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
]


def nuclei_mutation(attempt: int, base_args: list[str]) -> list[str]:
    """
    Mutation strategy for nuclei retries (#4): each retry lowers the
    request rate (-rl) further and rotates the User-Agent, since
    nuclei's default rate is the most common trigger for a WAF's
    automated-traffic rule. Strips any -rl/-H User-Agent this function
    added on a previous attempt before adding this attempt's version,
    so retries don't stack duplicate flags.
    """
    args = [a for a in base_args if a not in ("-rl",) ]
    # remove a prior mutation's rate-limit value and UA header pair if present
    cleaned = []
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a == "-rl":
            skip_next = True
            continue
        cleaned.append(a)
    rate = max(1, 10 - attempt * 3)  # 10 -> 7 -> 4 req/s across retries
    ua = _UA_ROTATION[attempt % len(_UA_ROTATION)]
    return cleaned + ["-rl", str(rate), "-H", f"User-Agent: {ua}"]


def httpx_mutation(attempt: int, base_args: list[str]) -> list[str]:
    """Same idea as nuclei_mutation but for httpx-pd's -rate-limit flag."""
    rate = max(1, 20 - attempt * 6)
    ua = _UA_ROTATION[attempt % len(_UA_ROTATION)]
    return base_args + ["-rate-limit", str(rate), "-H", f"User-Agent: {ua}"]


# ---------- Specific tool wrappers ----------
# Each of these is a thin, readable wrapper so the pipeline orchestrator
# can call run_subfinder(domain) instead of remembering raw CLI flags.

async def run_subfinder(domain: str) -> ToolResult:
    """Subdomain enumeration - finds subdomains of a given domain."""
    return await run_tool(
        "subfinder",
        ["subfinder", "-d", domain, "-silent"],
        timeout_seconds=180,
    )


async def run_httpx(hosts: list[str]) -> ToolResult:
    """
    Probes a list of hosts to see which are actually alive/responding.

    Calls the binary as "httpx-pd" (not "httpx") because the Python httpx
    library's own CLI wrapper collides with the real security tool's name
    in this container - see the comment in the Dockerfile for the full
    explanation. "pd" = ProjectDiscovery, the tool's maker.

    IMPORTANT: httpx-pd does NOT accept bare hostnames as positional
    arguments - each host must be passed with "-u" (its "-target" flag).
    Passing hosts without "-u" silently produces no output and no error,
    which is exactly the bug this comment is here to prevent someone from
    reintroducing.
    """
    target_flags = []
    for host in hosts:
        target_flags.extend(["-u", host])

    header_flags = []
    if header := _research_header():
        header_flags = ["-H", header]

    return await run_tool_with_backoff(
        "httpx",
        # -td: tech-detect, fingerprints the tech stack (server, CMS,
        # frameworks) in one pass. -json: structured output so we can
        # parse out the tech list reliably instead of scraping text.
        # This is fingerprint-once, reuse-everywhere: every other tool
        # downstream gets this info instead of re-detecting on its own.
        ["httpx-pd", "-silent", "-td", "-json"] + target_flags + header_flags,
        timeout_seconds=120,
        mutate_args_fn=httpx_mutation,
    )


async def run_gau(domain: str) -> ToolResult:
    """Fetches known URLs for a domain from public archives (GetAllUrls)."""
    return await run_tool(
        "gau",
        ["gau", domain],
        timeout_seconds=120,
    )


async def run_waybackurls(domain: str) -> ToolResult:
    """Fetches historical URLs for a domain from the Wayback Machine."""
    return await run_tool(
        "waybackurls",
        ["waybackurls", domain],
        timeout_seconds=120,
    )


async def run_arjun(url: str) -> ToolResult:
    """Discovers hidden/unused HTTP parameters on a given URL."""
    args = ["arjun", "-u", url, "-q"]
    if header := _research_header():
        # IMPORTANT: --headers MUST be given a string argument here. If
        # called bare (no value), Arjun opens an interactive text editor
        # and hangs forever - confirmed via Arjun's own documentation.
        # Always pass the header value directly, never call --headers alone.
        args += ["--headers", header]
    return await run_tool("arjun", args, timeout_seconds=180)


async def run_ffuf(url: str, wordlist_path: str) -> ToolResult:
    """Fuzzes a URL for hidden directories/files using a wordlist."""
    args = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist_path, "-s"]
    if header := _research_header():
        args += ["-H", header]
    return await run_tool("ffuf", args, timeout_seconds=300)


# Bug bounty programs overwhelmingly triage SSL/TLS findings (weak
# ciphers, self-signed certs, expired certs, missing HSTS/CSP, etc.) as
# Informational or Not Applicable unless paired with a demonstrated
# exploit - reporting them alone tends to hurt signal/accuracy rating
# more than it helps. Excluding these tags at the nuclei level (rather
# than just filtering them out after the fact) also saves real scan
# time, since nuclei never runs those templates in the first place.
# Certificate/TLS data is still useful for recon (identifying tech and
# infra) - that just happens via httpx -td and manual follow-up, not by
# nuclei reporting it as a "finding". Configurable via env so a program
# whose brief explicitly wants these can still opt back in.
_DEFAULT_NUCLEI_EXCLUDE_TAGS = "ssl,tls"

# Confirmed by pulling real scan data: the overwhelming majority of
# nuclei output that's pure noise (DNS record fingerprinting, tech-
# detect, robots.txt/options-method discovery templates, etc.) is
# nuclei's own severity: "info" tier - and essentially none of it is
# ever reportable. Rather than maintain a growing, easy-to-miss list of
# individual noisy tags (dns, tech, headers, misc, ...), this filters by
# severity directly at the nuclei level via -severity, so nuclei simply
# never runs (or at least never reports) an info-tier template match in
# the first place - same "save the cost, not just the noise" reasoning
# as the tag exclusion above, and it automatically covers any new
# info-tier template ProjectDiscovery adds later without this file
# needing an update. "unknown" stays included since that's nuclei's
# severity for templates that legitimately don't declare one, not a
# noise signal. Set NUCLEI_MIN_SEVERITY="" to disable and see everything
# again (e.g. while debugging why a specific template isn't firing).
_DEFAULT_NUCLEI_MIN_SEVERITY = "low,medium,high,critical,unknown"


async def run_nuclei(target: str, include_tags: str | None = None) -> ToolResult:
    """
    Runs template-based vulnerability scanning against a target.

    -no-color is important here, not just cosmetic: without it, nuclei's
    output contains ANSI terminal color codes (e.g. "\x1b[92m"), which
    get stored as-is in the findings table and show up as unreadable
    garbage in any UI or report - this was caught during real testing
    against scanme.nmap.org.

    -etags excludes noisy, low-value template categories by default (see
    _DEFAULT_NUCLEI_EXCLUDE_TAGS above). -severity additionally drops
    the whole info tier (see _DEFAULT_NUCLEI_MIN_SEVERITY above) - the
    two are complementary, not redundant: -etags catches specific
    categories we never want regardless of severity (SSL/TLS), -severity
    catches the broad "this is recon, not a finding" tier regardless of
    category. Both configurable via env, same override pattern.

    include_tags (#1 - per-target technique adaptiveness): an ADDITIVE
    -tags value derived from THIS host's detected tech stack (see
    target_intelligence.select_nuclei_tags_for_host) - e.g. a detected
    WordPress site adds "wordpress,cms" template categories on top of
    the broad default sweep, while a bare custom-API host adds nothing
    and just gets the default. This is the mechanism that makes SWAS
    change its scanning style per target instead of running the exact
    same sweep against everything - the tech-stack model already
    existed, this is what actually reads from it (see the comment in
    pipeline.py's old _phase_scan explaining this was deliberately
    deferred until it could be done safely).
    """
    args = ["nuclei", "-u", target, "-silent", "-no-color"]
    if header := _research_header():
        args += ["-H", header]

    exclude_tags = os.environ.get("NUCLEI_EXCLUDE_TAGS", _DEFAULT_NUCLEI_EXCLUDE_TAGS)
    if exclude_tags.strip():
        args += ["-etags", exclude_tags.strip()]

    min_severity = os.environ.get("NUCLEI_MIN_SEVERITY", _DEFAULT_NUCLEI_MIN_SEVERITY)
    if min_severity.strip():
        args += ["-severity", min_severity.strip()]

    if include_tags:
        args += ["-tags", include_tags]

    return await run_tool_with_backoff("nuclei", args, timeout_seconds=300, mutate_args_fn=nuclei_mutation)


async def run_dalfox(url: str) -> ToolResult:
    """Scans a URL for XSS vulnerabilities."""
    args = ["dalfox", "url", url, "--silence"]
    if header := _research_header():
        args += ["-H", header]
    return await run_tool("dalfox", args, timeout_seconds=180)


async def run_sqlmap(url: str) -> ToolResult:
    """Tests a URL for SQL injection vulnerabilities. Only call this on
    URLs that are already known to have parameters - running it blind
    against every host wastes significant time."""
    args = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"]
    if header := _research_header():
        # sqlmap uses the long-form --header flag, not -H like the
        # Go-based tools (subfinder/httpx/nuclei share -H by convention,
        # but sqlmap's own CLI predates and differs from that).
        args += ["--header", header]
    return await run_tool("sqlmap", args, timeout_seconds=300)


async def run_notify(message: str) -> ToolResult:
    """Sends a summary notification when a scan run completes."""
    return await run_tool(
        "notify",
        ["notify", "-silent"],
        timeout_seconds=30,
    )
