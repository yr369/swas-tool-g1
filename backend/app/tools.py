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

    return await run_tool(
        "httpx",
        ["httpx-pd", "-silent"] + target_flags,
        timeout_seconds=120,
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
    return await run_tool(
        "arjun",
        ["arjun", "-u", url, "-q"],
        timeout_seconds=180,
    )


async def run_ffuf(url: str, wordlist_path: str) -> ToolResult:
    """Fuzzes a URL for hidden directories/files using a wordlist."""
    return await run_tool(
        "ffuf",
        ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist_path, "-s"],
        timeout_seconds=300,
    )


async def run_nuclei(target: str) -> ToolResult:
    """
    Runs template-based vulnerability scanning against a target.

    -no-color is important here, not just cosmetic: without it, nuclei's
    output contains ANSI terminal color codes (e.g. "\x1b[92m"), which
    get stored as-is in the findings table and show up as unreadable
    garbage in any UI or report - this was caught during real testing
    against scanme.nmap.org.
    """
    return await run_tool(
        "nuclei",
        ["nuclei", "-u", target, "-silent", "-no-color"],
        timeout_seconds=300,
    )


async def run_dalfox(url: str) -> ToolResult:
    """Scans a URL for XSS vulnerabilities."""
    return await run_tool(
        "dalfox",
        ["dalfox", "url", url, "--silence"],
        timeout_seconds=180,
    )


async def run_sqlmap(url: str) -> ToolResult:
    """Tests a URL for SQL injection vulnerabilities. Only call this on
    URLs that are already known to have parameters - running it blind
    against every host wastes significant time."""
    return await run_tool(
        "sqlmap",
        ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"],
        timeout_seconds=300,
    )


async def run_notify(message: str) -> ToolResult:
    """Sends a summary notification when a scan run completes."""
    return await run_tool(
        "notify",
        ["notify", "-silent"],
        timeout_seconds=30,
    )
