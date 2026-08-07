"""
evidence_lifecycle.py - batch 24: the four pieces of "what happens to a
finding and its evidence AFTER it's first captured" that nothing else in
the pipeline covers.

Plain-language, one paragraph each:

1. Dead-target detection (pre-flight, cheap). run_target_pipeline
   already stops a scan early if probe finds zero live hosts - but that
   only fires AFTER a full subfinder/subdomain-enumeration pass has
   already run. This adds a much cheaper check BEFORE any of that: if
   this target was scanned before and we have a cached subdomain list,
   try a small sample of previously-known hosts first. If every single
   one is now unreachable, the whole target has likely gone dark since
   last scan (decommissioned, expired, DNS pulled) - skip the entire
   pipeline run instead of burning a full recon pass discovering that
   the same way, and record when it went dark so it's visible instead
   of silently retried forever.

2. Finding evidence integrity check ("evidence rot"). A finding's
   evidence proves a bug was real AT SCAN TIME. Time passes between a
   scan and writing a report - the target gets patched, a WAF rule goes
   up, a feature is removed. Submitting a report whose evidence quietly
   stopped being true is a wasted report and a credibility cost. This
   re-fetches the URL embedded in a finding's evidence and re-checks for
   the SAME distinguishing signature that made the finding fire in the
   first place, right before a report gets drafted - not a full re-scan,
   one targeted re-check.

3. Finding evidence archival. findings.raw_output_path has existed in
   the schema and the API response model since Phase 1 but was NEVER
   actually written by any code path - every finding's evidence has
   silently been capped at whatever _save_finding/_save_detective_finding
   truncate it to (5000 chars), with no way to recover anything beyond
   that. This writes the FULL, untruncated evidence to disk and
   populates that already-existing column, so nothing is lost even
   though the DB copy stays capped for query/display performance.

4. Alert fatigue guard. target_intelligence.get_unalerted_high_value_findings
   returns every qualifying finding with no cap, and _phase_notify sends
   one notify() call per finding with no grouping - a single widespread
   misconfiguration across 40 subdomains currently means 40 separate
   real-time alerts in one burst. This groups findings by the same
   (tool_name, vuln_type) signature triage.py already uses for outcome
   lookups, sends full detail for a small number of distinct signatures,
   and collapses anything beyond that into one summary line per
   signature - so a burst of structurally-identical findings costs one
   alert, not one per finding.
"""

import json
import logging
import os
import re
from pathlib import Path

import asyncpg
import httpx

logger = logging.getLogger("swas.evidence_lifecycle")

_TIMEOUT = httpx.Timeout(8.0, connect=4.0)

# ---------------------------------------------------------------------
# 1. Dead-target detection
# ---------------------------------------------------------------------
_LIVENESS_SAMPLE_SIZE = 8


async def check_target_alive_before_scan(conn: asyncpg.Connection, target_id: int, target: str) -> bool:
    """
    Cheap pre-flight liveness check, run before phase 1 (recon) starts.
    Uses a small sample of PREVIOUSLY discovered subdomains from
    recon_cache, if any exist - a target scanned for the first time has
    no cache yet and always passes through (nothing to compare against,
    must actually scan to find out). If a cache exists and every sampled
    host fails to answer at all (DNS failure or connection refused/
    timeout on both https:// and http://), marks scope_targets.dead_since
    and returns False; a target that answers on ANY sampled host clears
    dead_since (it's back) and returns True. Fails open (returns True,
    i.e. "go ahead and scan") on any unexpected error - a liveness-check
    bug should never be the reason a real target never gets scanned.
    """
    try:
        row = await conn.fetchrow(
            "SELECT recon_cache FROM scope_targets WHERE id = $1", target_id
        )
    except Exception as exc:
        logger.warning("evidence_lifecycle: liveness pre-check DB read failed for target_id=%s: %s", target_id, exc)
        return True

    if row is None or not row["recon_cache"]:
        return True  # first-ever scan of this target - nothing cached to sample, must scan

    try:
        cached_hosts = json.loads(row["recon_cache"])
    except (ValueError, TypeError):
        return True
    if not cached_hosts:
        return True

    sample = random.sample(cached_hosts, min(_LIVENESS_SAMPLE_SIZE, len(cached_hosts)))
    any_alive = False
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            for host in sample:
                host = host.strip()
                if not host:
                    continue
                for scheme in ("https://", "http://"):
                    probe_url = host if host.startswith(("http://", "https://")) else scheme + host
                    try:
                        await client.head(probe_url)
                        any_alive = True
                        break
                    except httpx.HTTPError:
                        continue
                if any_alive:
                    break
    except Exception as exc:
        logger.warning("evidence_lifecycle: liveness pre-check request loop failed for target_id=%s: %s", target_id, exc)
        return True

    try:
        if any_alive:
            await conn.execute(
                "UPDATE scope_targets SET dead_since = NULL WHERE id = $1", target_id
            )
        else:
            await conn.execute(
                "UPDATE scope_targets SET dead_since = COALESCE(dead_since, now()) WHERE id = $1",
                target_id,
            )
            logger.info(
                "evidence_lifecycle: target_id=%s (%s) appears dead - none of %d previously-known "
                "host(s) responded, skipping this scan run",
                target_id, target, len(sample),
            )
    except Exception as exc:
        logger.warning("evidence_lifecycle: liveness pre-check DB write failed for target_id=%s: %s", target_id, exc)

    return any_alive


# ---------------------------------------------------------------------
# 2. Finding evidence integrity check ("evidence rot")
# ---------------------------------------------------------------------
_INTEGRITY_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _extract_url(evidence: str | None) -> str | None:
    if not evidence:
        return None
    match = _INTEGRITY_URL_RE.search(evidence)
    return match.group(0).rstrip(":.,)") if match else None


def _extract_distinguishing_signature(evidence: str | None) -> str | None:
    """
    Evidence text always quotes the specific proof string in single or
    double quotes right after it fires (see any detective.py check's
    evidence f-string - 'root:x:0:0:', "AKIA...", the OOB marker, etc.).
    Pulls the LONGEST quoted substring out as the thing to re-check for,
    since the longest quote is almost always the actual proof rather
    than a URL fragment or parameter name that happens to be quoted too.
    """
    if not evidence:
        return None
    candidates = re.findall(r"'([^']{6,200})'|\"([^\"]{6,200})\"", evidence)
    flat = [a or b for a, b in candidates]
    if not flat:
        return None
    return max(flat, key=len)


async def check_evidence_integrity(evidence: str | None) -> tuple[str, str]:
    """
    Re-fetches the URL embedded in `evidence` and checks whether the
    same distinguishing signature that made the finding fire originally
    is still present in the response. Returns (status, note) where
    status is one of:
      "reproducible" - signature still present, evidence still holds up
      "rotted"       - URL still reachable but signature no longer present
      "inconclusive" - couldn't extract a URL/signature, or the request
                       itself failed (target down, timeout, etc.) - NOT
                       the same as "rotted"; a down target doesn't mean
                       the bug was fixed, it means we can't tell right now
    Read-only - a single GET, never re-runs the original payload/probe
    (which could be a multi-step injection, an OOB check, etc.) - this
    is a lighter-weight "is the surface still shaped the same way" check,
    not a full re-verification.
    """
    url = _extract_url(evidence)
    signature = _extract_distinguishing_signature(evidence)
    if not url or not signature:
        return "inconclusive", "Could not extract both a URL and a distinguishing signature from this evidence to re-check."

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return "inconclusive", f"Re-check request to {url} failed ({exc}) - target may just be temporarily down."

    if signature in resp.text[:20000]:
        return "reproducible", f"Re-fetched {url} and the original signature ({signature[:60]!r}) is still present."
    return "rotted", (
        f"Re-fetched {url} and the original signature ({signature[:60]!r}) is NO LONGER present - "
        f"this finding may have been patched or the surface has changed since the original scan. "
        f"Worth a manual look before including in a report."
    )


async def check_and_record_evidence_integrity(conn: asyncpg.Connection, finding_id: int, evidence: str | None) -> str:
    """Runs check_evidence_integrity and persists the result onto the
    finding row (evidence_integrity, evidence_checked_at), so the
    dashboard/report flow can show "last verified" info without
    re-running the check on every page load. Returns the status string."""
    status, note = await check_evidence_integrity(evidence)
    try:
        await conn.execute(
            "UPDATE findings SET evidence_integrity = $1, evidence_checked_at = now() WHERE id = $2",
            status, finding_id,
        )
    except Exception as exc:
        logger.warning("evidence_lifecycle: failed to persist integrity result for finding_id=%s: %s", finding_id, exc)
    return status


# ---------------------------------------------------------------------
# 3. Finding evidence archival
# ---------------------------------------------------------------------
EVIDENCE_ARCHIVE_DIR = Path(os.environ.get("EVIDENCE_ARCHIVE_DIR", "/data/scans/evidence_archive"))

# Only bother archiving when the full evidence is actually longer than
# what the DB column keeps - archiving a 200-char evidence string to its
# own file would just be noise for zero recovery benefit.
_ARCHIVE_THRESHOLD_CHARS = 5000


def archive_evidence_to_disk(finding_id: int, full_evidence: str) -> str | None:
    """
    Writes the FULL, untruncated evidence for a finding to
    EVIDENCE_ARCHIVE_DIR/{finding_id}.txt and returns that path (to be
    stored in findings.raw_output_path - a column that's existed since
    Phase 1 but was never actually written until this). Returns None
    (and logs, doesn't raise) on any filesystem error, or if the
    evidence isn't long enough to be worth archiving separately from
    what's already kept in the findings.evidence column - callers should
    treat None as "nothing to store", not an error condition.
    """
    if not full_evidence or len(full_evidence) <= _ARCHIVE_THRESHOLD_CHARS:
        return None
    try:
        EVIDENCE_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        path = EVIDENCE_ARCHIVE_DIR / f"{finding_id}.txt"
        path.write_text(full_evidence, encoding="utf-8")
        return str(path)
    except OSError as exc:
        logger.warning("evidence_lifecycle: failed to archive evidence for finding_id=%s: %s", finding_id, exc)
        return None


# ---------------------------------------------------------------------
# 4. Alert fatigue guard
# ---------------------------------------------------------------------
# Beyond this many DISTINCT (tool_name, vuln_type) signatures in one
# notify pass, remaining signatures get collapsed into one summary line
# each instead of full detail - keeps a genuinely diverse batch of real
# findings detailed while still capping total alert volume.
_MAX_DETAILED_ALERT_SIGNATURES = 5
# Beyond this many findings sharing the SAME signature, only the first
# this-many get named individually within that signature's alert; the
# rest are folded into "+N more".
_MAX_NAMED_PER_SIGNATURE = 3


def group_and_throttle_alerts(findings: list[dict]) -> list[dict]:
    """
    Groups a batch of high-value findings by (tool_name, vuln_type) -
    the same signature shape triage.py's build_signature() uses for
    outcome lookups, so "the same kind of bug across many hosts" is
    recognized the same way here as it is there. Returns a list of
    {"message": str, "finding_ids": list[int]} entries, ready to hand
    to tools.run_notify() one at a time - a single alert per DISTINCT
    signature (with up to _MAX_NAMED_PER_SIGNATURE targets named and
    the rest counted), and beyond _MAX_DETAILED_ALERT_SIGNATURES
    distinct signatures in one batch, the remaining signatures collapse
    to one short summary line each rather than full detail - this is
    what actually prevents a 40-finding burst from becoming 40 alerts.
    """
    if not findings:
        return []

    grouped: dict[tuple[str, str], list[dict]] = {}
    order: list[tuple[str, str]] = []
    for f in findings:
        key = (f.get("tool_name", "unknown"), f.get("vuln_type", "unknown"))
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(f)

    alerts: list[dict] = []
    for i, key in enumerate(order):
        tool_name, vuln_type = key
        members = grouped[key]
        finding_ids = [m["id"] for m in members]

        if i < _MAX_DETAILED_ALERT_SIGNATURES:
            named = members[:_MAX_NAMED_PER_SIGNATURE]
            targets = ", ".join(m.get("target", "?") for m in named)
            extra = len(members) - len(named)
            extra_note = f" (+{extra} more)" if extra > 0 else ""
            severity = (members[0].get("severity") or "unknown").upper()
            reasoning = members[0].get("triage_reasoning") or ""
            message = (
                f"[HIGH VALUE] {severity} {vuln_type} ({tool_name}) - {len(members)} finding(s) "
                f"across {targets}{extra_note} - triage says likely accepted. {reasoning}"
            )
        else:
            message = (
                f"[HIGH VALUE, GROUPED] {vuln_type} ({tool_name}) - {len(members)} more finding(s) "
                f"in this batch - see dashboard for details (alert volume capped after "
                f"{_MAX_DETAILED_ALERT_SIGNATURES} distinct signatures in one run)."
            )

        alerts.append({"message": message[:1000], "finding_ids": finding_ids})

    return alerts

