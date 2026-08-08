"""
pipeline/persistence.py - every _save_*/_get_*/_persist_*/_upsert_*
helper the pipeline phases use to write findings, scan notes, recon
cache, and attack-surface endpoints/params back to Postgres. Split
out of the former monolithic pipeline.py; these all stayed together
(rather than one file per phase's helpers) since several are shared
across phases (e.g. _save_detective_finding_pooled is called from
both phase_recon.py and phase_scan.py) and duplicating them per-phase
would reintroduce the exact drift-risk a split is meant to avoid.
"""

import json
import os
import re

import asyncpg

from .. import evidence_lifecycle, finding_dedup, fp_filter
from .shared import logger

_AEM_HOSTNAME_PATTERN = re.compile(r"\baem\b|aem[-_]?(prod|stage|dev|author|publish)", re.IGNORECASE)
_AEM_TECH_PATTERN = re.compile(r"aem|adobe experience manager", re.IGNORECASE)

def _log_aem_pivot_hint(host: str, tech: list[str]) -> None:
    """
    Zero-cost recon nudge: if this host looks like it's running Adobe
    Experience Manager (by hostname convention or by httpx -td tech
    detection), log a note pointing at AEM-specific manual testing
    rather than letting the host just blend in as "another target for
    generic nuclei/dalfox/sqlmap runs". This does not change what scans
    are run in Phase 1 - it's a visibility aid so a human reviewing logs
    knows where the higher-value manual effort is likely to pay off.
    """
    hostname_hit = bool(_AEM_HOSTNAME_PATTERN.search(host))
    tech_hit = any(_AEM_TECH_PATTERN.search(t) for t in tech)
    if hostname_hit or tech_hit:
        logger.info(
            "recon: %s looks like Adobe Experience Manager (AEM) - consider pivoting "
            "manual testing to dispatcher config exposure, default/misconfigured admin "
            "interfaces (e.g. /crx/de), and SSRF opportunities, rather than reporting "
            "generic TLS/cert findings for this host",
            host,
        )


# nuclei's own severity tags map directly onto our schema's severity
# values - no AI needed to know that nuclei already says "[medium]".
_NUCLEI_SEVERITY_TAGS = {"critical", "high", "medium", "low", "info"}


async def _save_finding_pooled(
    pool: asyncpg.Pool, project_id: int, target_id: int, tool_name: str, raw_output: str
) -> None:
    async with pool.acquire() as conn:
        await _save_finding(conn, project_id, target_id, tool_name, raw_output)


async def _save_nuclei_findings_pooled(
    pool: asyncpg.Pool, project_id: int, target_id: int, raw_output: str
) -> None:
    """Thin pool-based wrapper so callers inside a phase full of slow
    outbound HTTP calls (_phase_scan) can save without holding a
    connection across all of them - see checkpoint.run_phase's
    docstring for the full "why" behind this pattern. The 3 _*_pooled
    wrappers here exist purely so call sites deep inside _phase_scan
    could be a one-line mechanical swap (`_save_x(conn, ...)` ->
    `_save_x_pooled(pool, ...)`) rather than needing an `async with
    pool.acquire()` block correctly indented at every one of the ~40
    call sites."""
    async with pool.acquire() as conn:
        await _save_nuclei_findings(conn, project_id, target_id, raw_output)


async def _save_scan_note_pooled(
    pool: asyncpg.Pool, project_id: int, target_id: int, check_name: str, note: str
) -> None:
    async with pool.acquire() as conn:
        await _save_scan_note(conn, project_id, target_id, check_name, note)


# How long a subfinder result stays reusable before recon re-runs it for
# real. Subdomain sets for a given root domain rarely change hour to
# hour, so a target on a 6-hourly schedule (or someone repeatedly
# clicking manual rescan) was paying full subfinder cost - which hits
# many external OSINT sources per run - for the same answer every time.
# Default (12h) means: 6-hourly schedules reuse the cache ~3 of 4 runs,
# daily/weekly schedules always get fresh recon (their interval already
# exceeds the cache window), and single-target manual rescans get the
# same speedup as scheduled ones. Set RECON_CACHE_HOURS=0 to disable and
# always run fresh subfinder.
_RECON_CACHE_HOURS = float(os.environ.get("RECON_CACHE_HOURS", "12"))


async def _get_recon_cache_if_fresh(pool: asyncpg.Pool, target_id: int) -> list[str] | None:
    """
    Returns the cached subdomain list for this target if one exists and
    is younger than _RECON_CACHE_HOURS, else None (meaning: run subfinder
    for real). A disabled cache (_RECON_CACHE_HOURS <= 0) always returns
    None so recon behaves exactly as it did before this feature.
    """
    if _RECON_CACHE_HOURS <= 0:
        return None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT recon_cache FROM scope_targets "
            "WHERE id = $1 AND recon_cached_at > now() - ($2 || ' hours')::interval",
            target_id, str(_RECON_CACHE_HOURS),
        )
    if row is None or not row["recon_cache"]:
        return None
    try:
        return json.loads(row["recon_cache"])
    except (ValueError, TypeError):
        return None  # corrupt cache row - fail open to a fresh subfinder run, not a crash


async def _save_recon_cache_pooled(pool: asyncpg.Pool, target_id: int, subdomains: list[str]) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE scope_targets SET recon_cache = $1, recon_cached_at = now() WHERE id = $2",
            json.dumps(subdomains), target_id,
        )


# Cap how much of each list gets persisted - this is a resume snapshot,
# not a permanent record (findings/scan_notes already own that job), so
# keeping it bounded matters more than keeping every last entry.
_STATE_SNAPSHOT_LIST_CAP = 500


async def _persist_pipeline_state(
    conn: asyncpg.Connection,
    target_id: int,
    live_hosts: list[str],
    discovered_urls: list[str],
    params_found: dict[str, bool],
    tech_stack: dict[str, list[str]],
) -> None:
    """Batch 26 item 4: snapshots what probe/fuzz discovered so a scan
    interrupted by a crash/redeploy can resume without re-running them -
    see checkpoint.get_recently_completed_phases and this function's
    counterpart, the rehydration block at the top of run_target_pipeline."""
    await conn.execute(
        """
        UPDATE scope_targets
        SET state_live_hosts = $1, state_discovered_urls = $2,
            state_params_found = $3, state_tech_stack = $4, state_updated_at = now()
        WHERE id = $5
        """,
        json.dumps(live_hosts[:_STATE_SNAPSHOT_LIST_CAP]),
        json.dumps(discovered_urls[:_STATE_SNAPSHOT_LIST_CAP]),
        json.dumps(params_found),
        json.dumps(tech_stack),
        target_id,
    )


# 401/403 on an unauthenticated probe is a reasonable (not certain) signal
# that an endpoint requires auth; 200 is a reasonable (not certain) signal
# that it doesn't. Anything else (redirects, 5xx, etc.) is genuinely
# ambiguous and left as NULL/unknown rather than guessed - this mirrors
# the same "don't manufacture a signal you don't actually have" discipline
# used in gate.py.
def _infer_requires_auth(status_code: int | None) -> bool | None:
    if status_code in (401, 403):
        return True
    if status_code == 200:
        return False
    return None


async def _save_surface_endpoints_pooled(
    pool: asyncpg.Pool,
    target_id: int,
    endpoints: list[dict],
) -> None:
    """
    Upserts a batch of observed endpoints into the persistent attack
    surface model. Each dict: {url, source, is_live, status_code,
    tech_stack}. On conflict (same target_id+url seen in an earlier
    scan), merges rather than overwrites: tech_stack and sources are
    unioned, times_seen increments, requires_auth only gets set if we
    don't already have a confident answer from a prior scan (so one
    ambiguous probe doesn't erase a previously-confirmed 401).

    Short-acquire pattern (acquire only for this one batch write, same
    as _save_recon_cache_pooled/_save_detective_finding_pooled above) -
    this is called after all the outbound HTTP probing for the phase is
    already done, never interleaved with it.
    """
    if not endpoints:
        return
    async with pool.acquire() as conn:
        for ep in endpoints:
            status_code = ep.get("status_code")
            inferred_auth = _infer_requires_auth(status_code)
            auth_evidence = f"inferred from status_code={status_code}" if inferred_auth is not None else None
            await conn.execute(
                """
                INSERT INTO attack_surface_endpoints
                    (target_id, url, is_live, last_status_code, tech_stack, sources, requires_auth, auth_evidence)
                VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
                ON CONFLICT (target_id, md5(url)) DO UPDATE SET
                    times_seen = attack_surface_endpoints.times_seen + 1,
                    last_seen_at = now(),
                    last_status_code = EXCLUDED.last_status_code,
                    is_live = COALESCE(EXCLUDED.is_live, attack_surface_endpoints.is_live),
                    tech_stack = COALESCE(
                        (
                            SELECT jsonb_agg(DISTINCT t)
                            FROM jsonb_array_elements_text(
                                attack_surface_endpoints.tech_stack || EXCLUDED.tech_stack
                            ) AS t
                        ),
                        '[]'::jsonb
                    ),
                    sources = COALESCE(
                        (
                            SELECT jsonb_agg(DISTINCT s)
                            FROM jsonb_array_elements_text(
                                attack_surface_endpoints.sources || EXCLUDED.sources
                            ) AS s
                        ),
                        '[]'::jsonb
                    ),
                    requires_auth = COALESCE(attack_surface_endpoints.requires_auth, EXCLUDED.requires_auth),
                    auth_evidence = COALESCE(attack_surface_endpoints.auth_evidence, EXCLUDED.auth_evidence)
                """,
                target_id,
                ep["url"],
                ep.get("is_live"),
                status_code,
                json.dumps(ep.get("tech_stack") or []),
                json.dumps([ep["source"]] if ep.get("source") else []),
                inferred_auth,
                auth_evidence,
            )


_ARJUN_PARAMS_RE = re.compile(r"parameters?\s+found:\s*(.+)", re.IGNORECASE)


def _parse_arjun_params(stdout: str) -> list[str]:
    """
    Best-effort parse of arjun's human-readable stdout (it doesn't run
    with a JSON output flag here). If the expected "parameters found:"
    line isn't there - format changed, or arjun printed something else -
    this just returns [] rather than raising; the caller still records
    that arjun ran and found *something* via params_found[host]=True
    regardless of whether we could parse the actual names out of it.
    """
    match = _ARJUN_PARAMS_RE.search(stdout)
    if not match:
        return []
    return [p.strip() for p in match.group(1).split(",") if p.strip()]


async def _save_surface_params_pooled(pool: asyncpg.Pool, target_id: int, url: str, params: list[str]) -> None:
    if not params:
        return
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE attack_surface_endpoints
            SET params = COALESCE(
                (
                    SELECT jsonb_agg(DISTINCT p)
                    FROM jsonb_array_elements_text(COALESCE(params, '[]'::jsonb) || $2::jsonb) AS p
                ),
                '[]'::jsonb
            )
            WHERE target_id = $1 AND url = $3
            """,
            target_id, json.dumps(params), url,
        )


async def _save_detective_finding_pooled(
    pool: asyncpg.Pool, project_id: int, target_id: int, result: dict
) -> None:
    async with pool.acquire() as conn:
        await _save_detective_finding(conn, project_id, target_id, result)


async def _save_nuclei_findings(
    conn: asyncpg.Connection, project_id: int, target_id: int, raw_output: str
) -> None:
    """
    Splits nuclei's bundled multi-line output into individual findings,
    one per template match, instead of one blended finding for everything
    nuclei found. This matters because nuclei already tells us the real
    severity per line (e.g. "[CVE-2023-48795] ... [medium] ...") - bundling
    27 results of mixed severity into one finding meant AI triage had to
    guess at one verdict for a mix of info-level noise and a real CVE,
    which is exactly the inconsistency we saw in real testing (the same
    bundle got triaged as medium one time, high another). Splitting lets
    each line get scored on its own merits.

    Falls back to saving the whole block as one finding if a line doesn't
    match nuclei's expected bracket format - never silently drops output
    just because it didn't parse as expected.
    """
    strict_mode = os.environ.get("FP_FILTER_STRICT_MODE", "").lower() in ("1", "true", "yes")
    cleaned_output, removed = fp_filter.filter_noise("nuclei", raw_output, strict_mode=strict_mode)
    if removed:
        logger.info("fp_filter: dropped %d noisy line(s) from nuclei output", removed)

    unparsed_lines = []
    saved_count = 0

    for line in cleaned_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # nuclei -silent format: [template-id:tag] [protocol] [severity] target [extras]
        # The severity is always the SECOND bracketed group after the
        # template id and protocol.
        brackets = re.findall(r"\[([^\]]*)\]", line)
        severity = None
        if len(brackets) >= 3 and brackets[2].lower() in _NUCLEI_SEVERITY_TAGS:
            severity = brackets[2].lower()

        vuln_type = brackets[0].split(":")[0] if brackets else "nuclei"

        if severity is None:
            unparsed_lines.append(line)
            continue

        finding_id, is_new = await finding_dedup.upsert_finding(
            conn, project_id, target_id, 'nuclei', vuln_type, severity, line[:1000],
        )
        if is_new:
            await _upsert_finding_cluster(conn, target_id, finding_id, 'nuclei')
        saved_count += 1

    if unparsed_lines:
        # Anything that didn't match the expected format still gets
        # saved, just bundled and left as 'unknown' for triage to handle
        # - we never want a parsing miss to mean lost data.
        await _save_finding(conn, project_id, target_id, "nuclei", "\n".join(unparsed_lines))

    logger.info("nuclei: saved %d individual findings, %d unparsed line(s) bundled separately",
                saved_count, len(unparsed_lines))


async def _upsert_finding_cluster(
    conn: asyncpg.Connection, target_id: int, finding_id: int, source: str
) -> None:
    """
    Links a newly-saved finding into its target's cluster row, creating
    the cluster row on first insert for that target. This is what
    populates finding_clusters / finding_cluster_members so the
    correlation layer (high_potential_clusters view) actually has data
    instead of sitting empty.
    """
    cluster_id = await conn.fetchval(
        """
        INSERT INTO finding_clusters (target_id)
        VALUES ($1)
        ON CONFLICT (target_id) DO UPDATE SET updated_at = now()
        RETURNING id
        """,
        target_id,
    )
    inserted_id = await conn.fetchval(
        """
        INSERT INTO finding_cluster_members (cluster_id, finding_id, source)
        VALUES ($1, $2, $3)
        ON CONFLICT (cluster_id, finding_id) DO NOTHING
        RETURNING finding_id
        """,
        cluster_id, finding_id, source,
    )
    if inserted_id is not None:
        # Only reset on an actual new member (not a no-op re-insert of the
        # same finding). Without this, a cluster that was hunted once on
        # scan #1 with a single boring finding never gets re-examined even
        # after scan #3 adds three more suspicious findings to the same
        # target - logic_hunter_status='done' is permanent otherwise.
        await conn.execute(
            """
            UPDATE finding_clusters
            SET logic_hunter_status = 'pending', updated_at = now()
            WHERE id = $1 AND logic_hunter_status = 'done'
            """,
            cluster_id,
        )


async def _save_finding(
    conn: asyncpg.Connection, project_id: int, target_id: int, tool_name: str, raw_output: str
) -> None:
    """
    Writes a candidate finding to the database. Phase 1 keeps severity
    as 'unknown' and vuln_type as the tool name - the AI-assisted
    triage that assigns real severity/VRT categories comes in a later
    phase. This just makes sure no tool output is silently lost.

    Known-noisy lines (per fp_filter.py) are stripped before storage -
    zero-cost, no AI call, based on well-documented FP patterns. If
    filtering removes EVERYTHING, we skip saving a finding at all rather
    than storing an empty/useless row.
    """
    strict_mode = os.environ.get("FP_FILTER_STRICT_MODE", "").lower() in ("1", "true", "yes")
    cleaned_output, removed = fp_filter.filter_noise(tool_name, raw_output, strict_mode=strict_mode)
    if removed:
        logger.info("fp_filter: dropped %d noisy line(s) from %s output", removed, tool_name)

    if not cleaned_output.strip():
        logger.info("fp_filter: all %s output was noise, skipping finding", tool_name)
        return

    finding_id, is_new = await finding_dedup.upsert_finding(
        conn, project_id, target_id, tool_name,
        tool_name,  # Phase 1: vuln_type defaults to the tool name until triage exists
        'unknown',
        cleaned_output[:5000],  # cap stored evidence length
    )
    if not is_new:
        return
    await _upsert_finding_cluster(conn, target_id, finding_id, tool_name)

    # Batch 24: archive the FULL evidence to disk if it was truncated
    # above, and record where - see evidence_lifecycle.py's own
    # docstring on why raw_output_path existed but was never written
    # before this.
    archive_path = evidence_lifecycle.archive_evidence_to_disk(finding_id, cleaned_output)
    if archive_path is not None:
        await conn.execute("UPDATE findings SET raw_output_path = $1 WHERE id = $2", archive_path, finding_id)


async def _save_scan_note(
    conn: asyncpg.Connection, project_id: int, target_id: int, check_name: str, note: str
) -> None:
    """
    Persists a detective.py signal that was deliberately NOT auto-filed
    as a finding (see each check's own docstring, and add_scan_notes.sql
    for the full reasoning) - candidates for manual review, or confirmed
    gaps that are almost always Informative alone.

    This replaces what used to be a bare logger.info() call: computed,
    correctly classified as "worth a human look, not a formal finding,"
    then thrown away into a Docker log nobody reads. Same classification,
    same restraint about not treating it as a graded finding - just
    actually visible now (GET /api/projects/{id}/notes) instead of gone.
    """
    await conn.execute(
        """
        INSERT INTO scan_notes (project_id, target_id, check_name, note)
        VALUES ($1, $2, $3, $4)
        """,
        project_id, target_id, check_name, note[:2000],
    )


async def _save_detective_finding(
    conn: asyncpg.Connection, project_id: int, target_id: int, result: dict
) -> None:
    """
    Saves a finding produced by detective.py's checks (subdomain takeover,
    CORS misconfig, cache deception, entropy, and 100+ others).

    IMPORTANT - this used to trust each check's own self-declared
    severity as final and skip triage entirely ("each detective check
    already did its own confirmation logic ... nothing left to filter
    or triage"). That was the actual reason detective.py findings were
    noisy: a check's own confirmation logic can still be a single-signal
    heuristic, and a self-graded "critical" never got a second,
    independent look the way every other tool's findings do.

    Now these are stored the same way tool/nuclei findings are:
    severity='unknown', so the automatic post-scan "triage" phase (and
    the on-demand /triage-all endpoint) picks them up and runs them
    through triage.triage_finding() - independent AI review, VRT
    mapping, and the policy-exclusion guidance baked into triage.py's
    prompt. The check's own severity verdict isn't thrown away, just
    demoted from "final answer" to "input": it's embedded at the front
    of the evidence text and triage.py strips it back out to feed the
    model as context (see triage._extract_self_declared_severity).
    """
    self_declared_prefix = f"[self-declared-severity: {result['severity']}]\n"
    full_evidence = self_declared_prefix + result["evidence"]
    finding_id, is_new = await finding_dedup.upsert_finding(
        conn, project_id, target_id, 'detective',
        result["vuln_type"], 'unknown', full_evidence[:5000],
    )
    if not is_new:
        return
    await _upsert_finding_cluster(conn, target_id, finding_id, 'detective')

    # Batch 24: same archival as _save_finding above.
    archive_path = evidence_lifecycle.archive_evidence_to_disk(finding_id, full_evidence)
    if archive_path is not None:
        await conn.execute("UPDATE findings SET raw_output_path = $1 WHERE id = $2", archive_path, finding_id)

    logger.info(
        "detective: saved %s finding (self-declared severity=%s, pending triage) for target_id=%s",
        result["vuln_type"], result["severity"], target_id,
    )


