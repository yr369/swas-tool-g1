"""
pipeline/phase_post.py - the five short post-scan phases (verify,
gate, logic_hunter, triage, notify), each just a thin wrapper calling
into its own module (verify.py, gate.py, logic_hunter.py, triage.py,
notify path) for a single project. Split out of the former
monolithic pipeline.py; kept together since none is more than ~40
lines and none references phase_scan/recon/probe/fuzz internals.
"""

import asyncio
import json
import logging
import os
import re

import asyncpg

from .. import auth_policy, auth_sessions, checkpoint, detective, evidence_lifecycle, finding_dedup, fp_filter, gate, git_dumper, logic_hunter, oob, screenshots, target_intelligence, tools, triage, verify

from .shared import logger


async def _phase_verify(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs verify.py's active-confirmation pass on every finding still
    pending verification for this project, right after scan and before
    gate - deliberately before gate/triage so a finding that gets
    upgraded to 'confirmed' here (OOB-proven SSRF, cache-poisoning-
    capable host-header injection, browser-executed XSS) carries that
    proof into the cheaper/more-expensive review stages downstream,
    instead of being judged on the raw unverified signal alone. Not
    every finding has a verification technique yet (see verify.py's
    dispatch table) - those are simply left at verification_status
    'pending', which is honest: "not yet checked," not "checked and
    failed."
    """
    verified = await verify.verify_project_findings(conn, project_id)
    logger.info("verify: actively re-confirmed %s finding(s) for project_id=%s", verified, project_id)


async def _phase_gate(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs the cheap 7-Question Gate (see gate.py) on every 'unknown'-
    severity finding in this project, right after scan and before the
    more expensive logic_hunter/triage phases. Findings that fail the
    gate are never deleted - they stay in the table with
    gate_status='failed' for visibility - but triage.py skips them, so
    a scan full of scanner noise doesn't burn a full triage call per
    line. Checkpointed/retried like every other phase; a gate failure
    itself fails open per-finding (see gate.run_gate), so this can only
    ever cost extra triage calls, never silently drop a real finding.
    """
    gated = await gate.gate_project_findings(conn, project_id)
    logger.info("gate: reviewed %s finding(s) for project_id=%s", gated, project_id)


async def _phase_logic_hunter(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs logic_hunter.py's LLM business-logic/auth-bypass reasoning
    over this project's high-potential clusters (see
    high_potential_clusters) - the targets where correlation already
    found 2+ findings or 2+ distinct sources, which is where a chained
    logic bug is actually likely to be findable from existing evidence.
    Runs after gate (so it's reasoning over signal, not raw noise) and
    before triage (so any hypothesis it saves gets the same independent
    triage review every other finding gets). Idempotent to re-run: each
    cluster is only hunted once (finding_clusters.logic_hunter_status),
    so this never double-spends the expensive reasoning call.
    """
    hunted = await logic_hunter.hunt_project(conn, project_id)
    logger.info("logic_hunter: saved %s hypothesis/hypotheses for project_id=%s", hunted, project_id)


async def _phase_triage(conn: asyncpg.Connection, project_id: int) -> None:
    """
    Runs AI triage on every 'unknown'-severity finding in this project -
    this now includes detective.py findings (see _save_detective_finding),
    which used to skip triage entirely. Kept as its own phase, after
    scan and before notify, so:

    - it's checkpointed/retried the same as every other phase (a triage
      failure doesn't silently lose findings, it retries once then
      marks needs_attention like anything else)
    - it runs automatically at the end of every scan, so findings get
      an independent AI look without you needing to remember to call
      /triage-all yourself
    - it's idempotent to re-run: it only ever processes rows still
      marked 'unknown', so if multiple targets in the same project
      finish around the same time this just triages whatever's new
      each time, nothing gets triaged twice

    Failures inside triage_finding() itself are already caught per-
    finding (falls back to severity='unknown' with a logged reason,
    see triage.py) so one bad finding can't take down the whole batch.

    After individual findings are scored, also runs cluster-aware
    triage (triage.triage_project_clusters) - this is the second pass
    that reasons about the COMBINATION of findings per target (e.g.
    info disclosure + weak auth = higher severity than either alone),
    reading from high_potential_clusters. It runs second on purpose:
    cluster reasoning is more meaningful once each member finding
    already has a real severity to reason on top of, rather than a
    placeholder 'unknown'.
    """
    triaged = await triage.triage_project_findings(conn, project_id)
    clustered = await triage.triage_project_clusters(conn, project_id)
    logger.info(
        "triage: reviewed %s finding(s), scored %s cluster(s) for project_id=%s",
        triaged, clustered, project_id,
    )


async def _phase_notify(pool: asyncpg.Pool, project_id: int, target: str) -> None:
    """
    Best-effort notification. A failure here should not be treated as a
    pipeline failure - it's a courtesy, not a critical step.

    Human-in-the-loop checkpoint (#13): before (or regardless of) the
    generic "scan completed" message, checks for any high-value finding
    in this PROJECT (severity critical/high, triage says likely
    accepted) that hasn't been alerted on yet, and sends one immediate,
    specific notification per finding. This runs at the project level,
    not just this target, because notify is the last phase per-target
    but findings from a sibling target in the same project may have
    finished triage moments earlier - checking the whole project each
    time a target reaches notify means nothing waits longer than one
    target's worth of phases to get flagged. mark_alerted ensures the
    same finding is never announced twice across multiple targets'
    notify phases landing close together.

    Phase 1 has no notification destination configured yet (no Slack/
    Discord webhook, etc.) - rather than calling the notify tool and
    logging a confusing-looking error every single scan, we skip it
    cleanly and say so. Once a real destination is set up (a later,
    deliberate decision - see NOTIFY_WEBHOOK_URL in .env), this will
    start actually sending alerts.
    """
    if not os.environ.get("NOTIFY_WEBHOOK_URL"):
        logger.info("notify: skipped (no notification destination configured yet)")
        return

    async with pool.acquire() as conn:
        high_value = await target_intelligence.get_unalerted_high_value_findings(conn, project_id)
        # Batch 24: alert fatigue guard. Groups findings sharing the
        # same (tool_name, vuln_type) signature into one alert instead
        # of firing one notify() call per finding - see
        # evidence_lifecycle.group_and_throttle_alerts's own docstring
        # for why an unthrottled 40-finding burst was the actual gap.
        alerts = evidence_lifecycle.group_and_throttle_alerts(high_value)
        for alert in alerts:
            alert_result = await tools.run_notify(alert["message"])
            if not alert_result.success:
                logger.info(
                    "notify: high-value alert failed for finding_ids=%s: %s",
                    alert["finding_ids"], alert_result.error,
                )
        if high_value:
            await target_intelligence.mark_alerted(conn, [f["id"] for f in high_value])
            logger.info(
                "notify: sent %d grouped alert(s) covering %d high-value finding(s) for project_id=%s",
                len(alerts), len(high_value), project_id,
            )

    result = await tools.run_notify(f"Scan completed for {target}")
    if not result.success:
        logger.info("notify phase had a non-fatal issue: %s", result.error)
