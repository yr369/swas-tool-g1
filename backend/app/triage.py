"""
triage.py - assigns real severity to findings using a tiered AI approach.

Plain-language: Phase 1 stored every finding with severity='unknown'.
This module asks Gemini "how severe is this, really?" - but uses a cheap,
fast model (gemini-2.5-flash) for the routine cases, and only spends more
on a stronger model when the cheap model itself signals low confidence.
Most findings are routine (a missing security header is always 'info';
an exposed admin panel is usually 'high') - escalation is the exception,
not the rule, which keeps cost and time down without sacrificing
accuracy on the genuinely ambiguous cases.
"""

import json
import logging
import os
import re

from google import genai

from .gemini_rotation import generate_with_rotation

logger = logging.getLogger("swas.triage")

_CHEAP_MODEL = "gemini-2.5-flash"
_ESCALATION_MODEL = "gemini-2.5-pro"

_TRIAGE_PROMPT = """You are triaging a security finding from an automated \
bug bounty scan. Assign a severity and a confidence score.

Tool: {tool_name}
{self_declared_context}Evidence (raw tool output, may contain multiple lines):
---
{evidence}
---
{outcome_context}{vrt_context}
Respond with ONLY a JSON object, no other text, no markdown fences:
{{"severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "one sentence explaining the evidence AND, if the category is commonly restricted by bounty policy, saying so explicitly", "likely_program_outcome": "accepted|informative|out_of_scope|duplicate", "vrt_category": "closest matching VRT category name or null"}}

Guidance: missing security headers, generic fingerprinting (server/version
detection), and DNS records are almost always "info". Known CVEs with
confirmed version matches are at least "medium", often "high". Anything
suggesting actual exploitability (working SQLi, XSS execution, auth
bypass) is "high" or "critical". If you are NOT confident in this
classification (the evidence is ambiguous, contradictory, or you're
guessing), set confidence below 0.6 - this is expected and fine, it
routes the finding to a closer look rather than forcing a bad guess.

SSL/TLS/certificate findings (weak ciphers, self-signed or expired
certs, missing HSTS/CSP, protocol version warnings, and similar scanner
output) are ALWAYS "info", high confidence (0.9+), and should NOT be
escalated - mature programs consistently close these as Informational
or Not Applicable unless paired with a demonstrated exploit. Treat the
certificate/TLS data as reconnaissance (it can reveal org names,
internal hostnames, or infrastructure) rather than as a reportable
vulnerability in its own right - say so in "reasoning" rather than
inventing a higher severity.

Policy-exclusion check - do this BEFORE assigning severity: most bug
bounty programs (Bugcrowd/HackerOne standard disclosure terms) treat
the following as near-automatic "Informative" or "Out of Scope" UNLESS
the evidence shows a concrete chained impact beyond the bare technique
itself: denial-of-service / resource exhaustion / rate-limit-only
findings, unauthenticated cache purge or cache-busting without
demonstrated cache POISONING (poisoning another user's response is
reportable; purging alone usually is not), self-XSS or XSS requiring
the victim to paste something into their own console, clickjacking on
a page with no sensitive state-changing action, missing rate limiting
alone, open redirect with no further chained impact, verbose error
messages/stack traces with no sensitive data, best-practice
recommendations, and social-engineering-required scenarios. If the
evidence matches one of these, set severity "info", confidence 0.85+,
and say plainly in "reasoning" which excluded category it falls under
and what additional evidence (if any) would change that. Do not let a
technically-correct proof-of-concept override this - "it works" and
"a program will pay for it" are different questions, and this field is
answering the second one.

If the evidence mentions or the target hostname suggests Adobe
Experience Manager (AEM), note in "reasoning" that this is worth manual
follow-up on AEM-specific attack surface (dispatcher config exposure,
default admin interfaces like /crx/de, SSRF via AEM), not just the raw
scanner line - but still classify the raw scanner output itself by its
own actual severity, don't inflate it just because AEM was mentioned.
"""


def build_signature(tool_name: str, vuln_type: str, target_type: str = "website") -> str:
    """
    Builds the stable pattern key used to look up past outcomes - e.g.
    "nuclei:CVE-2023-48795:website". Keeping this in one function means
    triage and outcome-logging always agree on the same format.
    """
    return f"{tool_name}:{vuln_type}:{target_type}"


def _format_outcome_context(stats: dict | None) -> str:
    """
    Turns aggregated past-outcome stats into a short block injected into
    the prompt. Returns "" (nothing added) if there's no history yet -
    this is the realistic case for a brand-new signature, and the prompt
    should read naturally without it, not reference an empty history.
    """
    if not stats or stats.get("total", 0) == 0:
        return ""

    total = stats["total"]
    return (
        f"\nHistorical context: findings matching this exact pattern have been "
        f"submitted {total} time(s) before, with these outcomes: "
        f"{stats.get('accepted', 0)} accepted, {stats.get('duplicate', 0)} duplicate, "
        f"{stats.get('rejected', 0)} rejected, {stats.get('informative', 0)} informative, "
        f"{stats.get('not_applicable', 0)} not applicable. Weigh this history when judging "
        f"severity and confidence - e.g. a pattern rejected every time before should lower "
        f"your confidence in it being worth high severity, unless this specific evidence "
        f"clearly differs from past instances.\n"
    )


def _get_client() -> genai.Client:
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _parse_triage_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


def _format_self_declared_context(self_declared_severity: str | None) -> str:
    """
    detective.py checks assign their own severity based on their own
    confirmation logic at detection time. That self-assessment is
    useful signal, not ground truth - a check's own confidence in its
    match doesn't mean a program will pay for it. Feeding it in as
    context (rather than trusting it directly) lets the model sanity
    check, confirm, or downgrade it instead of it going straight into
    the findings table unexamined.
    """
    if not self_declared_severity:
        return ""
    return (
        f"The detection check itself self-assessed this as severity "
        f"\"{self_declared_severity}\" based on its own confirmation logic. "
        f"Treat that as one input, not the answer - independently verify "
        f"against the evidence and policy-exclusion guidance below, and "
        f"downgrade it if the self-assessment overstates real-world impact "
        f"or falls into a commonly-excluded category.\n"
    )


async def triage_finding(
    tool_name: str, evidence: str, outcome_stats: dict | None = None, vrt_entries: list[dict] | None = None,
    self_declared_severity: str | None = None,
) -> dict:
    """
    Returns {"severity": str, "confidence": float, "reasoning": str,
    "vrt_category": str|None, "model_used": str}. Token budget is kept
    small on purpose - evidence is capped, and we send one finding at a
    time rather than dumping unrelated context, so cost scales with
    actual findings, not with everything we happen to know.

    outcome_stats (optional): aggregated past-outcome history for this
    finding's signature, from finding_outcomes via get_signature_stats().
    When provided and non-empty, it's woven into the prompt as real
    context - this is the actual "learns from mistakes" mechanism. When
    absent (a brand-new pattern with no history), triage proceeds exactly
    as before with no behavior change.

    vrt_entries (optional): Bugcrowd's real VRT categories (from vrt.py),
    given to the model so it can name the closest matching Bugcrowd
    category - grounding our generic severity scale in Bugcrowd's actual
    scoring language, not just our own words.

    self_declared_severity (optional): the severity a detective.py check
    assigned itself at detection time. Passed through as context (see
    _format_self_declared_context) rather than trusted directly - this is
    what makes detective.py findings go through the same independent
    review as every other finding instead of skipping it.

    Tries the cheap model first. If its own reported confidence is below
    0.6, escalates ONE retry to the stronger model - this is the
    "spend more only on the hard cases" behavior, not a blanket upgrade.
    """
    client = _get_client()
    # Cap evidence length sent to the model - keeps prompts small/cheap
    # and avoids wasting tokens on truncated-anyway giant tool dumps.
    capped_evidence = evidence[:2000]
    outcome_context = _format_outcome_context(outcome_stats)
    self_declared_context = _format_self_declared_context(self_declared_severity)
    from . import vrt as vrt_module  # local import avoids a circular import at module load time
    vrt_context = vrt_module.format_vrt_context(vrt_entries or [])
    prompt = _TRIAGE_PROMPT.format(
        tool_name=tool_name, evidence=capped_evidence,
        outcome_context=outcome_context, vrt_context=vrt_context,
        self_declared_context=self_declared_context,
    )

    try:
        # generate_with_rotation tries _CHEAP_MODEL first, then rotates
        # through the rest of MODEL_ROTATION automatically if it hits a
        # 429 quota error - so a single exhausted free-tier model no
        # longer kills triage for the rest of the scan.
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_CHEAP_MODEL)
        result = _parse_triage_response(response.text or "")
        result["model_used"] = model_used
    except Exception as exc:
        logger.exception("Triage failed on every model in the rotation")
        return {"severity": "unknown", "confidence": 0.0, "reasoning": f"Triage failed: {exc}", "model_used": "none"}

    if result.get("confidence", 1.0) < 0.6:
        logger.info("Low confidence (%.2f) on %s, escalating", result.get("confidence", 0), result["model_used"])
        try:
            # Escalation also rotates, starting from the pro model, so an
            # exhausted pro quota falls back through the rest of the
            # chain rather than giving up after one try.
            response, escalation_model_used = await generate_with_rotation(
                client, prompt, preferred_model=_ESCALATION_MODEL
            )
            escalated = _parse_triage_response(response.text or "")
            escalated["model_used"] = escalation_model_used
            return escalated
        except Exception as exc:
            logger.warning("Escalation failed on every model, keeping first-pass result: %s", exc)
            # Fall back to the first-pass result rather than losing the
            # finding entirely - a low-confidence guess is still more
            # useful than nothing, and it's clearly labeled as such.
            return result

    return result


# detective.py findings get saved with severity='unknown' (same as every
# other finding) plus their own self-assessed severity embedded at the
# front of the evidence text, in this format. See pipeline.py's
# _save_detective_finding for the writer side.
_SELF_DECLARED_PREFIX_RE = re.compile(r"^\[self-declared-severity: (\w+)\]\n")


def _extract_self_declared_severity(evidence: str) -> tuple[str, str | None]:
    """
    Splits a detective.py finding's embedded self-assessment out of the
    evidence text. Returns (evidence_without_prefix, self_declared_severity
    or None). Findings from other tools never have this prefix, so this
    is a no-op for them.
    """
    match = _SELF_DECLARED_PREFIX_RE.match(evidence)
    if not match:
        return evidence, None
    return evidence[match.end():], match.group(1)


async def fetch_signature_stats(conn, signature: str) -> dict | None:
    """
    Aggregated past-outcome history for one signature. Shared by every
    caller of triage (the on-demand API endpoint and the automatic
    post-scan phase) so they look up history the exact same way.
    """
    row = await conn.fetchrow(
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted,
            COUNT(*) FILTER (WHERE outcome = 'duplicate') AS duplicate,
            COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected,
            COUNT(*) FILTER (WHERE outcome = 'informative') AS informative,
            COUNT(*) FILTER (WHERE outcome = 'not_applicable') AS not_applicable
        FROM finding_outcomes
        WHERE signature = $1
        """,
        signature,
    )
    return dict(row) if row and row["total"] else None


async def triage_project_findings(conn, project_id: int) -> int:
    """
    Triages every 'unknown'-severity finding in a project, one at a
    time, looking up past outcome history and stripping/passing through
    any self-declared severity a detective.py check embedded. Shared by
    the on-demand /triage-all endpoint AND the automatic "triage" phase
    that now runs at the end of every scan (see pipeline.py) - so
    detective.py findings get the same independent AI review tool
    findings always got, without you needing to remember to click
    anything. Returns the number of findings triaged.
    """
    from . import vrt as vrt_module

    rows = await conn.fetch(
        """
        SELECT id, tool_name, vuln_type, evidence FROM findings
        WHERE project_id = $1 AND severity = 'unknown' AND gate_status != 'failed'
        """,
        project_id,
    )

    vrt_entries = await vrt_module.get_vrt_entries()  # fetched once, reused for every finding in this batch
    triaged = 0
    for row in rows:
        signature = build_signature(row["tool_name"], row["vuln_type"])
        outcome_stats = await fetch_signature_stats(conn, signature)
        clean_evidence, self_declared_severity = _extract_self_declared_severity(row["evidence"] or "")

        result = await triage_finding(
            row["tool_name"], clean_evidence,
            outcome_stats=outcome_stats, vrt_entries=vrt_entries,
            self_declared_severity=self_declared_severity,
        )
        outcome = result.get("likely_program_outcome")
        await conn.execute(
            """
            UPDATE findings
            SET severity = $1,
                likely_program_outcome = $2,
                triage_reasoning = $3,
                triage_confidence = $4
            WHERE id = $5
            """,
            result["severity"] if result["severity"] in
            ("critical", "high", "medium", "low", "info") else "unknown",
            outcome if outcome in ("accepted", "informative", "out_of_scope", "duplicate") else None,
            result.get("reasoning"),
            result.get("confidence"),
            row["id"],
        )
        triaged += 1

    return triaged


# ---------------------------------------------------------------------
# Cluster-aware triage
# ---------------------------------------------------------------------
#
# Everything above scores ONE finding at a time - that's necessary (a
# missing header and a confirmed CVE need independent scrutiny) but it
# can't catch the case where two individually-unremarkable findings on
# the SAME target combine into something a program actually pays for
# (e.g. an information-disclosure finding that supplies exactly what a
# separate weak-auth finding needs). This section adds that second
# pass: it reads high_potential_clusters (2+ findings or 2+ distinct
# sources on one target - see correlation_schema_fix2.sql) and asks the
# model to reason about the COMBINATION, on top of - not instead of -
# each finding's own individual severity.

_CLUSTER_PROMPT = """You are looking at a CLUSTER of findings that were all detected \
on the SAME target during one scan. Each has already been independently scored; your \
job is to reason about whether chaining them together changes the real-world impact \
beyond any single finding's severity.

Target: {target_name} ({target_type})

Findings in this cluster ({count} total, {sources} distinct source(s)):
{findings_block}

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"combined_severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "one to two sentences on whether/how these chain together, or why they don't", "vrt_category": "closest matching VRT category name or null", "likely_program_outcome": "accepted|informative|out_of_scope|duplicate"}}

Guidance: most clusters do NOT chain into something bigger - two unrelated info-level \
findings on the same host are still just two info-level findings, and combined_severity \
should equal the single highest individual severity present, not be inflated just for \
existing as a cluster. Only raise combined_severity ABOVE the highest individual severity \
when there's a concrete, statable reason the combination unlocks new impact - the \
canonical example is an information-disclosure finding (leaked credential, internal \
endpoint, config detail) PLUS a weak-auth or exposed-admin-interface finding on the SAME \
target, where the disclosure supplies exactly what the weak auth needs. Apply the same \
policy-exclusion judgment individual triage uses: a chain built entirely out of commonly- \
excluded categories (DoS, self-XSS, rate-limit-only, etc.) does not become reportable \
just by being clustered together unless the chain itself demonstrates new, concrete impact.
"""


async def triage_cluster(target_name: str, target_type: str | None, members: list[dict]) -> dict:
    """
    members: rows with tool_name, vuln_type, severity, evidence, source.
    Returns the same shape as triage_finding, plus reuses the escalation
    model directly (this only runs on the small set of high-potential
    clusters, not every finding, so the cost tradeoff that justifies the
    cheap-model-first behavior above doesn't apply here).
    """
    client = _get_client()
    findings_block = "\n".join(
        f"- [{m['severity']}] {m['tool_name']}/{m['vuln_type']} (source={m['source']}): "
        f"{(m['evidence'] or '')[:300]}"
        for m in members
    )
    sources = len({m["source"] for m in members})
    prompt = _CLUSTER_PROMPT.format(
        target_name=target_name, target_type=target_type or "website",
        count=len(members), sources=sources, findings_block=findings_block,
    )

    try:
        response, model_used = await generate_with_rotation(client, prompt, preferred_model=_ESCALATION_MODEL)
        result = _parse_triage_response(response.text or "")
        result["model_used"] = model_used
        return result
    except Exception as exc:
        logger.exception("Cluster triage failed for %s", target_name)
        return {"combined_severity": None, "confidence": 0.0,
                "reasoning": f"Cluster triage failed: {exc}", "model_used": "none"}


async def triage_project_clusters(conn, project_id: int) -> int:
    """
    Scores every high-potential cluster in a project that hasn't been
    cluster-triaged yet (finding_clusters.triage_status = 'pending').
    Skips a cluster if its members haven't been individually triaged
    yet (still 'unknown') - cluster reasoning is more meaningful once
    each finding has its own real severity to reason on top of, and
    this is idempotent to re-run so it just picks the cluster up on a
    later pass once triage_project_findings has scored its members.
    Returns the number of clusters scored.
    """
    rows = await conn.fetch(
        """
        SELECT hpc.cluster_id, hpc.target_id, hpc.target_name, hpc.target_type
        FROM high_potential_clusters hpc
        JOIN finding_clusters fc ON fc.id = hpc.cluster_id
        WHERE fc.target_id IN (SELECT id FROM scope_targets WHERE project_id = $1)
          AND fc.triage_status = 'pending'
        """,
        project_id,
    )

    scored = 0
    for row in rows:
        members = await conn.fetch(
            """
            SELECT f.tool_name, f.vuln_type, f.severity, f.evidence, fcm.source
            FROM finding_cluster_members fcm
            JOIN findings f ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = $1 AND f.severity != 'unknown'
            """,
            row["cluster_id"],
        )
        if not members:
            continue  # members not individually triaged yet - pick this cluster up next run

        result = await triage_cluster(row["target_name"], row["target_type"], [dict(m) for m in members])
        if result.get("combined_severity") in ("critical", "high", "medium", "low", "info"):
            await conn.execute(
                """
                UPDATE finding_clusters
                SET severity = $1, vrt_category = $2, llm_backend_used = $3,
                    triage_status = 'scored', updated_at = now()
                WHERE id = $4
                """,
                result["combined_severity"], result.get("vrt_category"), result.get("model_used"),
                row["cluster_id"],
            )
            scored += 1
        else:
            logger.warning("Cluster %s triage returned no usable severity, leaving pending", row["cluster_id"])

    return scored
