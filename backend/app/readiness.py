"""
readiness.py - automated checks before a finding is marked ready to submit.

Plain-language: this catches the boring mistakes that get reports bounced
regardless of how real the bug is - missing reproduction steps, stale
scope, severity never triaged, evidence too thin to act on. It's not a
replacement for your judgment - it's a pre-flight check that flags
obvious gaps so you don't submit something half-finished.
"""

from dataclasses import dataclass, field


@dataclass
class ReadinessCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class ReadinessResult:
    ready: bool
    checks: list[ReadinessCheck] = field(default_factory=list)


def check_finding_readiness(finding: dict, target_in_scope: bool) -> ReadinessResult:
    """
    Runs a fixed set of checks against a finding before it's submitted.
    All checks must pass for ready=True - any single failure blocks
    submission-readiness, since a report missing even one of these is a
    common, avoidable rejection reason.
    """
    checks = []

    # 1. Severity has actually been triaged - 'unknown' means nobody
    # (human or AI) has looked at this yet.
    has_severity = finding.get("severity") not in (None, "unknown")
    checks.append(ReadinessCheck(
        name="severity_triaged",
        passed=has_severity,
        detail="Severity assigned" if has_severity else "Run triage before submitting - severity is still 'unknown'",
    ))

    # 2. Evidence exists and isn't trivially short - an empty or
    # one-line evidence field usually means there's nothing concrete to
    # show a triager, regardless of how the tool flagged it.
    evidence = finding.get("evidence") or ""
    has_evidence = len(evidence.strip()) >= 20
    checks.append(ReadinessCheck(
        name="has_evidence",
        passed=has_evidence,
        detail="Evidence present" if has_evidence else "Evidence is empty or too thin to be useful in a report",
    ))

    # 3. Target is still actually in scope - scope can change mid-
    # engagement (programs update their brief), so this is checked at
    # submission time, not just at intake.
    checks.append(ReadinessCheck(
        name="still_in_scope",
        passed=target_in_scope,
        detail="Target is in scope" if target_in_scope else "Target is no longer marked in-scope - re-check the program's current scope before submitting",
    ))

    # 4. Not already marked dismissed or already submitted - catches
    # accidental duplicate submission attempts.
    status = finding.get("status", "new")
    not_already_handled = status not in ("submitted", "dismissed")
    checks.append(ReadinessCheck(
        name="not_already_handled",
        passed=not_already_handled,
        detail="Not yet submitted/dismissed" if not_already_handled else f"This finding is already marked '{status}'",
    ))

    # 5. Severity isn't 'info' - info-level findings (missing headers,
    # fingerprinting) are almost never worth a standalone submission on
    # their own; flagging this here saves a likely-wasted report.
    not_just_info = finding.get("severity") != "info"
    checks.append(ReadinessCheck(
        name="severity_worth_reporting",
        passed=not_just_info,
        detail="Severity is above info-level" if not_just_info else "Info-level findings are rarely worth a standalone submission - consider bundling with a related finding or skipping",
    ))

    all_passed = all(c.passed for c in checks)
    return ReadinessResult(ready=all_passed, checks=checks)
