"""
Manual verification for the impact_evidence severity cap (triage.py) -
against a REAL local Postgres, real asyncpg, per project testing
standard. The only thing swapped out is the outbound Gemini call
(triage.generate_with_rotation), same pattern as
test_retry_queue_manual.py.

Setup:
    export PGPASSWORD=testpass GEMINI_API_KEY=test-key-not-used
    psql -h localhost -U swas_test -d swas_test_db -f backend/db/migrations/012_impact_evidence.sql
    (+ full schema replay - see test_error_taxonomy_manual.py's docstring)

Run:
    cd backend && python3 -m app.test_impact_evidence_manual
"""
import asyncio
import os
import sys

import asyncpg

os.environ.setdefault("GEMINI_API_KEY", "test-key-not-used")

from . import triage  # noqa: E402

DB_DSN = os.environ.get(
    "TEST_DB_DSN", "postgresql://swas_test:testpass@localhost/swas_test_db"
)


def test_weak_impact_evidence_detection():
    cases = [
        (None, True),
        ("", True),
        ("   ", True),
        ("none", True),
        ("N/A", True),
        ("Not demonstrated.", True),
        ("short", True),  # under _MIN_IMPACT_EVIDENCE_LENGTH
        ("Extracted row: user_id=4821, email=admin@target.com, role=superadmin", False),
        ("Response body contained victim's session cookie value after XSS payload fired", False),
    ]
    for value, expected_weak in cases:
        actual = triage._impact_evidence_is_weak(value)
        assert actual == expected_weak, f"{value!r} -> got weak={actual}, expected {expected_weak}"
        print(f"PASS: impact_evidence={value!r} -> weak={actual}")


def test_cap_applies_only_to_critical_high_with_weak_evidence():
    # critical + weak -> capped to medium, reasoning prefixed
    result = {"severity": "critical", "impact_evidence": "", "reasoning": "SQLi confirmed via error-based technique"}
    capped = triage._apply_impact_evidence_cap(dict(result))
    assert capped["severity"] == "medium", capped
    assert "capped from critical to medium" in capped["reasoning"], capped
    print("PASS: critical + weak impact_evidence -> capped to medium")

    # high + strong evidence -> NOT capped
    result2 = {
        "severity": "high",
        "impact_evidence": "Read /etc/passwd contents showing root and 3 other system user entries",
        "reasoning": "LFI confirmed",
    }
    capped2 = triage._apply_impact_evidence_cap(dict(result2))
    assert capped2["severity"] == "high", capped2
    assert capped2["reasoning"] == "LFI confirmed", capped2
    print("PASS: high + strong impact_evidence -> NOT capped, reasoning untouched")

    # medium + weak evidence -> NOT capped (medium doesn't depend on impact_evidence)
    result3 = {"severity": "medium", "impact_evidence": "", "reasoning": "Confirmed CVE version match"}
    capped3 = triage._apply_impact_evidence_cap(dict(result3))
    assert capped3["severity"] == "medium", capped3
    print("PASS: medium + weak impact_evidence -> left alone (medium doesn't require impact_evidence)")

    # info + weak evidence -> NOT capped
    result4 = {"severity": "info", "impact_evidence": None, "reasoning": "Missing security header"}
    capped4 = triage._apply_impact_evidence_cap(dict(result4))
    assert capped4["severity"] == "info", capped4
    print("PASS: info + weak impact_evidence -> left alone")


async def _fake_generate_weak_critical(client, prompt, preferred_model=None):
    class _R:
        text = (
            '{"severity": "critical", "confidence": 0.95, "reasoning": "SQLi confirmed", '
            '"likely_program_outcome": "accepted", "impact_evidence": ""}'
        )
    return _R(), "gemini-2.5-flash"


async def _fake_generate_strong_high(client, prompt, preferred_model=None):
    class _R:
        text = (
            '{"severity": "high", "confidence": 0.9, "reasoning": "IDOR confirmed", '
            '"likely_program_outcome": "accepted", '
            '"impact_evidence": "Response for user_id=1002 (not the authenticated user) showed '
            'their full name, email, and phone number"}'
        )
    return _R(), "gemini-2.5-flash"


async def _e2e():
    pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=1, max_size=3)
    original = triage.generate_with_rotation
    try:
        async with pool.acquire() as conn:
            project_id = await conn.fetchval(
                "INSERT INTO projects (name, platform) VALUES ($1, $2) RETURNING id",
                "impact-evidence-test-project", "hackerone",
            )
            target_id = await conn.fetchval(
                "INSERT INTO scope_targets (project_id, target) VALUES ($1, $2) RETURNING id",
                project_id, "impact-test.example.com",
            )

        try:
            # Round 1: only the weak-evidence finding exists yet, so
            # triage_project_findings (which sweeps ALL unknown findings
            # in the project) can't accidentally also triage round 2's
            # finding with round 1's fake response.
            async with pool.acquire() as conn:
                weak_finding_id = await conn.fetchval(
                    """
                    INSERT INTO findings (project_id, target_id, tool_name, vuln_type, evidence)
                    VALUES ($1, $2, 'sqlmap', 'sqli-error-based', 'boolean differential observed') RETURNING id
                    """,
                    project_id, target_id,
                )
            triage.generate_with_rotation = _fake_generate_weak_critical
            async with pool.acquire() as conn:
                await triage.triage_project_findings(conn, project_id)
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT severity, impact_evidence, triage_reasoning FROM findings WHERE id = $1", weak_finding_id
                )
            assert row["severity"] == "medium", row  # capped down from critical
            assert row["impact_evidence"] is None, row  # empty string stored as NULL
            assert "capped from critical to medium" in row["triage_reasoning"], row
            print(f"PASS: weak-impact critical finding stored as severity={row['severity']!r}, capping noted in reasoning")

            # Round 2: weak_finding is no longer 'unknown' (just resolved
            # above), so this sweep only picks up the new finding.
            async with pool.acquire() as conn:
                strong_finding_id = await conn.fetchval(
                    """
                    INSERT INTO findings (project_id, target_id, tool_name, vuln_type, evidence)
                    VALUES ($1, $2, 'custom-idor-check', 'idor', 'sequential id enumeration test') RETURNING id
                    """,
                    project_id, target_id,
                )
            triage.generate_with_rotation = _fake_generate_strong_high
            async with pool.acquire() as conn:
                await triage.triage_project_findings(conn, project_id)
            async with pool.acquire() as conn:
                row2 = await conn.fetchrow(
                    "SELECT severity, impact_evidence FROM findings WHERE id = $1", strong_finding_id
                )
            assert row2["severity"] == "high", row2  # NOT capped
            assert row2["impact_evidence"] and "phone number" in row2["impact_evidence"], row2
            print(f"PASS: strong-impact high finding stays severity={row2['severity']!r}, impact_evidence persisted")

        finally:
            async with pool.acquire() as conn:
                await conn.execute("DELETE FROM projects WHERE id = $1", project_id)

    finally:
        triage.generate_with_rotation = original
        await pool.close()


def test_e2e_real_db():
    asyncio.run(_e2e())


if __name__ == "__main__":
    tests = [
        test_weak_impact_evidence_detection,
        test_cap_applies_only_to_critical_high_with_weak_evidence,
        test_e2e_real_db,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {t.__name__} - {e}")
    if failed:
        print(f"\n{failed}/{len(tests)} test(s) FAILED")
        sys.exit(1)
    print(f"\nAll {len(tests)} test(s) passed")
