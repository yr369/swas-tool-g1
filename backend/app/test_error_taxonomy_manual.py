"""
Manual verification for error_taxonomy.py, exercised end-to-end through
checkpoint.run_phase() against a REAL local Postgres - not mocked, per
project testing standard. Confirms:
  1. classify_error() maps real exception instances to the right bucket
     (asyncpg.PostgresError, httpx errors, a real google.genai error,
     FileNotFoundError, AuthPolicyError, config.ConfigError, a real
     json.JSONDecodeError, asyncio.TimeoutError).
  2. checkpoint.run_phase's failure path actually writes error_type
     into phase_runs via asyncpg with a real typed param - catches the
     class of silent binding bug the project has hit before (an
     untyped/mistyped param passing psycopg-style checks but failing or
     silently coercing under asyncpg).
  3. The CHECK constraint added in migration 010 is live and enforced.

Setup (run once, matches the project's local-Postgres testing pattern):
    export PGPASSWORD=testpass
    psql -h localhost -U swas_test -d swas_test_db -f backend/db/init.sql
    psql -h localhost -U swas_test -d swas_test_db -f backend/db/migrations/010_error_taxonomy.sql
    (+ any other prior migrations needed for phase_runs' full shape)

Run:
    cd backend && python3 -m app.test_error_taxonomy_manual
"""
import asyncio
import json
import os
import sys

import asyncpg
import httpx
import requests
from google.genai import errors as genai_errors

from . import auth_policy, checkpoint, config, error_taxonomy

DB_DSN = os.environ.get(
    "TEST_DB_DSN", "postgresql://swas_test:testpass@localhost/swas_test_db"
)


def _make_genai_error(cls, code: int, status: str):
    resp = requests.Response()
    resp.status_code = code
    resp._content = json.dumps({"error": {"code": code, "status": status, "message": status}}).encode()
    return cls(code, resp)


def test_classification_with_real_exception_instances():
    cases = [
        (auth_policy.AuthPolicyError("blocked"), "auth_policy_denied"),
        (config.ConfigError("bad config"), "config_error"),
        (KeyError("GEMINI_API_KEY"), "config_error"),
        (_make_genai_error(genai_errors.ClientError, 429, "RESOURCE_EXHAUSTED"), "ai_quota_exhausted"),
        (_make_genai_error(genai_errors.ClientError, 400, "INVALID_ARGUMENT"), "ai_provider_error"),
        (asyncio.TimeoutError("timed out"), "network_timeout"),
        (ConnectionRefusedError("refused"), "network_error"),
        (FileNotFoundError("nuclei"), "tool_not_found"),
        (json.JSONDecodeError("bad json", "doc", 0), "parse_error"),
        (ValueError("could not parse response"), "parse_error"),
        (RuntimeError("something totally unclassified"), "unknown"),
    ]
    for exc, expected in cases:
        actual = error_taxonomy.classify_error(exc)
        assert actual == expected, f"{type(exc).__name__}({exc}) -> got {actual}, expected {expected}"
        print(f"PASS: {type(exc).__name__} -> {actual}")


def test_httpx_status_error_classification():
    request = httpx.Request("GET", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(500, request=request)
    exc = httpx.HTTPStatusError("server error", request=request, response=response)
    assert error_taxonomy.classify_error(exc) == "ai_provider_error"
    print("PASS: httpx.HTTPStatusError (tier-2 provider) -> ai_provider_error")

    timeout_exc = httpx.ConnectTimeout("connect timed out", request=request)
    assert error_taxonomy.classify_error(timeout_exc) == "network_timeout"
    print("PASS: httpx.ConnectTimeout -> network_timeout")


async def _e2e_writes_error_type_via_real_asyncpg():
    pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=1, max_size=2)
    try:
        async with pool.acquire() as conn:
            project_id = await conn.fetchval(
                "INSERT INTO projects (name, platform) VALUES ($1, $2) RETURNING id",
                "error-taxonomy-test-project", "hackerone",
            )
            target_id = await conn.fetchval(
                "INSERT INTO scope_targets (project_id, target) VALUES ($1, $2) RETURNING id",
                project_id, "test.example.com",
            )
            phase_run_id = await checkpoint.create_pending_run(conn, project_id, target_id, "recon")

        # Real exception, real asyncpg write path through run_phase.
        try:
            async with checkpoint.run_phase(pool, phase_run_id, project_id, target_id, "recon"):
                raise FileNotFoundError("nuclei: command not found")
        except FileNotFoundError:
            pass  # run_phase re-raises by design; expected here

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status, error_type, error_message FROM phase_runs WHERE id = $1",
                phase_run_id,
            )
        assert row["status"] == "failed", row
        assert row["error_type"] == "tool_not_found", row
        assert "nuclei" in row["error_message"], row
        print(f"PASS: real asyncpg write through checkpoint.run_phase -> error_type={row['error_type']!r}")

        # Confirm the CHECK constraint is actually live (not just present
        # in the .sql file but never applied) by trying an invalid value
        # directly.
        async with pool.acquire() as conn:
            try:
                await conn.execute(
                    "UPDATE phase_runs SET error_type = $2 WHERE id = $1",
                    phase_run_id, "not_a_real_category",
                )
                assert False, "expected asyncpg.CheckViolationError for invalid error_type"
            except asyncpg.CheckViolationError:
                print("PASS: CHECK constraint rejects an invalid error_type via real asyncpg")

        # Cleanup
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM projects WHERE id = $1", project_id)  # cascades

    finally:
        await pool.close()


def test_e2e_real_db_write():
    asyncio.run(_e2e_writes_error_type_via_real_asyncpg())


if __name__ == "__main__":
    tests = [
        test_classification_with_real_exception_instances,
        test_httpx_status_error_classification,
        test_e2e_real_db_write,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {t.__name__} - {e}")
        except Exception as e:
            failed += 1
            print(f"FAIL: {t.__name__} - unexpected {type(e).__name__}: {e}")
    if failed:
        print(f"\n{failed}/{len(tests)} test(s) FAILED")
        sys.exit(1)
    print(f"\nAll {len(tests)} test(s) passed")
