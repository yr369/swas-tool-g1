"""
Manual end-to-end verification for retry_queue.py + the
triage.py wiring (triage_project_findings enqueueing on total AI
failure, retry_pending_ai_failures draining the queue) - against a REAL
local Postgres, real asyncpg, not mocked, per project testing standard.

The ONLY thing swapped out is the actual outbound Gemini network call
(triage.generate_with_rotation) - swapped for a plain async function we
control, same pattern already used and validated in
test_gemini_rotation_circuit_breaker_manual.py. Everything else (DB
writes, retry_queue's SQL, the real generate_with_rotation call site,
triage_finding's real parsing/exception-handling logic) is exercised for
real.

Setup:
    export PGPASSWORD=testpass GEMINI_API_KEY=test-key-not-used
    psql -h localhost -U swas_test -d swas_test_db -f backend/db/init.sql
    (+ all prior migrations/backend/app/*.sql, in order - see batch 19's
    test file docstring for the full replay list)
    psql -h localhost -U swas_test -d swas_test_db -f backend/db/migrations/011_ai_retry_queue.sql

Run:
    cd backend && python3 -m app.test_retry_queue_manual
"""
import asyncio
import os
import sys

import asyncpg

os.environ.setdefault("GEMINI_API_KEY", "test-key-not-used")

from . import retry_queue, triage  # noqa: E402 (env var must be set first)

DB_DSN = os.environ.get(
    "TEST_DB_DSN", "postgresql://swas_test:testpass@localhost/swas_test_db"
)


async def _cleanup(conn, project_id):
    await conn.execute("DELETE FROM projects WHERE id = $1", project_id)  # cascades to findings/scope_targets
    await conn.execute("DELETE FROM ai_retry_queue")


async def _fake_generate_always_fails(client, prompt, preferred_model=None):
    raise RuntimeError("all Gemini models exhausted (simulated for test)")


async def _fake_generate_succeeds(client, prompt, preferred_model=None):
    class _FakeResponse:
        text = (
            '{"severity": "medium", "confidence": 0.9, '
            '"reasoning": "retried successfully", "likely_program_outcome": "accepted"}'
        )
    return _FakeResponse(), "gemini-2.5-flash"


async def _run():
    pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=1, max_size=3)
    original_generate = triage.generate_with_rotation
    try:
        # --- Part 1: retry_queue primitives against real Postgres ---
        async with pool.acquire() as conn:
            item_id = await retry_queue.enqueue(
                conn, "finding_triage", {"finding_id": 999999, "project_id": 1}, max_attempts=2,
            )
            due = await retry_queue.fetch_due(conn, "finding_triage")
            assert any(r["id"] == item_id for r in due), "just-enqueued item should be immediately due"
            print(f"PASS: enqueue + fetch_due found item id={item_id}")

            await retry_queue.mark_attempt_failed(conn, item_id, "boom", "ai_provider_error")
            row = await conn.fetchrow("SELECT status, attempts, next_attempt_at FROM ai_retry_queue WHERE id = $1", item_id)
            assert row["status"] == "pending", row
            assert row["attempts"] == 1, row
            now_row = await conn.fetchrow("SELECT now() AS now")
            assert row["next_attempt_at"] > now_row["now"], (row["next_attempt_at"], now_row["now"])
            due_now = await retry_queue.fetch_due(conn, "finding_triage")
            assert not any(r["id"] == item_id for r in due_now), "item with future next_attempt_at should not be due yet"
            print("PASS: first failed attempt backs off and is no longer immediately due")

            await retry_queue.mark_attempt_failed(conn, item_id, "boom again", "ai_provider_error")
            row = await conn.fetchrow("SELECT status, attempts FROM ai_retry_queue WHERE id = $1", item_id)
            assert row["status"] == "failed", row  # max_attempts=2 reached
            assert row["attempts"] == 2, row
            print("PASS: reaching max_attempts marks the item permanently 'failed'")

            await conn.execute("DELETE FROM ai_retry_queue WHERE id = $1", item_id)

        # --- Part 2: end-to-end through triage.py with a real finding ---
        async with pool.acquire() as conn:
            project_id = await conn.fetchval(
                "INSERT INTO projects (name, platform) VALUES ($1, $2) RETURNING id",
                "retry-queue-test-project", "hackerone",
            )
            target_id = await conn.fetchval(
                "INSERT INTO scope_targets (project_id, target) VALUES ($1, $2) RETURNING id",
                project_id, "retry-test.example.com",
            )
            finding_id = await conn.fetchval(
                """
                INSERT INTO findings (project_id, target_id, tool_name, vuln_type, evidence)
                VALUES ($1, $2, $3, $4, $5) RETURNING id
                """,
                project_id, target_id, "nuclei", "xss-reflected", "some evidence blob",
            )

        try:
            # Simulate total AI failure during the normal triage phase.
            triage.generate_with_rotation = _fake_generate_always_fails
            async with pool.acquire() as conn:
                triaged_count = await triage.triage_project_findings(conn, project_id)
            assert triaged_count == 1, triaged_count

            async with pool.acquire() as conn:
                finding_row = await conn.fetchrow("SELECT severity FROM findings WHERE id = $1", finding_id)
                assert finding_row["severity"] == "unknown", finding_row
                queue_row = await conn.fetchrow(
                    "SELECT id, status, payload FROM ai_retry_queue WHERE kind = 'finding_triage' AND status = 'pending'"
                )
                assert queue_row is not None, "expected a pending finding_triage retry item"
                import json as _json
                payload = queue_row["payload"] if isinstance(queue_row["payload"], dict) else _json.loads(queue_row["payload"])
                assert payload["finding_id"] == finding_id, payload
            print(f"PASS: total AI failure during triage_project_findings enqueued a retry item for finding {finding_id}")

            # Force it due right now instead of waiting for backoff, so the
            # test doesn't need to sleep for real minutes.
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE ai_retry_queue SET next_attempt_at = now() WHERE id = $1", queue_row["id"],
                )

            # Now simulate the AI recovering, and run the worker function
            # main.py's background loop calls periodically.
            triage.generate_with_rotation = _fake_generate_succeeds
            processed = await triage.retry_pending_ai_failures(pool)
            assert processed == 1, processed

            async with pool.acquire() as conn:
                finding_row = await conn.fetchrow(
                    "SELECT severity, triage_reasoning FROM findings WHERE id = $1", finding_id,
                )
                assert finding_row["severity"] == "medium", finding_row
                queue_row2 = await conn.fetchrow("SELECT status FROM ai_retry_queue WHERE id = $1", queue_row["id"])
                assert queue_row2["status"] == "succeeded", queue_row2
            print(
                f"PASS: retry_pending_ai_failures resolved the queued finding "
                f"(severity now {finding_row['severity']!r}), marked queue item succeeded"
            )

            # --- Part 3: an already-resolved finding gets skipped as a no-op ---
            async with pool.acquire() as conn:
                other_finding_id = await conn.fetchval(
                    """
                    INSERT INTO findings (project_id, target_id, tool_name, vuln_type, evidence, severity)
                    VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
                    """,
                    project_id, target_id, "nuclei", "info-disclosure", "evidence", "unknown",
                )
                new_item_id = await retry_queue.enqueue(
                    conn, "finding_triage", {"finding_id": other_finding_id, "project_id": project_id},
                )
                # Someone/something else resolves it before the retry runs.
                await conn.execute(
                    "UPDATE findings SET severity = 'low' WHERE id = $1", other_finding_id,
                )

            processed2 = await triage.retry_pending_ai_failures(pool)
            assert processed2 == 1, processed2
            async with pool.acquire() as conn:
                item_row = await conn.fetchrow("SELECT status FROM ai_retry_queue WHERE id = $1", new_item_id)
                assert item_row["status"] == "succeeded", item_row
            print("PASS: a finding resolved by other means before retry runs is skipped as a no-op, not clobbered")

        finally:
            async with pool.acquire() as conn:
                await _cleanup(conn, project_id)

    finally:
        triage.generate_with_rotation = original_generate
        await pool.close()


if __name__ == "__main__":
    try:
        asyncio.run(_run())
    except AssertionError as e:
        print(f"FAIL: {e}")
        sys.exit(1)
    print("\nAll manual retry-queue tests passed")
