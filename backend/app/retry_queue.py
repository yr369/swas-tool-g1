"""
retry_queue.py - generic retry queue for AI calls that failed even after
generate_with_rotation exhausted every Gemini model AND every tier-2
provider.

Why this exists: before this, a totally-failed AI call (see
triage.triage_finding's except block) just stayed failed. For triage
specifically that's not quite "lost forever" - the finding keeps
severity='unknown' and gets re-selected by triage_project_findings the
NEXT time the triage phase runs for that project, which could be the
next full rescan, hours or days later. This queue closes that gap: a
background worker (see main.py's ai retry loop, and
triage.retry_pending_ai_failures) retries queued items every few minutes
instead of waiting for the next scan.

Kept intentionally generic (kind + JSONB payload) rather than
triage-specific, since the same "AI call failed after exhausting
rotation" pattern applies to gate.py, logic_hunter.py, report_writer.py,
scope_parser.py, and target_intelligence.py too - each just needs its
own `kind` string and a worker branch that knows how to redo ITS
specific call. Only "finding_triage" has a worker branch wired up in
this batch (see triage.retry_pending_ai_failures).
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import asyncpg

logger = logging.getLogger("swas.retry_queue")

DEFAULT_MAX_ATTEMPTS = 5

# Exponential-ish backoff, capped at 4h - a permanently-exhausted daily
# quota shouldn't get hammered every few minutes for hours, but a
# transient blip shouldn't wait 4 hours for its very first retry either.
# Index = attempts-so-far (post-increment), so the FIRST retry after one
# failure waits 2 minutes, the fifth waits 4 hours.
_BACKOFF_SCHEDULE_MINUTES = [2, 5, 15, 60, 240]


def _backoff_for(attempts: int) -> timedelta:
    idx = min(attempts, len(_BACKOFF_SCHEDULE_MINUTES) - 1)
    return timedelta(minutes=_BACKOFF_SCHEDULE_MINUTES[idx])


async def enqueue(
    conn: asyncpg.Connection, kind: str, payload: dict, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> int:
    """Adds an item to the retry queue. Returns the new row's id."""
    row = await conn.fetchrow(
        """
        INSERT INTO ai_retry_queue (kind, payload, max_attempts)
        VALUES ($1, $2::jsonb, $3)
        RETURNING id
        """,
        kind, json.dumps(payload), max_attempts,
    )
    logger.info("Enqueued retry item id=%s kind=%s payload=%s", row["id"], kind, payload)
    return row["id"]


async def fetch_due(conn: asyncpg.Connection, kind: str, limit: int = 20) -> list[asyncpg.Record]:
    """Returns up to `limit` pending items of `kind` whose next_attempt_at
    has already passed, oldest first, so a backlog drains in the order
    it built up rather than newest-first."""
    return await conn.fetch(
        """
        SELECT id, kind, payload, attempts, max_attempts
        FROM ai_retry_queue
        WHERE kind = $1 AND status = 'pending' AND next_attempt_at <= now()
        ORDER BY created_at ASC
        LIMIT $2
        """,
        kind, limit,
    )


async def mark_succeeded(conn: asyncpg.Connection, item_id: int) -> None:
    await conn.execute(
        "UPDATE ai_retry_queue SET status = 'succeeded', updated_at = now() WHERE id = $1",
        item_id,
    )


async def mark_attempt_failed(conn: asyncpg.Connection, item_id: int, error: str, error_type: str) -> None:
    """
    Records a failed retry attempt. If max_attempts has now been
    reached, marks the item permanently 'failed' - this queue stops
    trying at that point rather than retrying forever; a permanently
    failed finding_triage item just means that finding keeps
    severity='unknown' until the project's next full triage phase runs,
    same as before this feature existed. Otherwise schedules the next
    attempt with backoff and leaves the item 'pending'.
    """
    row = await conn.fetchrow(
        "SELECT attempts, max_attempts FROM ai_retry_queue WHERE id = $1", item_id
    )
    if row is None:
        logger.warning("mark_attempt_failed called for missing retry item id=%s", item_id)
        return

    new_attempts = row["attempts"] + 1
    if new_attempts >= row["max_attempts"]:
        await conn.execute(
            """
            UPDATE ai_retry_queue
            SET status = 'failed', attempts = $2, last_error = $3, error_type = $4, updated_at = now()
            WHERE id = $1
            """,
            item_id, new_attempts, error[:2000], error_type,
        )
        logger.warning(
            "Retry item id=%s permanently failed after %d attempts (%s)", item_id, new_attempts, error_type,
        )
    else:
        next_attempt_at = datetime.now(timezone.utc) + _backoff_for(new_attempts)
        await conn.execute(
            """
            UPDATE ai_retry_queue
            SET attempts = $2, last_error = $3, error_type = $4, next_attempt_at = $5, updated_at = now()
            WHERE id = $1
            """,
            item_id, new_attempts, error[:2000], error_type, next_attempt_at,
        )
        logger.info(
            "Retry item id=%s attempt %d/%d failed, retrying at %s (%s)",
            item_id, new_attempts, row["max_attempts"], next_attempt_at.isoformat(), error_type,
        )
