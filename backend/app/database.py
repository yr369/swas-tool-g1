"""
database.py - manages the connection pool to PostgreSQL.

Plain-language explanation: instead of opening a brand new connection to
the database every time we need one (slow), we keep a small "pool" of
already-open connections ready to use. FastAPI borrows one when it needs
it and returns it when done.

This module is intentionally simple - it just sets up the pool on startup
and closes it cleanly on shutdown. All actual queries live in other files
(e.g. projects.py, findings.py) and borrow a connection from here.
"""

import os
import asyncpg

# This will hold the actual connection pool once the app starts up.
# It starts as None because the pool doesn't exist until we explicitly
# create it (see connect_db below).
_pool: asyncpg.Pool | None = None


async def connect_db() -> None:
    """
    Creates the connection pool. Call this once, when the FastAPI app
    starts up (see main.py's startup event).
    """
    global _pool
    database_url = os.environ["DATABASE_URL"]

    _pool = await asyncpg.create_pool(
        dsn=database_url,
        min_size=2,
        # Was 10 - too low for a project with many scope targets scanning
        # concurrently. Each target's pipeline task holds ONE connection
        # for its entire run (recon + every detective check, many of
        # which are slow outbound network calls), not per-query - so
        # more than ~10 concurrently-scanning targets on a single
        # project saturates the pool and blocks everything else in the
        # app, including /api/health, until a target pipeline finishes.
        # Confirmed live on OCI: a project with 7+ concurrent scope
        # targets held all 10 connections idle-but-checked-out for
        # minutes. 30 gives real headroom without approaching Postgres's
        # own default max_connections=100 (no override set in
        # docker-compose.yml, so there's plenty of room).
        #
        # This doesn't fix the underlying pattern (holding a connection
        # for a whole pipeline run instead of acquiring per-query) - it
        # just raises the ceiling enough that a large project doesn't
        # starve the rest of the app. The real fix is a bigger change
        # (acquire/release per query inside pipeline.py) worth doing as
        # its own pass, not a one-line config tweak.
        max_size=30,
        # If the database is briefly unreachable (e.g. restarting), don't
        # fail immediately - give it a few seconds to come back.
        timeout=10,
    )


async def disconnect_db() -> None:
    """Closes the connection pool cleanly. Call this on app shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool:
    """
    Returns the active connection pool so other parts of the app can run
    queries. Raises a clear error if called before connect_db() - this
    should never happen in normal operation, but a clear error here is
    much easier to debug than a confusing crash somewhere else.
    """
    if _pool is None:
        raise RuntimeError(
            "Database pool not initialized. connect_db() must be called "
            "during app startup before any queries are run."
        )
    return _pool
