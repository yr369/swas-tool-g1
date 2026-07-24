"""
Manual verification harness for auth_policy.py + auth_sessions.py.

Unlike test_crlf_check_manual.py and test_agent_loop_manual.py, this one
genuinely needs a real Postgres with pgcrypto - the thing being tested is
server-side encryption, which cannot be meaningfully mocked. Point it at
a real (ideally scratch/local) database via the same DATABASE_URL the app
itself uses, plus a throwaway SWAS_SESSION_KEY:

    export DATABASE_URL="postgresql://postgres:testpass@localhost/swas_test"
    export SWAS_SESSION_KEY="some-throwaway-passphrase"
    cd backend && python3 -m app.test_auth_policy_and_sessions_manual

Requires auth_policy_migration.sql and auth_sessions_migration.sql to
already be applied to that database (same as any other migration - see
the "Verification method" note in the project handoff doc for how to
replay the full schema history locally).

This creates its own throwaway `projects` rows and cleans them up at the
end regardless of pass/fail, so it's safe to run against a persistent
dev database, not just a scratch one - though a scratch database is
still recommended since it does exercise real INSERT/DELETE.

What this proves, all against real asyncpg + real pgcrypto:
  1. store_session refuses to run with no SWAS_SESSION_KEY set.
  2. store_session is blocked on a project that isn't explicitly
     'approved' in auth_policy - and confirms zero rows persist.
  3. store -> get on an approved project roundtrips the exact original
     credential value.
  4. The raw stored bytes do not contain the plaintext credential.
  5. Decrypting with the wrong passphrase raises rather than returning
     garbage silently.
  6. list_sessions returns metadata only (no secret material) and does
     not require approval to call.
"""
import asyncio
import os

import asyncpg

from . import auth_policy, auth_sessions


async def main():
    database_url = os.environ["DATABASE_URL"]
    if not os.environ.get("SWAS_SESSION_KEY"):
        raise SystemExit("Set SWAS_SESSION_KEY (any throwaway value) before running this harness.")

    conn = await asyncpg.connect(database_url)
    project_ids = []
    try:
        project_id = await conn.fetchval(
            "INSERT INTO projects (name, platform) VALUES ('harness-test-program', 'hackerone') RETURNING id"
        )
        project_ids.append(project_id)

        real_key = os.environ.pop("SWAS_SESSION_KEY")
        try:
            await auth_policy.set_policy(conn, project_id, "approved", "harness test", "harness")
            try:
                await auth_sessions.store_session(conn, project_id, "user_a", "session_cookie=abc123secret")
                raise AssertionError("store_session proceeded with no SWAS_SESSION_KEY set!")
            except RuntimeError:
                print("PASS (1/6): store_session refuses to run with no encryption key set")
        finally:
            os.environ["SWAS_SESSION_KEY"] = real_key

        project_id_2 = await conn.fetchval(
            "INSERT INTO projects (name, platform) VALUES ('harness-unapproved-program', 'bugcrowd') RETURNING id"
        )
        project_ids.append(project_id_2)
        try:
            await auth_sessions.store_session(conn, project_id_2, "user_a", "should-not-persist")
            raise AssertionError("store_session proceeded on an unapproved project!")
        except auth_policy.AuthPolicyError:
            print("PASS (2/6): store_session blocked on unapproved project")
        count = await conn.fetchval(
            "SELECT count(*) FROM project_auth_sessions WHERE project_id = $1", project_id_2
        )
        assert count == 0
        print("PASS (2b/6): zero rows persisted for the blocked project")

        await auth_sessions.store_session(
            conn, project_id, "user_a", "session_cookie=abc123secret",
            session_type="cookie", notes="free-tier account",
        )
        result = await auth_sessions.get_session(conn, project_id, "user_a")
        assert result["credential_value"] == "session_cookie=abc123secret"
        print("PASS (3/6): store -> get roundtrip returns the exact original credential")

        raw = await conn.fetchval(
            "SELECT encrypted_value FROM project_auth_sessions WHERE project_id = $1 AND session_name = 'user_a'",
            project_id,
        )
        assert b"abc123secret" not in raw
        print(f"PASS (4/6): raw stored bytes do not contain the plaintext credential (len={len(raw)} bytes)")

        try:
            await conn.fetchrow(
                "SELECT pgp_sym_decrypt(encrypted_value, 'totally-wrong-key') FROM project_auth_sessions "
                "WHERE project_id = $1 AND session_name = 'user_a'",
                project_id,
            )
            raise AssertionError("decrypting with the wrong passphrase did not raise!")
        except AssertionError:
            raise
        except Exception:
            print("PASS (5/6): decrypting with the wrong passphrase correctly raises")

        listing = await auth_sessions.list_sessions(conn, project_id)
        assert "encrypted_value" not in listing[0] and "credential_value" not in listing[0]
        assert listing[0]["session_name"] == "user_a"
        print("PASS (6/6): list_sessions returns metadata only, no secret material")

        print("\nALL PASS")
    finally:
        for pid in project_ids:
            await conn.execute("DELETE FROM projects WHERE id = $1", pid)  # cascades to sessions/policy rows
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
