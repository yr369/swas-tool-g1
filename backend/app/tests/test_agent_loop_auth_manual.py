"""
Manual verification harness for agent_loop.py's authenticated
(auth_get/auth_compare) path.

Unlike the base test_agent_loop_manual.py, this one needs a real
Postgres with pgcrypto (auth_sessions.py's encryption is server-side)
and the auth_policy_migration.sql / auth_sessions_migration.sql schema
already applied - see test_auth_policy_and_sessions_manual.py's
docstring for how to set that up. Run from `backend/`:

    export DATABASE_URL="postgresql://postgres:testpass@localhost/swas_test2"
    export SWAS_SESSION_KEY="some-throwaway-passphrase"
    python3 -m app.test_agent_loop_auth_manual

generate_with_rotation is monkeypatched with a scripted fake model, same
as the base harness - no real GEMINI_API_KEY needed.

What this proves, against a real local mock server (not mocked
responses) that actually inspects the Cookie/Authorization header it
receives per request:

  1. SESSION ISOLATION IS REAL: auth_compare with two different
     registered sessions produces two DIFFERENT responses from the
     server, because the server itself only returns the "private" body
     when it sees the correct, specific credential value - proving the
     right credential actually got attached to the right request, not
     just that *some* header was sent.
  2. NO CREDENTIAL LEAKAGE: neither raw session value appears ANYWHERE
     in investigate()'s returned summary or in any history entry -
     checked by substring-searching the full JSON-serialized result.
  3. UNAPPROVED PROJECT: auth_get is never actually attempted (and
     never reaches the mock server with a valid credential) when the
     project has no 'approved' auth_policy row - the loop silently
     falls back to anonymous-only investigation.
  4. UNKNOWN SESSION NAME: asking for a session name that was never
     registered returns a clear "unknown session" tool result and
     issues no request at all.
"""
import asyncio
import json
import os

import asyncpg

from .. import agent_loop, auth_policy, auth_sessions


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text


_SESSION_A_VALUE = "cookie_session=A_super_secret_value"
_SESSION_B_VALUE = "cookie_session=B_super_secret_value"


async def _serve_idor(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hit_log: list):
    data = await reader.read(4096)
    lines = data.split(b"\r\n")
    request_line = lines[0].decode(errors="ignore")
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode().strip().lower()] = v.decode().strip()

    cookie = headers.get("cookie", "")
    hit_log.append(cookie)

    if cookie == _SESSION_A_VALUE:
        body = b'{"user": "A", "private_notes": "A only data"}'
        status = "200 OK"
    elif cookie == _SESSION_B_VALUE:
        body = b'{"user": "B", "private_notes": "B only data"}'
        status = "200 OK"
    else:
        body = b'{"error": "unauthorized"}'
        status = "401 Unauthorized"

    resp = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()


def _patch_llm(fake_generate):
    orig = agent_loop.generate_with_rotation
    agent_loop.generate_with_rotation = fake_generate
    agent_loop._get_client = lambda: object()
    return orig


async def _setup_project(conn, name: str, approve: bool):
    project_id = await conn.fetchval(
        "INSERT INTO projects (name, platform) VALUES ($1, 'hackerone') RETURNING id", name,
    )
    if approve:
        await auth_policy.set_policy(conn, project_id, "approved", "harness test", "harness")
        await auth_sessions.store_session(conn, project_id, "user_a", _SESSION_A_VALUE, session_type="cookie")
        await auth_sessions.store_session(conn, project_id, "user_b", _SESSION_B_VALUE, session_type="cookie")
    return project_id


async def test_session_isolation_and_no_leakage(conn):
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve_idor(r, w, hit_log), "127.0.0.1", 8921)
    project_id = await _setup_project(conn, "harness-idor-program", approve=True)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        assert "user_a" in prompt and "user_b" in prompt, "auth actions/session names were not offered in the prompt!"
        if call_count["n"] == 1:
            return _FakeResponse(json.dumps({
                "action": "auth_compare", "session_name_a": "user_a", "session_name_b": "user_b",
                "url": "http://127.0.0.1:8921/api/notes", "why": "check for IDOR",
            })), "fake-model"
        return _FakeResponse(json.dumps({
            "action": "finish",
            "conclusion": "both sessions returned their own private_notes, no cross-account leak observed",
            "confidence": 0.7,
        })), "fake-model"

    orig = _patch_llm(fake_generate)
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            result = await agent_loop.investigate(
                hypothesis="user A's session might be able to read user B's private notes",
                target_name="idor-target", target_type="website",
                surface_context="no surface data", conn=conn, project_id=project_id,
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert hit_log == [_SESSION_A_VALUE, _SESSION_B_VALUE], f"unexpected cookies sent: {hit_log}"
    print("PASS (1/4): auth_compare sent the correct, distinct cookie for each named session:", hit_log)

    full_dump = json.dumps(result)
    assert _SESSION_A_VALUE not in full_dump and _SESSION_B_VALUE not in full_dump, (
        "REGRESSION: a raw credential value leaked into the investigation result!"
    )
    print("PASS (2/4): neither raw session value appears anywhere in the returned result")

    touched = result["endpoints_touched"]
    assert {e["session_name"] for e in touched} == {"user_a", "user_b"}
    assert all(e["source"] == "logic_hunter_agent_authenticated" for e in touched)
    print("PASS (2b/4): endpoints_touched records session NAMES (labels), not values:", touched)


async def test_unapproved_project_falls_back_anonymous(conn):
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve_idor(r, w, hit_log), "127.0.0.1", 8922)
    project_id = await _setup_project(conn, "harness-unapproved-idor-program", approve=False)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        actions_menu = prompt.split("Rules:")[0]
        assert "auth_get" not in actions_menu and "auth_compare" not in actions_menu, (
            "auth actions were offered in the menu for an UNAPPROVED project!"
        )
        # Try anyway, as if the model hallucinated the action from training data.
        if call_count["n"] == 1:
            return _FakeResponse(json.dumps({
                "action": "auth_get", "session_name": "user_a",
                "url": "http://127.0.0.1:8922/api/notes", "why": "try anyway",
            })), "fake-model"
        return _FakeResponse(json.dumps({
            "action": "finish", "conclusion": "no authenticated sessions available, cannot confirm", "confidence": 0.1,
        })), "fake-model"

    orig = _patch_llm(fake_generate)
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            result = await agent_loop.investigate(
                hypothesis="user A's session might be able to read user B's private notes",
                target_name="idor-target", target_type="website",
                surface_context="no surface data", conn=conn, project_id=project_id,
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert hit_log == [], f"REGRESSION: an auth_get on an unapproved project reached the server! hit_log={hit_log}"
    print("PASS (3/4): auth_get on an unapproved project never reached the server:", result["summary"][:120])


async def test_unknown_session_name(conn):
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve_idor(r, w, hit_log), "127.0.0.1", 8923)
    project_id = await _setup_project(conn, "harness-unknown-session-program", approve=True)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _FakeResponse(json.dumps({
                "action": "auth_get", "session_name": "user_z_does_not_exist",
                "url": "http://127.0.0.1:8923/api/notes", "why": "typo'd session name",
            })), "fake-model"
        return _FakeResponse(json.dumps({
            "action": "finish", "conclusion": "requested session did not exist", "confidence": 0.1,
        })), "fake-model"

    orig = _patch_llm(fake_generate)
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            await agent_loop.investigate(
                hypothesis="test", target_name="idor-target", target_type="website",
                surface_context="no surface data", conn=conn, project_id=project_id,
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert hit_log == [], f"REGRESSION: an unknown session name still reached the server! hit_log={hit_log}"
    print("PASS (4/4): an unregistered session name issues no request at all")


async def main():
    database_url = os.environ["DATABASE_URL"]
    if not os.environ.get("SWAS_SESSION_KEY"):
        raise SystemExit("Set SWAS_SESSION_KEY before running this harness.")

    conn = await asyncpg.connect(database_url)
    project_ids_created = []
    try:
        await test_session_isolation_and_no_leakage(conn)
        await test_unapproved_project_falls_back_anonymous(conn)
        await test_unknown_session_name(conn)
        print("\nALL PASS")
    finally:
        rows = await conn.fetch("SELECT id FROM projects WHERE name LIKE 'harness-%-program'")
        for r in rows:
            await conn.execute("DELETE FROM projects WHERE id = $1", r["id"])
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
