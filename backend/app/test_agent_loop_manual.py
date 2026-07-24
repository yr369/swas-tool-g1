"""
Manual verification harness for agent_loop.py.

Not wired into a pytest suite (repo has none yet) - run directly from
the `backend/` directory:
    cd backend && python3 -m app.test_agent_loop_manual

No real GEMINI_API_KEY needed: generate_with_rotation is monkeypatched
with a scripted fake model so this test is deterministic and free. What
it actually proves, against real local HTTP servers (not mocked
responses) and the real agent_loop code path:

  1. SAFETY: a scripted "model" that tries to sneak in a disallowed
     action (here, "action": "post" - not in _ALLOWED_ACTIONS) never
     causes a real HTTP request. Proven by pointing it at a local server
     that would record any request it received; the server log stays
     empty for that step.
  2. STEP BUDGET: a scripted model that always asks for another 'get'
     and never calls 'finish' still stops at exactly _MAX_STEPS steps,
     and a forced-conclude call happens afterward - proven by counting
     actual server hits.
  3. WRITEBACK: URLs the loop actually GETs show up in
     endpoints_touched with the right status codes, ready for the
     caller (_save_hypothesis) to upsert into attack_surface_endpoints.
"""
import asyncio
import urllib.parse

from . import agent_loop


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text


async def _serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hit_log: list):
    data = await reader.read(4096)
    request_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
    method, path, _ = request_line.split(" ", 2)
    hit_log.append((method, path))
    body = b'{"ok": true}'
    resp = (
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n"
    ).encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()


async def _run_server(port: int, hit_log: list):
    server = await asyncio.start_server(lambda r, w: _serve(r, w, hit_log), "127.0.0.1", port)
    async with server:
        asyncio.ensure_future(server.serve_forever())
        await asyncio.sleep(0.15)
        yield


async def test_disallowed_action_never_hits_network():
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve(r, w, hit_log), "127.0.0.1", 8911)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        # Step 1: try a disallowed method dressed up as an "action".
        if call_count["n"] == 1:
            return _FakeResponse(
                '{"action": "post", "url": "http://127.0.0.1:8911/admin", "why": "try to write"}'
            ), "fake-model"
        # Step 2: give up and finish.
        return _FakeResponse(
            '{"action": "finish", "conclusion": "post is not available, nothing more to check", "confidence": 0.2}'
        ), "fake-model"

    orig = agent_loop.generate_with_rotation
    agent_loop.generate_with_rotation = fake_generate
    agent_loop._get_client = lambda: object()
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            result = await agent_loop.investigate(
                hypothesis="attacker can write to /admin without auth",
                target_name="test-target", target_type="website",
                surface_context="no surface data",
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert hit_log == [], f"REGRESSION: a disallowed action reached the network! hit_log={hit_log}"
    assert result["steps_taken"] == 2
    print("PASS (1/3): disallowed 'post' action never issued a real request.", "hit_log:", hit_log)


async def test_step_budget_hard_enforced():
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve(r, w, hit_log), "127.0.0.1", 8912)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        # Never finishes on its own - always asks for one more GET.
        return _FakeResponse(
            f'{{"action": "get", "url": "http://127.0.0.1:8912/probe{call_count["n"]}", "why": "keep going"}}'
        ), "fake-model"

    orig = agent_loop.generate_with_rotation
    agent_loop.generate_with_rotation = fake_generate
    agent_loop._get_client = lambda: object()
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            result = await agent_loop.investigate(
                hypothesis="endless hypothesis that never gets confirmed",
                target_name="test-target", target_type="website",
                surface_context="no surface data",
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert result["steps_taken"] == agent_loop._MAX_STEPS, (
        f"REGRESSION: step budget not enforced, got {result['steps_taken']} vs cap {agent_loop._MAX_STEPS}"
    )
    assert len(hit_log) == agent_loop._MAX_STEPS, (
        f"REGRESSION: expected exactly {agent_loop._MAX_STEPS} real requests, got {len(hit_log)}: {hit_log}"
    )
    # +1 because the model never called finish, so a forced-conclude call happens after the loop.
    assert call_count["n"] == agent_loop._MAX_STEPS + 1
    print(f"PASS (2/3): step budget hard-capped at {agent_loop._MAX_STEPS} real requests "
          f"(model never called finish), forced-conclude ran once after.")


async def test_endpoint_writeback():
    hit_log: list = []
    server = await asyncio.start_server(lambda r, w: _serve(r, w, hit_log), "127.0.0.1", 8913)

    call_count = {"n": 0}

    async def fake_generate(client, prompt, preferred_model=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _FakeResponse(
                '{"action": "get", "url": "http://127.0.0.1:8913/api/user/1", "why": "check response shape"}'
            ), "fake-model"
        return _FakeResponse(
            '{"action": "finish", "conclusion": "endpoint returned 200 with a JSON body, consistent with the hypothesis", "confidence": 0.6}'
        ), "fake-model"

    orig = agent_loop.generate_with_rotation
    agent_loop.generate_with_rotation = fake_generate
    agent_loop._get_client = lambda: object()
    try:
        async with server:
            asyncio.ensure_future(server.serve_forever())
            await asyncio.sleep(0.15)
            result = await agent_loop.investigate(
                hypothesis="unauth GET to /api/user/1 leaks another user's data",
                target_name="test-target", target_type="website",
                surface_context="no surface data",
            )
    finally:
        agent_loop.generate_with_rotation = orig

    assert len(result["endpoints_touched"]) == 1
    ep = result["endpoints_touched"][0]
    assert ep["url"] == "http://127.0.0.1:8913/api/user/1"
    assert ep["status_code"] == 200
    assert ep["is_live"] is True
    assert ep["source"] == "logic_hunter_agent"
    print("PASS (3/3): endpoint touched during investigation captured correctly for surface writeback:", ep)


async def main():
    await test_disallowed_action_never_hits_network()
    await test_step_budget_hard_enforced()
    await test_endpoint_writeback()
    print("\nALL PASS")


if __name__ == "__main__":
    asyncio.run(main())
