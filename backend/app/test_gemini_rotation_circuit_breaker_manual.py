"""
Manual verification harness for the per-model circuit breaker in
gemini_rotation.py (generate_with_rotation).

Not wired into a pytest suite (repo has none yet) - run directly from
the `backend/` directory:
    cd backend && python3 -m app.test_gemini_rotation_circuit_breaker_manual

Uses REAL google.genai.errors.ClientError/ServerError objects (built
from a real requests.Response, exactly how the SDK constructs them
internally) so the breaker's error-classification logic (_is_quota_exhausted,
_is_transient_server_error) is exercised against the real exception
shapes it'll see in production, not stand-ins. The only thing faked is
the network call itself (client.models.generate_content) - swapped for
a plain Python function so this runs with no real API key and no
network access, which fits this module's job (rotation/breaker logic)
rather than actually validating Gemini connectivity.
"""
import asyncio
import json
import sys

import requests
from google.genai import errors as genai_errors

from . import gemini_rotation


def _make_error(cls, code: int, status: str):
    resp = requests.Response()
    resp.status_code = code
    resp._content = json.dumps({"error": {"code": code, "status": status, "message": status}}).encode()
    return cls(code, resp)


def _quota_error():
    return _make_error(genai_errors.ClientError, 429, "RESOURCE_EXHAUSTED")


def _server_error():
    return _make_error(genai_errors.ServerError, 503, "UNAVAILABLE")


class _FakeModels:
    """Stands in for client.models. `behavior` maps model name -> either
    a callable(returns a fake response) or an Exception instance to
    raise. Tracks every call made, in order, so tests can assert exactly
    which models were actually attempted (vs skipped by the breaker)."""

    def __init__(self, behavior: dict):
        self.behavior = behavior
        self.calls: list[str] = []

    def generate_content(self, model: str, contents: str):
        self.calls.append(model)
        outcome = self.behavior.get(model)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome()
        raise RuntimeError(f"test misconfigured: no behavior for model {model}")


class _FakeClient:
    def __init__(self, behavior: dict):
        self.models = _FakeModels(behavior)


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text


def test_quota_exhausted_trips_breaker_and_skips_on_next_call():
    gemini_rotation._reset_circuit_breaker_for_tests()
    model_a, model_b = gemini_rotation.MODEL_ROTATION[0], gemini_rotation.MODEL_ROTATION[1]
    behavior = {
        model_a: _quota_error(),
        model_b: lambda: _FakeResponse("ok from b"),
    }
    client = _FakeClient(behavior)

    response, used = asyncio.run(gemini_rotation.generate_with_rotation(client, "prompt"))
    assert used == model_b
    assert client.models.calls == [model_a, model_b], client.models.calls
    assert gemini_rotation._is_tripped(model_a), "model_a should be tripped after 429"
    print(f"PASS: {model_a} tripped on 429, rotated to {model_b}")

    # Second call: model_a should be SKIPPED entirely (no attempt), going
    # straight to model_b - the actual point of the breaker.
    client2 = _FakeClient({model_a: RuntimeError("should never be called"), model_b: lambda: _FakeResponse("ok again")})
    response2, used2 = asyncio.run(gemini_rotation.generate_with_rotation(client2, "prompt"))
    assert used2 == model_b
    assert client2.models.calls == [model_b], (
        f"expected model_a to be skipped by breaker, but calls were {client2.models.calls}"
    )
    print(f"PASS: {model_a} skipped without an attempt on next call (breaker held)")
    gemini_rotation._reset_circuit_breaker_for_tests()


def test_cooldown_elapsing_clears_the_trip():
    gemini_rotation._reset_circuit_breaker_for_tests()
    model_a = gemini_rotation.MODEL_ROTATION[0]
    gemini_rotation._trip(model_a)
    assert gemini_rotation._is_tripped(model_a)

    # Force the cooldown window to have already elapsed by back-dating
    # the trip timestamp, rather than sleeping for real in a test.
    gemini_rotation._tripped_models[model_a] -= (gemini_rotation._MODEL_COOLDOWN_SECONDS + 1)
    assert not gemini_rotation._is_tripped(model_a), "trip should clear once cooldown has elapsed"
    assert model_a not in gemini_rotation._tripped_models, "cleared trip should be removed from state"
    print(f"PASS: {model_a}'s trip clears once cooldown elapses")
    gemini_rotation._reset_circuit_breaker_for_tests()


def test_transient_server_error_does_not_trip_breaker():
    """A transient 503 is retried on the SAME model (existing retry
    behavior) - it should NOT trip the breaker, since the model itself
    isn't exhausted, just momentarily unavailable."""
    gemini_rotation._reset_circuit_breaker_for_tests()
    model_a = gemini_rotation.MODEL_ROTATION[0]
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise _server_error()
        return _FakeResponse("recovered")

    client = _FakeClient({model_a: flaky})
    response, used = asyncio.run(gemini_rotation.generate_with_rotation(client, "prompt"))
    assert used == model_a
    assert not gemini_rotation._is_tripped(model_a), "transient 503 should not trip the breaker"
    print(f"PASS: transient 503 on {model_a} retried in-place, did not trip breaker")
    gemini_rotation._reset_circuit_breaker_for_tests()


def test_all_models_tripped_falls_through_to_tier2_without_any_attempt():
    gemini_rotation._reset_circuit_breaker_for_tests()
    for m in gemini_rotation.MODEL_ROTATION:
        gemini_rotation._trip(m)

    client = _FakeClient({m: RuntimeError("should never be called") for m in gemini_rotation.MODEL_ROTATION})
    # No tier-2 keys set in this sandbox -> should raise, but WITHOUT
    # ever calling generate_content on any (fully tripped) model.
    try:
        asyncio.run(gemini_rotation.generate_with_rotation(client, "prompt"))
        assert False, "expected an exception when all models are tripped and no tier-2 is configured"
    except Exception as e:
        assert client.models.calls == [], f"expected zero attempts, got {client.models.calls}"
        assert "cooldown" in str(e).lower(), str(e)
        print(f"PASS: all models tripped -> zero attempts made, raised: {e}")
    gemini_rotation._reset_circuit_breaker_for_tests()


def test_status_reporting():
    gemini_rotation._reset_circuit_breaker_for_tests()
    model_a = gemini_rotation.MODEL_ROTATION[0]
    gemini_rotation._trip(model_a)
    status = gemini_rotation.get_circuit_breaker_status()
    assert model_a in status
    assert 0 < status[model_a] <= gemini_rotation._MODEL_COOLDOWN_SECONDS
    print(f"PASS: get_circuit_breaker_status reports {model_a} with {status[model_a]:.0f}s remaining")
    gemini_rotation._reset_circuit_breaker_for_tests()


if __name__ == "__main__":
    tests = [
        test_quota_exhausted_trips_breaker_and_skips_on_next_call,
        test_cooldown_elapsing_clears_the_trip,
        test_transient_server_error_does_not_trip_breaker,
        test_all_models_tripped_falls_through_to_tier2_without_any_attempt,
        test_status_reporting,
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
