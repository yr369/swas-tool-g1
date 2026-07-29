"""
Manual verification harness for config.check_startup_config().

Not wired into a pytest suite (repo has none yet) - run directly from
the `backend/` directory:
    cd backend && python3 -m app.test_config_manual

No DB/network needed - this only touches os.environ and PATH, both of
which are fully controllable/restorable in-process, so a real
subprocess env is exercised without needing mocks.
"""
import os
import shutil
import sys
import tempfile

from . import config

_REQUIRED = {
    "GEMINI_API_KEY": "real_key_value",
    "POSTGRES_USER": "swas_user",
    "POSTGRES_PASSWORD": "real_password",
    "POSTGRES_DB": "swas_db",
}


def _clean_env():
    for var in list(_REQUIRED) + ["ALLOWED_ORIGINS", "NOTIFY_WEBHOOK_URL"]:
        os.environ.pop(var, None)


def _make_fake_binaries(tmpdir: str, names: list[str]) -> str:
    """Creates empty, executable stub files for each name in tmpdir and
    returns tmpdir so it can be prepended to PATH."""
    for name in names:
        p = os.path.join(tmpdir, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(p, 0o755)
    return tmpdir


def test_fails_when_gemini_key_missing():
    _clean_env()
    with tempfile.TemporaryDirectory() as tmp:
        _make_fake_binaries(tmp, list(config._REQUIRED_BINARIES))
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tmp}:{old_path}"
        try:
            for var, val in _REQUIRED.items():
                if var != "GEMINI_API_KEY":
                    os.environ[var] = val
            try:
                config.check_startup_config()
                assert False, "expected ConfigError when GEMINI_API_KEY is unset"
            except config.ConfigError as e:
                assert "GEMINI_API_KEY" in str(e)
                print("PASS: missing GEMINI_API_KEY raises ConfigError -", e)
        finally:
            os.environ["PATH"] = old_path
    _clean_env()


def test_fails_on_placeholder_value():
    _clean_env()
    with tempfile.TemporaryDirectory() as tmp:
        _make_fake_binaries(tmp, list(config._REQUIRED_BINARIES))
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tmp}:{old_path}"
        try:
            for var, val in _REQUIRED.items():
                os.environ[var] = val
            os.environ["GEMINI_API_KEY"] = "your_gemini_api_key_here"
            try:
                config.check_startup_config()
                assert False, "expected ConfigError for placeholder value"
            except config.ConfigError as e:
                assert "placeholder" in str(e)
                print("PASS: placeholder GEMINI_API_KEY raises ConfigError -", e)
        finally:
            os.environ["PATH"] = old_path
    _clean_env()


def test_fails_when_binary_missing():
    _clean_env()
    with tempfile.TemporaryDirectory() as tmp:
        # deliberately skip nuclei
        binaries = [b for b in config._REQUIRED_BINARIES if b != "nuclei"]
        _make_fake_binaries(tmp, binaries)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = tmp  # exclusive PATH so real system nuclei (if any) can't hide the gap
        try:
            for var, val in _REQUIRED.items():
                os.environ[var] = val
            try:
                config.check_startup_config()
                assert False, "expected ConfigError when nuclei binary missing"
            except config.ConfigError as e:
                assert "nuclei" in str(e)
                print("PASS: missing nuclei binary raises ConfigError -", e)
        finally:
            os.environ["PATH"] = old_path
    _clean_env()


def test_passes_and_warns_when_all_required_present():
    _clean_env()
    with tempfile.TemporaryDirectory() as tmp:
        _make_fake_binaries(tmp, list(config._REQUIRED_BINARIES))
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tmp}:{old_path}"
        try:
            for var, val in _REQUIRED.items():
                os.environ[var] = val
            # deliberately leave ALLOWED_ORIGINS unset -> should warn, not raise
            warnings = config.check_startup_config()
            assert any("ALLOWED_ORIGINS" in w for w in warnings)
            print("PASS: all required present -> no raise, warns about ALLOWED_ORIGINS:", warnings)
        finally:
            os.environ["PATH"] = old_path
    _clean_env()


def test_warns_on_malformed_webhook_url():
    _clean_env()
    with tempfile.TemporaryDirectory() as tmp:
        _make_fake_binaries(tmp, list(config._REQUIRED_BINARIES))
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tmp}:{old_path}"
        try:
            for var, val in _REQUIRED.items():
                os.environ[var] = val
            os.environ["ALLOWED_ORIGINS"] = "http://localhost"
            os.environ["NOTIFY_WEBHOOK_URL"] = "not-a-url"
            warnings = config.check_startup_config()
            assert any("NOTIFY_WEBHOOK_URL" in w for w in warnings)
            print("PASS: malformed NOTIFY_WEBHOOK_URL warns:", warnings)
        finally:
            os.environ["PATH"] = old_path
    _clean_env()


if __name__ == "__main__":
    tests = [
        test_fails_when_gemini_key_missing,
        test_fails_on_placeholder_value,
        test_fails_when_binary_missing,
        test_passes_and_warns_when_all_required_present,
        test_warns_on_malformed_webhook_url,
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
