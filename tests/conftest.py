import json
import os
import sys
from pathlib import Path

import pytest

_JUDGE_KEYS = ("GEMINI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY")
_KEYS_AT_START = {name: os.environ.get(name) for name in _JUDGE_KEYS}


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch, tmp_path):
    """Keep a developer's .env, home directory and exported secrets out of the tests, and every
    test from reaching a hosted judge with the developer's key. ``delenv`` records nothing for a
    key that is absent, so each key is first set (which records its original state, present or
    not) and then deleted: whatever a test writes into os.environ is undone at teardown."""
    for name in list(os.environ):
        if name.startswith("INTENTSHIELD_"):
            monkeypatch.delenv(name)
    for name in _JUDGE_KEYS:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr("intentshield.harness.ENV_FILE", home / ".intentshield" / ".env")
    # A locally trained classifier would change decisions; tests run the deterministic agents.
    monkeypatch.setenv("INTENTSHIELD_INTENT_MODEL_DIR", "tests/no-intent-model")
    monkeypatch.setattr("intentshield.envfile.find_dotenv", lambda *a, **k: "")  # no developer .env, not even to name
    for module in ("api", "mcp_server", "mcp_verify"):
        monkeypatch.setattr(f"intentshield.{module}.load_dotenv", lambda *a, **k: False)


@pytest.fixture
def demo_proxy_config(tmp_path: Path) -> Path:
    """The committed demo proxy config with the interpreter and database made absolute, so the
    suite passes from any working directory."""
    source = Path(__file__).parents[1] / "configs" / "mcp-proxy.demo.json"
    data = json.loads(source.read_text())
    data["upstreams"][0]["command"] = sys.executable
    data["database_path"] = str(tmp_path / "demo-proxy.db")
    path = tmp_path / "mcp-proxy.demo.json"
    path.write_text(json.dumps(data))
    return path


def pytest_sessionfinish(session, exitstatus):
    """No test may leave a judge key behind for the rest of the session or the shell."""
    leaked = [name for name in _JUDGE_KEYS if os.environ.get(name) != _KEYS_AT_START[name]]
    if leaked:
        print(f"\nconftest: judge keys changed by the tests and not restored: {', '.join(leaked)}")
        session.exitstatus = 1
