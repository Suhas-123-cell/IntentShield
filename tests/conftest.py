import json
import os
import sys
from pathlib import Path

import pytest

_JUDGE_KEYS = ("GEMINI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY")


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch, tmp_path):
    """Keep a developer's .env, home directory and exported secrets out of the tests, and every
    test from reaching a hosted judge with the developer's key. ``delenv`` with ``raising=False``
    records the keys even when absent, so a test that sets one is always undone."""
    for name in list(os.environ):
        if name.startswith("INTENTSHIELD_"):
            monkeypatch.delenv(name)
    for name in _JUDGE_KEYS:
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr("intentshield.harness.ENV_FILE", home / ".intentshield" / ".env")
    # A locally trained classifier would change decisions; tests run the deterministic agents.
    monkeypatch.setenv("INTENTSHIELD_INTENT_MODEL_DIR", "tests/no-intent-model")
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
