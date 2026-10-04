import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch):
    """Keep a developer's .env and exported secrets from leaking into tests."""
    for name in list(os.environ):
        if name.startswith("INTENTSHIELD_") or name == "GEMINI_API_KEY":
            monkeypatch.delenv(name)
    for module in ("api", "mcp_server", "mcp_verify"):
        monkeypatch.setattr(f"intentshield.{module}.load_dotenv", lambda *a, **k: False)
