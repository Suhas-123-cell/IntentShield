"""Regression tests for the proxy group of the 2026-10-31 audit: which .env files may configure the app (proxy-9)."""
from __future__ import annotations

import os
from pathlib import Path

import dotenv
import pytest

from intentshield.api import create_app

NAMES = ("INTENTSHIELD_PROXY_CONFIG", "INTENTSHIELD_CONTROL_TOKEN", "INTENTSHIELD_AGENT_TOKEN",
         "INTENTSHIELD_AUDIT_PLAIN", "OLLAMA_HOST")


@pytest.fixture
def clean_env(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("intentshield.api.load_dotenv", dotenv.load_dotenv)  # the real call, not the suite's no-op
    monkeypatch.setattr("intentshield.envfile.find_dotenv", dotenv.find_dotenv)
    yield
    for name in NAMES:
        os.environ.pop(name, None)


def test_a_cwd_env_cannot_name_the_proxy_config_or_set_the_tokens(tmp_path: Path, monkeypatch, capsys, clean_env):
    """proxy-9: a cloned repository's .env chose the upstream command to run and the approval tokens."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "proxy.json").write_text("{}")
    (repo / ".env").write_text("INTENTSHIELD_PROXY_CONFIG=./proxy.json\nINTENTSHIELD_CONTROL_TOKEN=known\n"
                               "INTENTSHIELD_AGENT_TOKEN=known\nOLLAMA_HOST=http://attacker.example\n"
                               "INTENTSHIELD_AUDIT_PLAIN=kept\n")
    monkeypatch.chdir(repo)
    # base: raises on the config's contents; here the tokens held only by that file stop the start (see below)
    with pytest.raises(ValueError, match="INTENTSHIELD_CONTROL_TOKEN"):
        create_app(tmp_path / "db.sqlite")
    assert all(name not in os.environ for name in NAMES[:3] + ("OLLAMA_HOST",))
    assert os.environ["INTENTSHIELD_AUDIT_PLAIN"] == "kept"  # other settings still load
    err = capsys.readouterr().err
    assert "INTENTSHIELD_PROXY_CONFIG" in err and "INTENTSHIELD_CONTROL_TOKEN" in err and str(repo) in err


def test_the_users_own_env_file_and_the_environment_still_set_them(tmp_path: Path, monkeypatch, clean_env):
    home = Path.home()  # the suite points it into tmp_path
    (home / ".intentshield").mkdir(parents=True)
    (home / ".intentshield" / ".env").write_text("INTENTSHIELD_CONTROL_TOKEN=operator\nINTENTSHIELD_AGENT_TOKEN=agent\n"
                                                 "INTENTSHIELD_PROXY_CONFIG=\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("INTENTSHIELD_CONTROL_TOKEN=repo-chosen\n")
    monkeypatch.chdir(repo)
    create_app(tmp_path / "db.sqlite")
    assert os.environ["INTENTSHIELD_CONTROL_TOKEN"] == "operator"
    monkeypatch.setenv("INTENTSHIELD_AUDIT_PLAIN", "exported")
    (repo / ".env").write_text("INTENTSHIELD_AUDIT_PLAIN=from-file\n")
    create_app(tmp_path / "db.sqlite")
    assert os.environ["INTENTSHIELD_AUDIT_PLAIN"] == "exported"


def test_a_token_only_a_cwd_env_held_stops_the_start_instead_of_leaving_the_api_open(tmp_path: Path, monkeypatch,
                                                                                    clean_env):
    """proxy-9 regression: ignoring the cwd .env's token must not start the approval API without one."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("INTENTSHIELD_CONTROL_TOKEN=operator-secret-canary\n")
    monkeypatch.chdir(repo)
    with pytest.raises(ValueError, match="cannot set it"):
        create_app(tmp_path / "db.sqlite")
    create_app(tmp_path / "db.sqlite", control_token="given")  # a token given by the caller is enough


def test_a_cwd_env_cannot_redirect_requests_move_data_or_weaken_protection(tmp_path: Path, monkeypatch, capsys,
                                                                           clean_env):
    """proxy-9: proxy variables, CA files, database paths, the threat memory and the rate limit came from a repo."""
    from intentshield.envfile import load_environment
    planted = {"INTENTSHIELD_DB": "./planted.db", "INTENTSHIELD_THREAT_DB": "./t.db", "INTENTSHIELD_THREAT_MEMORY": "off",
               "INTENTSHIELD_RATE_LIMIT_PER_MIN": "100000000", "INTENTSHIELD_HOOK_DB": "./hook.db",
               "http_proxy": "http://127.0.0.1:59998", "HTTPS_PROXY": "http://127.0.0.1:59998",
               "SSL_CERT_FILE": "./repo-ca.pem", "NODE_OPTIONS": "--require=./evil.js",
               "INTENTSHIELD_PACK_ED25519_KEYS": "x", "MY_CONTROL_TOKEN": "known"}
    benign = {"GROQ_API_KEY": "k", "INTENTSHIELD_GEMINI_MODEL": "m", "INTENTSHIELD_LOCAL_API_KEY": "u",
              "INTENTSHIELD_LOG_LEVEL": "debug"}
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("".join(f"{k}={v}\n" for k, v in {**planted, **benign}.items()))
    monkeypatch.chdir(repo)
    for name in [*planted, *benign]:
        monkeypatch.delenv(name, raising=False)
    refused = load_environment(dotenv.load_dotenv, usecwd=True, extra=frozenset({"MY_CONTROL_TOKEN"}))
    try:
        assert sorted(refused) == sorted(planted)
        assert not any(name in os.environ for name in planted)
        assert all(os.environ[name] == value for name, value in benign.items())
    finally:
        for name in [*planted, *benign]:
            os.environ.pop(name, None)


def test_a_custom_token_variable_in_a_searched_env_stops_the_gateway(tmp_path: Path, monkeypatch, clean_env):
    """proxy-9: --control-token-env names the variable, so a repository's .env could still set it."""
    from intentshield import mcp_server

    env = tmp_path / ".env"
    env.write_text("MY_GATEWAY_TOKEN=known\n")
    monkeypatch.setattr("intentshield.envfile.find_dotenv", lambda *a, **k: str(env))
    monkeypatch.setattr("intentshield.mcp_server.load_dotenv", dotenv.load_dotenv)
    monkeypatch.delenv("MY_GATEWAY_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="MY_GATEWAY_TOKEN"):
        mcp_server.main(["--config", "unused.json", "--control-token-env", "MY_GATEWAY_TOKEN"])
    assert "MY_GATEWAY_TOKEN" not in os.environ
