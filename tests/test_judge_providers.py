"""The judge with the user's own key: OpenAI, OpenRouter or any OpenAI-compatible endpoint, beside the
free Groq default; and `install --judge deepseek`, which the README documents."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from intentshield import install
from intentshield import judge as judge_module
from intentshield.judge import Judge


def _replying(sent: list):
    def urlopen(request, timeout):
        sent.append((request.full_url, request.headers.get("Authorization"), json.loads(request.data)))
        return io.BytesIO(json.dumps({"choices": [{"message": {"content": '{"verdict": "clean"}'}}]}).encode())
    return urlopen


def test_install_accepts_every_provider_the_judge_has():
    assert install.hook_command("claude", "h", judge="deepseek") == "h claude --judge deepseek"
    for spec in ("openai:gpt-4.1-mini", "openrouter:meta-llama/llama-3.3-70b-instruct", "custom:my-model"):
        assert install.hook_command("claude", "h", judge=spec) == f"h claude --judge {spec}"


@pytest.mark.parametrize("provider", ["openai", "openrouter", "custom"])
def test_a_judge_on_the_users_own_key_needs_a_model(provider, monkeypatch):
    with pytest.raises(ValueError, match="needs a model"):
        install.hook_command("claude", "h", judge=provider)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.setenv("INTENTSHIELD_JUDGE_API_KEY", "k")
    monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", "https://llm.example/v1/chat/completions")
    with pytest.raises(ValueError, match="needs a model"):
        Judge.from_spec(provider)


def test_openai_and_openrouter_judges_send_the_users_key_and_model(monkeypatch):
    sent: list = []
    monkeypatch.setattr(judge_module.urllib.request, "urlopen", _replying(sent))
    monkeypatch.setattr(Judge, "_answers", {})
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        Judge.from_spec("openai:gpt-4.1-mini")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-user")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-user")
    assert Judge.from_spec("openai:gpt-4.1-mini").output("summarize", "web:read", "A calm page.") is None
    assert Judge.from_spec("openrouter:some/model").output("summarize", "web:read", "Another page.") is None
    assert sent[0][:2] == ("https://api.openai.com/v1/chat/completions", "Bearer sk-user")
    assert sent[0][2]["model"] == "gpt-4.1-mini"
    assert sent[1][:2] == ("https://openrouter.ai/api/v1/chat/completions", "Bearer or-user")
    assert sent[1][2]["model"] == "some/model"


def test_custom_judge_posts_to_the_users_endpoint(monkeypatch):
    sent: list = []
    monkeypatch.setattr(judge_module.urllib.request, "urlopen", _replying(sent))
    monkeypatch.setattr(Judge, "_answers", {})
    monkeypatch.setenv("INTENTSHIELD_JUDGE_API_KEY", "c-key")
    monkeypatch.delenv("INTENTSHIELD_JUDGE_URL", raising=False)
    with pytest.raises(ValueError, match="INTENTSHIELD_JUDGE_URL"):
        Judge.from_spec("custom:m")
    for bad in ("http://llm.example/v1/chat/completions", "ftp://llm.example/x", "not a url"):
        monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", bad)
        with pytest.raises(ValueError, match="https"):
            Judge.from_spec("custom:m")
    monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", "https://llm.example/v1/chat/completions")
    assert Judge.from_spec("custom:m").output("summarize", "web:read", "A calm page.") is None
    assert sent[-1][:2] == ("https://llm.example/v1/chat/completions", "Bearer c-key")
    monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", "http://localhost:8000/v1/chat/completions")  # local server
    assert Judge.from_spec("custom:m").url == "http://localhost:8000/v1/chat/completions"


def test_install_stores_a_custom_judges_key_and_url(tmp_path: Path, monkeypatch):
    for name in ("INTENTSHIELD_JUDGE_API_KEY", "INTENTSHIELD_JUDGE_URL"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".intentshield" / ".env"
    with pytest.raises(ValueError, match="--judge-url"):
        install.ensure_judge_key("custom:m", tmp_path, api_key="c-key")
    with pytest.raises(ValueError, match="https"):
        install.ensure_judge_key("custom:m", tmp_path, api_key="c-key", judge_url="http://llm.example/v1")
    assert not env.exists()
    install.ensure_judge_key("custom:m", tmp_path, api_key="c-key", judge_url="https://llm.example/v1/chat/completions")
    lines = env.read_text().splitlines()
    assert "INTENTSHIELD_JUDGE_URL=https://llm.example/v1/chat/completions" in lines
    assert "INTENTSHIELD_JUDGE_API_KEY=c-key" in lines
    assert env.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="custom only"):
        install.ensure_judge_key("groq", tmp_path, api_key="gsk", judge_url="https://llm.example/v1")


def test_a_refused_judge_spec_stores_no_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="needs a model"):
        install.install("claude", home=tmp_path, cwd=tmp_path, hook="/opt/h", judge="openai", api_key="sk-user")
    assert not (tmp_path / ".intentshield" / ".env").exists()
