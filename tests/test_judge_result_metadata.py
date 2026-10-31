"""Result files of the judge benchmarks say which endpoint and context the judge ran through."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

import adaptive_judge  # noqa: E402

from intentshield import judge as judge_module  # noqa: E402


def test_the_endpoint_record_names_the_native_ollama_url_and_the_context(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    info = adaptive_judge.judge_endpoint(judge_module.Judge.from_spec("ollama:qwen2.5:7b"))
    assert info["url"].endswith("/api/chat") and info["num_ctx"] == judge_module.OLLAMA_CONTEXT == 8192
    assert len(info["prompt_sha256"]) == 16


def test_a_hosted_judge_records_no_context(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    info = adaptive_judge.judge_endpoint(judge_module.Judge.from_spec("gemini"))
    assert not info["url"].endswith("/api/chat") and info["num_ctx"] is None
