"""The one helper that sends a JSON request to a model provider (``intentshield.outbound``) and its three users: the judge, the
model gateway and the rule induction's local model. A request goes to an ``http`` or ``https`` address only."""
from __future__ import annotations

import io
import json
import urllib.request

import pytest

from intentshield import judge as judge_module
from intentshield import model_gateway, outbound, signatures
from intentshield.judge import Judge

_BAD_ADDRESSES = ["file:///etc/passwd", "ftp://example.org/x", "/etc/passwd", "gopher://example.org", "data:text/plain,hi", ""]


class _Reply(io.BytesIO):
    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _record(monkeypatch, reply: bytes = b'{"ok": true}') -> list[urllib.request.Request]:
    sent: list[urllib.request.Request] = []

    def urlopen(request, timeout):
        sent.append(request)
        return _Reply(reply)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return sent


@pytest.mark.parametrize("url", _BAD_ADDRESSES)
def test_a_request_to_an_address_that_is_not_http_is_refused_before_anything_is_opened(monkeypatch, url):
    sent = _record(monkeypatch)
    with pytest.raises(ValueError, match="not an http or https address"):
        outbound.open_json_post(url, {"a": 1}, {}, 5)
    assert sent == []


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/api/generate", "https://api.example.org/v1/chat", "HTTPS://API.EXAMPLE.ORG/x"])
def test_a_request_to_an_http_or_https_address_is_a_json_post(monkeypatch, url):
    sent = _record(monkeypatch)
    with outbound.open_json_post(url, {"a": "é"}, {"Authorization": "Bearer k"}, 5) as response:
        assert json.load(response) == {"ok": True}
    request = sent[0]
    assert request.get_method() == "POST" and json.loads(request.data) == {"a": "é"}
    assert request.get_header("Content-type") == "application/json" and request.get_header("Authorization") == "Bearer k"


def test_the_helper_passes_the_timeout_on(monkeypatch):
    timeouts: list[float] = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout: timeouts.append(timeout) or _Reply(b"{}"))
    outbound.open_json_post("https://api.example.org/x", {}, {}, 7.5).close()
    assert timeouts == [7.5]


def test_the_judge_takes_a_file_address_as_no_opinion_not_a_read_of_the_file(monkeypatch):
    sent = _record(monkeypatch)
    message, error = judge_module.post_chat_message("file:///etc/passwd", "k", {"model": "m"}, 5, 0)
    assert message is None and "ValueError" in error and "not an http or https address" in error and sent == []


def test_the_judge_sends_its_key_and_name_with_the_request(monkeypatch):
    sent = _record(monkeypatch, json.dumps({"choices": [{"message": {"content": "hi"}}]}).encode())
    monkeypatch.setattr(Judge, "_answers", {})
    assert judge_module.post_chat("https://api.example.org/v1/chat", "secret-key", {"model": "m"}, 5, 0) == ("hi", "")
    assert sent[0].get_header("Authorization") == "Bearer secret-key" and sent[0].get_header("User-agent") == "intentshield-judge"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.org/x"])
def test_the_model_gateway_reports_an_address_that_is_not_http_as_a_provider_error(monkeypatch, url):
    sent = _record(monkeypatch)
    with pytest.raises(model_gateway.ModelProviderError) as failure:
        model_gateway._post_json(url, {"x-goog-api-key": "k"}, {"a": 1}, 5)
    assert failure.value.code == "MODEL_PROVIDER_UNAVAILABLE" and sent == []
    assert "not an http or https URL" in failure.value.message


def test_the_model_gateway_returns_the_json_of_the_reply(monkeypatch):
    sent = _record(monkeypatch)
    assert model_gateway._post_json("https://example.org/m", {"x-goog-api-key": "k"}, {"a": 1}, 5) == {"ok": True}
    assert sent[0].get_header("X-goog-api-key") == "k"


def test_the_local_model_of_rule_induction_takes_a_bad_host_as_no_answer(monkeypatch):
    sent = _record(monkeypatch)
    assert signatures.ollama(host="file://", timeout=1)("prompt") is None and sent == []


def test_the_local_model_of_rule_induction_reads_its_json_answer(monkeypatch):
    sent = _record(monkeypatch, json.dumps({"response": json.dumps({"patterns": ["a"]})}).encode())
    assert signatures.ollama(host="http://127.0.0.1:11434")("prompt") == {"patterns": ["a"]}
    assert sent[0].full_url == "http://127.0.0.1:11434/api/generate" and json.loads(sent[0].data)["stream"] is False
