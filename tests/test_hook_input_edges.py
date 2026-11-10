"""Inputs a harness or a judge endpoint can plausibly send that once failed the hook."""
import io
import json
import os
import sqlite3
import urllib.request

import pytest

from intentshield import harness, judge, shell


def test_lone_surrogate_in_prompt_is_stored(tmp_path):
    event = harness._no_surrogates(json.loads('{"prompt": "email bob@corp.test the report \\ud83d", "n": [1, "\\udc00"]}'))
    assert "bob@corp.test" in event["prompt"]
    event["prompt"].encode()  # no lone surrogate is left
    event["n"][1].encode()
    db = sqlite3.connect(tmp_path / "t.db")
    db.execute("CREATE TABLE t (v TEXT)")
    db.execute("INSERT INTO t VALUES (?)", (event["prompt"],))


def test_plain_text_is_unchanged():
    event = {"prompt": "naïve café 😀", "tool_input": {"a": ["x", 1, None]}}
    assert harness._no_surrogates(event) == event


@pytest.mark.parametrize("reply", ["[]", "null", '{"choices": null}', '{"choices": [{"message": "text"}]}', '{"message": 3}'])
def test_judge_reply_of_wrong_shape_is_no_opinion(monkeypatch, reply):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(reply.encode()))
    message, error = judge.post_chat_message("http://localhost:1/v1/chat/completions", "", {"model": "m"}, 1, 0)
    assert message is None and error
    assert judge.post_chat("http://localhost:1/v1/chat/completions", "", {"model": "m"}, 1, 0)[0] is None


def test_env_file_with_export_and_bad_bytes(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"export ZZ_EXPORTED_KEY=abc\nZZ_BAD=\xff\xfe\nZZ_PLAIN = 'v'\n")
    for key in ("ZZ_EXPORTED_KEY", "ZZ_BAD", "ZZ_PLAIN"):
        monkeypatch.delenv(key, raising=False)
        monkeypatch.setitem(os.environ, key, "")
        monkeypatch.delenv(key)
    harness.load_env_file(path)
    assert os.environ["ZZ_EXPORTED_KEY"] == "abc" and os.environ["ZZ_PLAIN"] == "v" and "ZZ_BAD" in os.environ


@pytest.mark.parametrize("name", [".env.example", "app/.env.sample", ".env.template", ".env.dist"])
def test_env_templates_are_not_secrets(name):
    assert not shell.SECRET.search(name)


@pytest.mark.parametrize("name", [".env", "app/.env", ".env.local", ".env.production"])
def test_env_files_are_still_secrets(name):
    assert shell.SECRET.search(name)
