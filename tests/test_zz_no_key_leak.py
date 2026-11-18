"""A judge key set by one test must not reach the next test or outlive the run.

Two guards in conftest.py do that: the autouse fixture deletes every judge key before each test (and its monkeypatch puts the
original state back afterwards), and ``pytest_sessionfinish`` fails the run when a key differs from what it was when the session
began. The tests here show that each guard works; checking the environment from inside a test cannot, because the fixture has
already deleted the keys by then.
"""
import os
from types import SimpleNamespace

import conftest
from conftest import _JUDGE_KEYS, _KEYS_AT_START

_WROTE: list[str] = []


def test_a_test_may_write_a_judge_key_into_the_environment():
    for name in _JUDGE_KEYS:
        os.environ[name] = "written-by-a-test"  # by assignment, not through monkeypatch
        _WROTE.append(name)
    assert all(os.environ[name] == "written-by-a-test" for name in _JUDGE_KEYS)


def test_the_next_test_does_not_see_that_key():
    if not _WROTE:  # run alone or on another worker: no earlier test in this process wrote one
        return
    assert all(os.environ.get(name) is None for name in _JUDGE_KEYS)


def test_the_session_fails_when_a_judge_key_was_changed_and_not_restored(monkeypatch, capsys):
    monkeypatch.setenv(_JUDGE_KEYS[0], "left-behind")
    session = SimpleNamespace(exitstatus=0)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 1
    assert f"{_JUDGE_KEYS[0]}" in capsys.readouterr().out


def test_the_session_passes_when_every_judge_key_is_as_it_was(monkeypatch):
    for name, original in _KEYS_AT_START.items():
        if original is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, original)
    session = SimpleNamespace(exitstatus=0)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 0
