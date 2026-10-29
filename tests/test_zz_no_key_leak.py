"""Runs last (alphabetical): no earlier test may have left a judge key in the environment. The
conftest strips the keys for every test and restores their original state afterwards."""
import os

from conftest import _JUDGE_KEYS, _KEYS_AT_START


def test_no_judge_key_leaked_from_earlier_tests():
    # Inside a test the conftest has deleted every key; this checks the restore of the previous
    # test did not bring back a value that was not there when the session started.
    assert all(os.environ.get(name) is None for name in _JUDGE_KEYS)
    assert set(_KEYS_AT_START) == set(_JUDGE_KEYS)
