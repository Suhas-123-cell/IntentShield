"""The pack and learned-rule safety gate refuses adjacent repeats of the same characters (rules-17)."""
from __future__ import annotations

import pytest

from intentshield import rule_packs
from intentshield.rule_packs import compile_pack
from intentshield.signatures import safety_problem

LEAD = r"ignore previous instructions"
POLYNOMIAL = [
    r"\d+\d+\d+\d+!", r"\d*\d*\d*\d*\d*x", r"[\s\d]+[\d\s]+x", r"(?:\d+\.)?\d+(?:\d+\.)?\d+x", r"\d+\s*\d+x",
    r"\w+\w+x", r"\d{0,150}\d{0,150}\d{0,150}x", r"\d+\s*\s*\d+x",
    # the same, with the repeats in capturing groups
    r"(\d+)(\d+)(\d+)(\d+)!", r"\d+(\d+)\d+!", r"(\d+)\d+(\d+)!", r"\d+(\d)+\d+!", r"\d+(\d*)\d+!",
    r"(?P<a>\d+)(?P<b>\d+)(?P<c>\d+)!", r"(\d+)\s?(\d+)\s?(\d+)!", r"((\d+)(\d+))\d+!",
]
LINEAR = [
    r"\s+\d+\s+files\s+to\s+the\s+vendor", r"\s+(\w+\s){3}customer\s+list", r"\s+(?:all\s+)?previous\s+instructions\s*\w*",
    r"\d{1,3}\d{1,3}x", r"\d+\s+\d+x", r"\d+\.\d+\.\d+x", r"\s+\w{0,200}\w{0,200}x",
    r"(\d+)\s+(\d+)x", r"(\d+)\.(\d+)\.(\d+)x", r"(all\s+)?previous(\s+instructions)?", r"(\w+)\s+(\d+)x",
    r"\s+\s+\s+\s+x", r"\s*\s*\s*\s*x", r"share\s+the\s+[\w\s]+?with\s+the",  # whitespace is collapsed first
]


@pytest.mark.parametrize("tail", POLYNOMIAL)
def test_a_pattern_with_adjacent_repeats_of_one_character_class_is_refused(tail):
    assert "adjacent repeats" in safety_problem(LEAD + tail)


@pytest.mark.parametrize("tail", LINEAR)
def test_ordinary_patterns_with_several_repeats_are_still_accepted(tail):
    assert safety_problem(LEAD + tail) is None


def test_a_pack_with_such_a_rule_loses_that_rule_only():
    good = {"id": "good", "pattern": r"\bwire\s+(?:the|all)\s+(?:quarterly|pending)\s+(?:payments?|transfers?)\s+to\s+"
                                     r"(?:the\s+)?new\s+beneficiary\b"}
    bad = {"id": "bad", "pattern": LEAD + r"\d+\d+\d+\d+!"}
    loaded = compile_pack({"format": rule_packs.FORMAT, "name": "t", "version": 1, "rules": [bad, good],
                           "indicators": [], "fingerprints": [], "benign": []}, "hmac:default")
    assert [r[0] for r in loaded.rules] == ["good"] and "adjacent repeats" in loaded.rejected[0]["reason"]


@pytest.mark.parametrize("tail", [r"(?:x?x?x?)+y", r"(?:\d\d?)+!", r"(?:\d\d?){2,}!", r"(?:\w\w?)+!", r"(?:x?)+y", r"(?:ab?)+c",
                                  r"(?:x?x?){2,}y"])
def test_a_repeated_group_of_optional_items_is_refused(tail):
    assert safety_problem("ignore previous instructions" + tail) == "optional items in a repeated group"


@pytest.mark.parametrize("pattern", [
    r"ignore (?:all |any )?previous instructions", r"ignore\s+(?:the\s+)?previous\s+instructions",
    r"ignore (?:\w+\s){3}instructions", r"ignore previous instructions(?:s)?", r"ignore previous instructions\s*(?:now)?",
])
def test_optional_items_outside_a_repeat_are_still_accepted(pattern):
    assert safety_problem(pattern) is None
