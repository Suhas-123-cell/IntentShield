#!/usr/bin/env python3
"""Which harmful fixtures have their defining string in this repository's tests or source, and what the 214-call comparison
says without them. It does the same for the 467-fixture set's before and after figures for the built-in tool rules.

The two detection fixture sets were declared "held out": an item's command or path was not in IntentShield's repository text
when the set was built. The unit tests of the dangerous-command rules were written afterwards and contain some of the same
strings (canonical dangerous commands such as `rm -rf /` or `git push --force`; the rules were written from category lists, so
this may be coincidence). This script counts the overlap with a plain substring match and rescores the 214-call set without the
overlapping items, and the 467-fixture set's before and after figures without its overlapping items, so a reader can see how
much each comparison depends on them. `overlap_items.json` pins the items found at commit 1979d0e, which the report quotes; the
script lists any item the current tree no longer matches.

    overlap_check.py [--roots tests src] [--json]

Everything is derived from the committed fixtures and decisions; no guard is run and nothing is written. A short string
(`package.json`, `~/.bashrc`) matches by chance, so the match is a bound on the overlap, not a measure of leakage.
"""
# ruff: noqa: E501
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fresh_report as fr  # noqa: E402
import report_numbers as rn  # noqa: E402

ROOT = HERE.parents[1]
DETECT = ROOT / "results" / "hook-fidelity" / "detect"
TOOL_KINDS = ("shell", "read", "write", "edit")
MIN_LENGTH = 6   # shorter strings match anything
PINNED = json.loads((HERE / "overlap_items.json").read_text())


def defining_string(row: dict) -> str | None:
    """The command, or the path of a file tool, that makes the item what it is."""
    tool_input = row["payload"].get("tool_input") or row["payload"].get("toolArgs") or {}
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            return tool_input or None
    if not isinstance(tool_input, dict):
        return None
    for key in ("command", "file_path", "path", "url"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def repository_text(roots: list[str]) -> str:
    """The Python files under ``roots``, with escaped quotes also unescaped so a string in a test literal matches."""
    parts = []
    for root in roots:
        for path in sorted((ROOT / root).rglob("*.py")):
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(parts)
    return text + "\n" + text.replace('\\"', '"').replace("\\'", "'")


def overlapping_items(rows: list[dict], text: str) -> dict[str, str]:
    """item id -> defining string, for the primary harmful built-in-tool items whose defining string is in ``text``."""
    found: dict[str, str] = {}
    for row in rows:
        if not (row["primary"] and row["label"] == "harmful" and row["heldout"] and row["tool_kind"] in TOOL_KINDS):
            continue
        string = defining_string(row)
        if string and len(string) >= MIN_LENGTH and string in text:
            found[row["item_id"]] = string
    return found


def harmful_item_count(rows: list[dict]) -> int:
    return len({r["item_id"] for r in rows if r["primary"] and r["label"] == "harmful" and r["heldout"] and r["tool_kind"] in TOOL_KINDS})


def rescored(excluded: set[str]) -> dict:
    """The 214-call set's headline figures without the items in ``excluded``."""
    rows = [r for r in fr.load_fixtures() if r["item_id"] not in excluded]
    decisions = [json.loads(line) for line in (fr.FRESH / "decisions.jsonl").read_text().splitlines()]
    delivery = json.loads((DETECT / "r8fix" / "delivery.json").read_text())
    _, summary = fr.build_report(rows, decisions, delivery)
    out: dict = {"n_harmful": summary["n_harmful"], "n_benign": summary["n_benign"]}
    harmful = summary["by_guard"][fr.IS]["harmful"]["all_run"]
    out["intentshield_all_items"] = {"let_through": harmful["false_allow"]["k"], "n": harmful["n"], "ask": harmful["ask"], "deny": harmful["deny"]}
    for guard in fr.COMPARE_ON_SCOPE:
        same = summary["same_items"][guard]
        theirs, ours = same[guard], same[fr.IS]
        out[guard] = {"n": same["harmful_n"],
                      "guard": {"let_through": theirs["false_allow"]["k"], "deny": theirs["deny"]},
                      "intentshield_on_the_same_items": {"let_through": ours["false_allow"]["k"], "ask": ours["ask"], "deny": ours["deny"]}}
    return out


def rescored_467(excluded: set[str] | frozenset[str]) -> dict:
    """The 467-fixture set's harmful held-out figures, IntentShield before and after the built-in tool rules, without ``excluded``."""
    return rn.rules_before_after(excluded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--roots", nargs="+", default=["tests", "src"], help="directories under the repository root to search (default: tests src)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)
    text = repository_text(args.roots)
    result: dict = {"roots": args.roots}
    for name, path in (("fresh_214_call_set", fr.FRESH / "fixtures.jsonl"), ("fixtures_467_set", DETECT / "fixtures.jsonl")):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        found = overlapping_items(rows, text)
        result[name] = {"harmful_items": harmful_item_count(rows), "overlapping": len(found), "items": found}
    excluded = set(result["fresh_214_call_set"]["items"])
    result["fresh_without_overlap"] = rescored(excluded)
    result["fresh_with_all_items"] = rescored(set())
    pinned_467 = set(PINNED["fixtures_467_set"])
    result["fixtures_467_with_all_items"] = rescored_467(set())
    result["fixtures_467_without_overlap"] = rescored_467(pinned_467)
    result["pinned_items_missing_now"] = sorted((pinned_467 | set(PINNED["fresh_214_call_set"])) - set(result["fixtures_467_set"]["items"]) - set(result["fresh_214_call_set"]["items"]))
    if args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0
    for name in ("fresh_214_call_set", "fixtures_467_set"):
        block = result[name]
        print(f"{name}: {block['overlapping']} of {block['harmful_items']} declared-held-out harmful built-in-tool items have their command or path in {', '.join(args.roots)}")
    print()
    for label in ("fresh_with_all_items", "fresh_without_overlap"):
        block = result[label]
        i = block["intentshield_all_items"]
        print(f"{label} ({block['n_harmful']} harmful items): IntentShield lets through {i['let_through']}/{i['n']}, asks {i['ask']}, denies {i['deny']}")
        for guard in fr.COMPARE_ON_SCOPE:
            g = block[guard]
            print(f"    on {guard}'s scope ({g['n']} items): {guard} lets through {g['guard']['let_through']}, denies {g['guard']['deny']}; "
                  f"IntentShield lets through {g['intentshield_on_the_same_items']['let_through']}, denies {g['intentshield_on_the_same_items']['deny']}")
    print()
    names = (("held", "items that stayed held out"), ("declared", "items declared held out"), ("builtin", "built-in tool calls"))
    for label in ("fixtures_467_with_all_items", "fixtures_467_without_overlap"):
        for key, text in names:
            b = result[label][key]
            print(f"{label}, {b['n']} {text}: IntentShield lets through {b['before']} before the rules and {b['after']} after")
    if result["pinned_items_missing_now"]:
        print("pinned items whose string is no longer in the tree:", ", ".join(result["pinned_items_missing_now"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
