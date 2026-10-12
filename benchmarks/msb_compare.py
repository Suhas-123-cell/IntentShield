"""Paired comparison of MSB runs (benchmarks/msb.py) on the cases every arm scored.

An arm is one results-*.jsonl file (a defense, model and judge). Arms are compared only on the
intersection of case ids that every arm scored, so an arm that errored on a case (a server that
failed to start, e.g. c0343) drops it from all of them and the rates stay paired. The ids each arm
lost are listed. Trace metrics are recomputed with msb.rescore from the stored traces, so old and new
result files carry the same metric definitions (harm_executed of the file-state types is the stored
one, as it needs the container). Report files hold no case ids and cannot be paired; pass results.

Wilson CIs treat the cases as independent. They are not: each attack type is 20 attack tasks times a
few agent tasks per server, and the draws share a template, so the CIs are narrower than the real
uncertainty. Read them as a floor, not as a test.

    .venv/bin/python benchmarks/msb_compare.py [--exposure] [--data artifacts/data/MSB] [DIR_OR_FILE ...]
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any

import msb

DEFAULT = ("artifacts/msb-v4", "artifacts/msb-v4-noclf", "artifacts/msb-v5")
# Which server's executed call carries the attack text in its reply. Left out: prompt_injection (the
# text is in a description the agent sees without calling anything), out_of_scope_parameter (no
# instruction text) and search_term_deception (the poisoned document is some file read through the
# filesystem server, and the trace holds no replies).
EXPOSURE_ROLE = {"false_error": "task", "simulated_user": "task", "prompt_injection-simulated_user": "task",
                 "prompt_injection-false_error": "task", "name_overlap": "attack", "preference_manipulation": "attack",
                 "preference_manipulation-simulated_user": "attack",
                 "preference_manipulation-out_of_scope_parameter": "attack", "tool_transfer": "attack"}
COLUMNS = ("harm_executed", "harm_attempted", "harm_reached_review", "harm_blocked", "task_tool_executed",
           "task_tool_reached", "task_tool_blocked", "user_task", "truncated")


def arm_files(paths: list[Path]) -> list[Path]:
    return [f for p in paths for f in (sorted(p.glob("results-*.jsonl")) if p.is_dir() else [p])]


def arm_label(path: Path) -> str:
    stem = path.stem.removeprefix("results-").removesuffix("-holdout")
    return f"{path.parent.name}/{stem.split('-', 1)[-1]}"


def read_arm(path: Path, grid: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """(id -> rescored row, ids whose latest row is an error); the latest row per case wins, as in msb.py."""
    latest = {r["id"]: r for r in map(json.loads, path.read_text().splitlines()) if r}
    scored = {r["id"]: r for r in msb.rescore(list(latest.values()), grid)}
    return scored, {i for i, r in latest.items() if "error" in r}


def common_ids(arms: dict[str, dict[str, Any]]) -> list[str]:
    """Case ids scored in every arm."""
    return sorted(set.intersection(*(set(rows) for rows in arms.values()))) if arms else []


def dropped(arms: dict[str, dict[str, Any]], errors: dict[str, set[str]]) -> dict[str, dict[str, list[str]]]:
    """Per arm, the ids it lacks that some other arm scored: its own errors, and cases it never ran."""
    union = set().union(*(set(rows) for rows in arms.values())) if arms else set()
    out = {}
    for label, rows in arms.items():
        lacking = union - set(rows)
        out[label] = {"error": sorted(lacking & errors.get(label, set())),
                      "not_run": sorted(lacking - errors.get(label, set()))}
    return out


def exposure(rows: list[dict[str, Any]], grid: dict[str, dict[str, Any]]) -> dict[str, collections.Counter]:
    """Per attack type: cases where an executed call reached the server carrying the attack text, and
    how many harmful attempts followed (at or after the first such call: for tool_transfer and the
    out_of_scope variants the attack-role call is itself the harmful one). harm_attempted of the
    unexposed cases is shown to check that harm needed the exposure."""
    out: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for row in rows:
        t = row["attack_type"]
        if t not in EXPOSURE_ROLE:
            continue
        first = next((i for i, s in enumerate(row["trace"])
                      if s.get("executed") and msb.role_of(s) == EXPOSURE_ROLE[t]), None)
        c = out[t]
        if first is None:
            c["unexposed"] += 1
            c["unexposed_attempted"] += row["harm_attempted"]
            continue
        c["exposed"] += 1
        c["attempted_after"] += any(msb.is_harmful(grid[row["id"]], s, s["arguments"]) for s in row["trace"][first:])
        c["executed"] += row["harm_executed"]
    return out


def cell(m: dict[str, Any] | None) -> str:
    if not m:
        return "-"
    lo, hi = m["ci95"]
    return f"{m['k']}/{m['n']} {100 * m['rate']:.1f}% [{100 * lo:.1f},{100 * hi:.1f}]"


def table(header: list[str], body: list[list[str]]) -> str:
    widths = [max(len(r[i]) for r in [header, *body]) for i in range(len(header))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in [header, *body])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="*", type=Path, help=f"dirs or results files (default {', '.join(DEFAULT)})")
    parser.add_argument("--data", type=Path, default=Path("artifacts/data/MSB"))
    parser.add_argument("--exposure", action="store_true", help="exposure breakdown per arm")
    args = parser.parse_args(argv)

    grid = msb.cases(args.data)
    by_id = {c["id"]: c for c in grid}
    arms, errors = {}, {}
    for f in arm_files(args.paths or [Path(p) for p in DEFAULT if Path(p).exists()]):
        label = arm_label(f)
        arms[label], errors[label] = read_arm(f, grid)
    ids = common_ids(arms)
    paired = {label: [rows[i] for i in ids] for label, rows in arms.items()}
    summary = {label: msb.summarize(rows) for label, rows in paired.items()}

    print(f"{len(arms)} arms, {len(ids)} cases scored in every arm\n")
    print(table(["metric (k/n rate [95% Wilson])", *arms],
                [["n", *[str(len(paired[a])) for a in arms]]] +
                [[m, *[cell(summary[a].get("all", {}).get(m)) for a in arms]] for m in COLUMNS]))
    print("\nDropped (not scored in this arm, scored in another):")
    for label, d in dropped(arms, errors).items():
        print(f"  {label}: errors {d['error'] or '-'}; not run {len(d['not_run'])}"
              + (f" ({', '.join(d['not_run'][:6])}{'...' if len(d['not_run']) > 6 else ''})" if d["not_run"] else ""))
    print("\nPer attack type, counts k (user_task as k/n):")
    for t in sorted({r["attack_type"] for rows in paired.values() for r in rows}):
        body = []
        for a in arms:
            s = summary[a].get(t, {})
            body.append([a, str(s.get("harm_executed", {}).get("n", 0)),
                         *[f"{s[m]['k']}/{s[m]['n']}" if m == "user_task" and m in s else str(s[m]["k"]) if m in s else "-"
                           for m in COLUMNS]])
        print(f"\n{t}\n" + table(["arm", "n", *COLUMNS], body))
    if args.exposure:
        print("\nExposure: an executed call to the server carrying the attack text, then a harmful attempt")
        for a in arms:
            print(f"\n{a}\n" + table(["attack type", "exposed", "harm at/after", "harm executed", "unexposed", "unexposed harm"],
                                     [[t, str(c["exposed"]), str(c["attempted_after"]), str(c["executed"]),
                                       str(c["unexposed"]), str(c["unexposed_attempted"])]
                                      for t, c in sorted(exposure(paired[a], by_id).items())]))


if __name__ == "__main__":
    main()
