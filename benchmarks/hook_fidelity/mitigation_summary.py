"""Summarise the held-out translation evaluation (mitigation_eval.py rows) as k/n tables.

    python benchmarks/hook_fidelity/mitigation_summary.py RUNS.jsonl [--fit-only RANGES.json] [--json OUT.json]

Per harness build and scenario: the outcomes of translation OFF and ON (n runs each). Headlines, all as k/n over runs:
  * off RAN or HUNG and on BLOCKED (the translation changed the outcome from an unguarded call or a hang to a refusal),
  * off BLOCKED and on RAN or HUNG (a regression: the translation made a call that was refused run or wait),
  * both BLOCKED (nothing to fix: the harness already honoured the verdict, or the old mapping already refused it),
  * INVALID (excluded from every rate, listed with its reason).
And a check of the table itself: for each held-out build, what the fit-only ranges predicted the OFF arm would do for ``ask``
(and for a hook that cannot start) against what it did. A build between two measured releases of different class has no
prediction (class "uncertain") and is listed as such. Wilson 95% bounds are computed here, at display, from k and n.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = {"ask": 0, "deny": 1, "timeout": 2, "dead": 3}
PREDICTED_OFF = {"ask": {"dropped": "RAN", "denied": "BLOCKED", "hangs": "HUNG"}, "dead": {"runs": "RAN", "blocks": "BLOCKED"}}


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} (95% Wilson {lo * 100:.0f} to {hi * 100:.0f}%)"


def vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".")[:3])


def span_class(spans: list[list[str]], version: str) -> str:
    v = vkey(version)
    for kind, lo, hi, cls in spans:
        if kind == "run" and vkey(lo) <= v <= vkey(hi):
            return cls
        if kind == "gap" and vkey(lo) < v < vkey(hi):
            return cls
    if spans and spans[-1][0] == "run" and v > vkey(spans[-1][2]):
        return spans[-1][3]
    return "unmeasured"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def summarize(rows: list[dict], fit_only: dict | None = None) -> dict:
    cells: dict[tuple, dict[str, list[str]]] = defaultdict(lambda: {"off": [], "on": []})
    invalid = []
    for r in rows:
        if r["outcome"] == "INVALID":
            invalid.append({k: r.get(k) for k in ("harness", "version", "scenario", "arm", "rep", "invalid_reason")})
            continue
        cells[(r["harness"], r["version"], r["scenario"])][r["arm"]].append(r["outcome"])
    changed = defaultdict(lambda: [0, 0])      # harness -> [k, n] over (off, on) pairs where off was RAN or HUNG
    regress = defaultdict(lambda: [0, 0])
    both = defaultdict(lambda: [0, 0])
    by_scenario = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for (harness, _version, scenario), arms in cells.items():
        for off, on in zip(sorted(arms["off"]), sorted(arms["on"])):
            if off in ("RAN", "HUNG"):
                changed[harness][1] += 1
                changed[harness][0] += on == "BLOCKED"
                by_scenario[harness][scenario][1] += 1
                by_scenario[harness][scenario][0] += on == "BLOCKED"
            if off == "BLOCKED":
                regress[harness][1] += 1
                regress[harness][0] += on in ("RAN", "HUNG")
            if off == "BLOCKED" and on == "BLOCKED":
                both[harness][0] += 1
            both[harness][1] += 1
    check = []
    if fit_only:
        ordered = sorted(cells.items(), key=lambda kv: (kv[0][0], vkey(kv[0][1]), ORDER[kv[0][2]]))
        for (harness, version, scenario), arms in ordered:
            feature = {"ask": "ask", "dead": "dead"}.get(scenario)
            known = fit_only.get(harness, {}).get("ranges", {})
            if not feature or feature not in known or (harness == "codex" and feature == "ask"):
                continue   # codex's old mapping already refused an ask: its OFF arm does not show what Codex does with one
            cls = span_class(fit_only[harness]["ranges"][feature], version)
            predicted = PREDICTED_OFF[feature].get(cls)
            observed = sorted(set(arms["off"]))
            check.append({"harness": harness, "version": version, "feature": feature, "class": cls, "predicted_off": predicted,
                          "observed_off": observed, "hit": None if predicted is None else observed == [predicted]})
    return {"cells": {f"{h}|{v}|{s}": arms for (h, v, s), arms in sorted(cells.items(), key=lambda kv: (kv[0][0], vkey(kv[0][1]),
                                                                                                          ORDER[kv[0][2]]))},
            "changed_off_ran_or_hung_to_blocked": {h: {"k": k, "n": n} for h, (k, n) in changed.items()},
            "by_scenario": {h: {s: {"k": k, "n": n} for s, (k, n) in d.items()} for h, d in by_scenario.items()},
            "regressions_off_blocked_to_ran_or_hung": {h: {"k": k, "n": n} for h, (k, n) in regress.items()},
            "both_blocked_of_all_pairs": {h: {"k": k, "n": n} for h, (k, n) in both.items()},
            "invalid": invalid, "table_check": check}


def markdown(summary: dict) -> str:
    out = ["| harness | build | scenario | translation off | translation on |", "|---|---|---|---|---|"]
    for key, arms in summary["cells"].items():
        harness, version, scenario = key.split("|")
        count = lambda xs: ", ".join(f"{o} {xs.count(o)}/{len(xs)}" for o in dict.fromkeys(xs)) or "-"  # noqa: E731
        out.append(f"| {harness} | {version} | {scenario} | {count(arms['off'])} | {count(arms['on'])} |")
    out += ["", "Changed from RAN or HUNG (off) to BLOCKED (on), paired runs:"]
    for h, d in summary["changed_off_ran_or_hung_to_blocked"].items():
        out.append(f"- {h}: {rate(d['k'], d['n'])}; by scenario: " + ", ".join(
            f"{s} {rate(x['k'], x['n'])}" for s, x in summary["by_scenario"].get(h, {}).items()))
    out += ["", "Regressions (off BLOCKED, on RAN or HUNG):"]
    out += [f"- {h}: {rate(d['k'], d['n'])}" for h, d in summary["regressions_off_blocked_to_ran_or_hung"].items()]
    out += ["", "INVALID runs (excluded from every rate):"]
    out += [f"- {i['harness']} {i['version']} {i['scenario']} {i['arm']} #{i['rep']}: {i['invalid_reason']}"
            for i in summary["invalid"]]
    if summary["table_check"]:
        out += ["", "Fit-only table against the held-out builds (translation OFF arm):", "",
                "| harness | build | feature | class from fit-only ranges | predicted off | observed off | hit |",
                "|---|---|---|---|---|---|---|"]
        for c in summary["table_check"]:
            hit = f"no prediction (class {c['class']})" if c["hit"] is None else ("yes" if c["hit"] else "NO")
            out.append(f"| {c['harness']} | {c['version']} | {c['feature']} | {c['class']} | {c['predicted_off'] or '-'} | "
                       f"{'/'.join(c['observed_off'])} | {hit} |")
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rows", type=Path)
    parser.add_argument("--fit-only", type=Path, help="ranges-fit-only.json, to check the table against the held-out builds")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    summary = summarize(load(args.rows), json.loads(args.fit_only.read_text()) if args.fit_only else None)
    if args.json:
        args.json.write_text(json.dumps(summary, indent=1))
    print(markdown(summary))


if __name__ == "__main__":
    main()
