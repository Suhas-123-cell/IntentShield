"""Every MSB number the papers cite, recomputed from the raw results in results/msb.

One command, no Docker or model: it reads the stored traces, rescores them with msb.rescore (the same
metric code for every arm), pairs each model's arms on the cases all of them scored, and prints the
tables, paired cluster-bootstrap differences, review load and the Gemini breakdown. Write the paper
from this output, and rerun it after any change to results/ or to the metric code.

    .venv/bin/python benchmarks/paper_numbers.py [--results results/msb] [--bootstrap 2000]

Layout: results/msb/<model>/<arm>.jsonl, arms none, baseline, gateway (intent model off), hooks
(intent off), and optional gateway-intent-veto, gateway-intent-advisory, gateway-prompt-guard.
results/msb/MANIFEST.json lists each file's source run, commit and sha256; this script checks them.
The case grid comes from the MSB checkout (--data) when it is present, else from results/msb/cases.jsonl,
the same grid written out, so a clean clone needs nothing outside results/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import msb
import msb_compare

MAIN_ARMS = ("none", "baseline", "gateway", "hooks")
EXTRA_ARMS = ("gateway-intent-veto", "gateway-intent-advisory", "gateway-prompt-guard")
# Attack types whose payload is injected text; the other three only ask for the model name in a schema.
NO_INSTRUCTION = {"out_of_scope_parameter", "preference_manipulation-out_of_scope_parameter", "tool_transfer"}


def pct(k: int, n: int) -> str:
    return f"{100 * k / n:.1f}" if n else "-"


def kn(m: dict[str, Any]) -> str:
    """k/n and the rate, formatted from the counts at print time (never pre-rounded)."""
    return f"{m['k']}/{m['n']} {pct(m['k'], m['n'])}%"


def reviews(row: dict[str, Any], benign_only: dict[str, dict[str, Any]] | None = None) -> int:
    """Calls held for a human; with the case grid, only those that are not harmful."""
    return sum(s.get("decision") == "REVIEW" and not (
        benign_only and msb.is_harmful(benign_only[row["id"]], s, s["arguments"])) for s in row["trace"])


def self_disclosure(row: dict[str, Any]) -> bool:
    """Executed harm through a filled model-name field, on what reached the server."""
    return any(s.get("executed") and any(k in msb.MODEL_NAME_ARGS and str(v).strip()
                                         for k, v in s.get("sent", s["arguments"]).items()) for s in row["trace"])


def load_cases(path: Path) -> list[dict[str, Any]]:
    """The MSB case grid as msb.cases builds it, stored one case per line."""
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def check_manifest(root: Path) -> list[str]:
    manifest = json.loads((root / "MANIFEST.json").read_text())
    problems = []
    for rel, entry in manifest["files"].items():
        path = root / rel
        if not path.exists():
            problems.append(f"missing {rel}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            problems.append(f"sha256 mismatch {rel}")
    on_disk = {str(p.relative_to(root)) for p in root.glob("*/*.jsonl")}
    problems += [f"not in manifest {rel}" for rel in sorted(on_disk - set(manifest["files"]))]
    return problems


def model_report(model_dir: Path, grid: list[dict[str, Any]], reps: int) -> dict[str, Any]:
    """Prints the model's tables; returns its headline cells: paired n of the main arms, each main
    arm's msb.summarize counts, and the gateway minus baseline user_task difference (a fraction)."""
    by_id = {c["id"]: c for c in grid}
    arms = {}
    for arm in (*MAIN_ARMS, *EXTRA_ARMS):
        path = model_dir / f"{arm}.jsonl"
        if path.exists():
            arms[arm], _ = msb_compare.read_arm(path, grid)
    # The main table pairs the four main arms; the extra arms are compared on the cases all arms share.
    main_ids = msb_compare.common_ids({a: arms[a] for a in MAIN_ARMS if a in arms})
    all_ids = msb_compare.common_ids(arms)
    lost = {a: sorted(set().union(*map(set, arms.values())) - set(rows)) for a, rows in arms.items()}
    print(f"\n## {model_dir.name}, arms {', '.join(arms)}")
    print("not scored per arm (errors, agent timeouts):", {a: v for a, v in lost.items() if v} or "none")
    for title, ids, names in (("main arms", main_ids, [a for a in MAIN_ARMS if a in arms]),
                              ("all arms", all_ids, list(arms))):
        if title == "all arms" and len(names) == len([a for a in MAIN_ARMS if a in arms]):
            continue
        paired = {a: [arms[a][i] for i in ids] for a in names}
        n = len(ids)
        ut_n = sum(r["user_task"] is not None for r in paired[names[0]])
        print(f"\n### {title}: {n} paired cases (user_task n={ut_n})")
        print("\n| arm | H executed | attempted | R reached review | blocked | rewritten | task tool blocked "
              "| U user task | reviews/case | benign reviews/case |")
        print("|---|---|---|---|---|---|---|---|---|---|")
        for a, rows in paired.items():
            k = {m: sum(bool(r[m]) for r in rows) for m in msb_compare.COLUMNS}
            u = [r["user_task"] for r in rows if r["user_task"] is not None]
            print(f"| {a} | {pct(k['harm_executed'], n)} | {pct(k['harm_attempted'], n)} ({k['harm_attempted']}) "
                  f"| {pct(k['harm_reached_review'], n)} ({k['harm_reached_review']}) | {k['harm_blocked']} "
                  f"| {k['harm_rewritten']} | {pct(k['task_tool_blocked'], n)} | {pct(sum(u), len(u))} ({sum(u)}/{len(u)}) "
                  f"| {sum(reviews(r) for r in rows) / n:.2f} | {sum(reviews(r, by_id) for r in rows) / n:.2f} |")
        # The same arms as k/n: harm executed with its Wilson bounds (the only interval a rate of 0 has),
        # and the two columns the README takes from msb_compare.py.
        print("\n| arm | harm executed k/n [95% Wilson] | task tool executed k/n | truncated k/n |")
        print("|---|---|---|---|")
        for a, rows in paired.items():
            s = msb.summarize(rows)["all"]
            print(f"| {a} | {msb_compare.cell(s['harm_executed'])} | {kn(s['task_tool_executed'])} "
                  f"| {kn(s['truncated'])} |")
        if reps:
            for first in ("baseline", "gateway"):
                order = {first: paired[first], **{a: r for a, r in paired.items() if a != first}}
                _, diff = msb_compare.cluster_bootstrap(order, by_id, reps)
                print(f"\nuser_task difference from {first}, points [95% paired cluster bootstrap, {reps} resamples]")
                for a, d in diff.items():
                    v, lo, hi = d["user_task"]
                    print(f"  {a:26} {100 * v:+.1f} [{100 * lo:+.1f}, {100 * hi:+.1f}]")

    paired = {a: [arms[a][i] for i in main_ids] for a in MAIN_ARMS if a in arms}
    if "none" in paired:
        rows = paired["none"]
        harmed = [r for r in rows if r["harm_executed"]]
        sd = sum(map(self_disclosure, harmed))
        injected = [r for r in rows if r["attack_type"] not in NO_INSTRUCTION]
        followed = sum(r["harm_executed"] and not self_disclosure(r) for r in injected)
        print(f"\nundefended: {len(harmed)} harmful cases, {sd} self-disclosure; followed injected text in "
              f"{followed} of {len(injected)} injected-text cases")
    summary = {a: msb.summarize(rows)["all"] for a, rows in paired.items()}
    diff = (summary["gateway"]["user_task"]["rate"] - summary["baseline"]["user_task"]["rate"]
            if {"baseline", "gateway"} <= set(summary) else None)
    return {"paired_n": len(main_ids), "arms": summary, "user_task_gateway_minus_baseline": diff}


def headline(models: dict[str, dict[str, Any]]) -> list[str]:
    """The strings the README quotes: paired n per model and the gateway minus baseline user_task
    range across the agents (points, from the unrounded differences)."""
    diffs = {m: h["user_task_gateway_minus_baseline"] for m, h in models.items()
             if h["user_task_gateway_minus_baseline"] is not None}
    lines = ["paired cases per model (main arms): " + ", ".join(f"{m} {h['paired_n']}" for m, h in models.items())]
    if diffs:
        sizes = [abs(100 * d) for d in diffs.values()]
        lines.append("user_task, gateway minus baseline, points: "
                     + ", ".join(f"{m} {100 * d:+.1f}" for m, d in diffs.items())
                     + f"; range {min(sizes):.0f}\u2013{max(sizes):.0f} points across {len(diffs)} agents")
    return lines


def main(argv: list[str] | None = None) -> dict[str, dict[str, Any]]:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--results", type=Path, default=Path("results/msb"))
    parser.add_argument("--data", type=Path, default=Path("artifacts/data/MSB"),
                        help="MSB checkout for the case grid; when absent, --cases is read instead")
    parser.add_argument("--cases", type=Path, default=None, help="stored case grid (default <results>/cases.jsonl)")
    parser.add_argument("--bootstrap", type=int, default=2000)
    args = parser.parse_args(argv)
    problems = check_manifest(args.results)
    print("manifest:", "ok" if not problems else "; ".join(problems))
    grid = msb.cases(args.data) if args.data.exists() else load_cases(args.cases or args.results / "cases.jsonl")
    models = {model_dir.name: model_report(model_dir, grid, args.bootstrap)
              for model_dir in sorted(p for p in args.results.iterdir() if p.is_dir())}
    print("\n## headline")
    print("\n".join(headline(models)))
    if problems:
        raise SystemExit(1)
    return models


if __name__ == "__main__":
    main()
