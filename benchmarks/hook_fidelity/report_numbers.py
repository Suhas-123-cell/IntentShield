#!/usr/bin/env python3
"""Every number in docs/hook-fidelity-report.md, recomputed from the committed rows. No harness, no model, no network.

    .venv/bin/python benchmarks/hook_fidelity/report_numbers.py            # print the version matrix and the finding lines
    .venv/bin/python benchmarks/hook_fidelity/report_numbers.py --json     # the same as JSON

Rules (the same as the study's, section 1): a count is k/n over the committed stub-arm rows (INVALID rows never counted); the
Wilson interval is computed here from k and n and never stored rounded. The stub is deterministic and each cell has n of 2 to 5,
so an interval on rows bounds repeatability, not a rate; the build counts are the better unit and are printed beside the
row counts.

A block of rows (harness, build, mode, trust state) enters the matrix only if its neutral control (R1) ran the hook in every valid
run; otherwise nothing was tested there (the study calls it CONFIG-INVALID) and the build is listed as excluded.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE.parents[1] / "results" / "hook-fidelity"

HARNESS_NAMES = {"claude": "Claude Code", "codex": "Codex CLI", "gemini": "Gemini CLI"}
# The mode and trust state each version sweep ran in, for shell commands: Claude `-p --allowedTools Bash` (M1h), Codex `exec`
# with hooks trusted (persisted trust, or the bypass flag where it works), Gemini `-p --approval-mode yolo` (M2).
SWEEP = {
    "claude": {"mode": "M1h", "states": {"-"}},
    "codex": {"mode": "M1", "states": {"trusted-bypass", "trusted-persisted"}},
    "gemini": {"mode": "M2", "states": {"-"}},
}
REPLIES = (
    ("R4", "deny"),
    ("R3", "ask, no human"),
    ("R9", "hook runs past its timeout"),
    ("R5", "empty reply, exit 0"),
    ("R6", "malformed JSON, exit 0"),
    ("R7", "exit 2 with stderr"),
    ("R8", "exit 1"),
    ("R10b", "interpreter missing"),
)


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} [{100 * lo:.1f}, {100 * hi:.1f}]%"


def vkey(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def read(*parts: str) -> list[dict]:
    path = RES.joinpath(*parts)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def stub_rows() -> list[dict]:
    """The 1342 committed stub rows of the three matrix lanes (the 8 Gemini smoke rows are left out)."""
    gemini = [r for d in ("main", "sweep", "enable-default") for r in read("gemini", d, "runs.jsonl")]
    return read("claude", "all-runs.jsonl") + read("codex", "runs.jsonl") + gemini


def sweep_rows(harness: str, rows: list[dict]) -> list[dict]:
    cfg = SWEEP[harness]
    out = [
        r
        for r in rows
        if r["harness"] == harness
        and r["kind"] == "shell"
        and r["mode"] == cfg["mode"]
        and r["state"] in cfg["states"]
        and r["failcfg"] == "-"
        and r["outcome"] != "INVALID"
    ]
    if harness == "claude":  # the round-4 bisect builds, same cell
        out += [
            r
            for r in read("claude", "r4-gaps", "bisect", "runs.jsonl")
            if r["kind"] == "shell" and r["mode"] == "M1h" and r["outcome"] != "INVALID"
        ]
    if harness == "codex":  # the two releases between the sampled 0.140.0 and 0.143.0
        out += [r for r in read("codex", "r4-integration", "bisect", "runs.jsonl") if r["outcome"] != "INVALID"]
    return out


def live_builds(harness: str, rows: list[dict]) -> tuple[list[str], list[str]]:
    """(builds whose neutral control ran the hook, builds excluded because it did not or was blocked)."""
    by = defaultdict(list)
    for r in sweep_rows(harness, rows):
        if r["reply"] == "R1":
            by[r["version"]].append(r)
    live = sorted((v for v, rs in by.items() if all(r["outcome"] == "RAN" and r["hook_invoked"] is True for r in rs)), key=vkey)
    return live, sorted(set(by) - set(live), key=vkey)


def outcome_by_build(harness: str, reply: str, rows: list[dict], live: list[str]) -> dict[str, str]:
    seen: dict[str, set[str]] = defaultdict(set)
    for r in sweep_rows(harness, rows):
        if r["reply"] == reply and r["version"] in live:
            seen[r["version"]].add(r["outcome"])
    return {v: "/".join(sorted(o)) for v, o in seen.items()}


def segments(per_build: dict[str, str]) -> list[tuple[str, str, str, int]]:
    segs: list[list] = []
    for v in sorted(per_build, key=vkey):
        if segs and segs[-1][0] == per_build[v]:
            segs[-1][2] = v
            segs[-1][3] += 1
        else:
            segs.append([per_build[v], v, v, 1])
    return [tuple(s) for s in segs]


def seg_text(seg: tuple[str, str, str, int]) -> str:
    outcome, first, last, n = seg
    span = first if first == last else f"{first} to {last}"
    return f"{outcome} {span} ({n} build{'s' if n != 1 else ''})"


def matrix(rows: list[dict]) -> dict:
    out: dict = {"rows": [], "excluded": {}}
    for h in HARNESS_NAMES:
        live, excluded = live_builds(h, rows)
        out["excluded"][h] = excluded
        for reply, label in REPLIES:
            per = outcome_by_build(h, reply, rows, live)
            if per:
                out["rows"].append(
                    {
                        "harness": h,
                        "reply": reply,
                        "label": label,
                        "builds": len(per),
                        "segments": [seg_text(s) for s in segments(per)],
                    }
                )
    return out


def matrix_md(m: dict) -> str:
    lines = ["| harness | hook reply | builds | outcome of the guarded shell command, by release |", "|---|---|---|---|"]
    for r in m["rows"]:
        lines.append(
            f"| {HARNESS_NAMES[r['harness']]} | {r['label']} ({r['reply']}) | {r['builds']} | {'; '.join(r['segments'])} |"
        )
    return "\n".join(lines)


LABELS = {"timeout": "hook runs past its timeout", "empty": "empty reply", "exit2": "exit 2", "dead": "interpreter missing"}


def findings(rows: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    # 1. deny
    r4 = [r for r in rows if r["reply"] == "R4"]
    ran = [r for r in r4 if r["hook_invoked"] is True]
    blocked = [r for r in ran if r["outcome"] == "BLOCKED"]
    skipped = [r for r in r4 if r["hook_invoked"] is False and r["outcome"] == "RAN"]
    by_cause = Counter(
        "Codex untrusted hook"
        if (r["harness"], r["state"]) == ("codex", "untrusted")
        else "Claude Code mcp__.* matcher on a resource read"
        if r["kind"] == "resource"
        else "Gemini CLI before 0.26.0"
        for r in skipped
    )
    out["deny"] = (
        f"deny enforced where the hook ran: {fmt(len(blocked), len(ran))} rows ({len(ran) - len(blocked)} let the call run); "
        f"deny rows where the hook did not run and the call ran: {len(skipped)} of {len(r4)} "
        f"({', '.join(f'{k} {v}' for k, v in sorted(by_cause.items()))})"
    )
    # 2. ask
    live = {h: live_builds(h, rows)[0] for h in HARNESS_NAMES}
    ask = {h: outcome_by_build(h, "R3", rows, live[h]) for h in HARNESS_NAMES}
    cl, cx, gm = ask["claude"], ask["codex"], ask["gemini"]
    out["ask_claude"] = (
        f"Claude Code ask: RAN on {sum(o == 'RAN' for o in cl.values())} builds, BLOCKED on "
        f"{sum(o == 'BLOCKED' for o in cl.values())} of {len(cl)} measured; "
        f"last RAN {max((v for v, o in cl.items() if o == 'RAN'), key=vkey)}, first BLOCKED "
        f"{min((v for v, o in cl.items() if o == 'BLOCKED'), key=vkey)}"
    )
    out["ask_codex"] = f"Codex ask: RAN on {sum(o == 'RAN' for o in cx.values())} of {len(cx)} builds"
    out["ask_gemini"] = (
        f"Gemini ask: RAN on {sum(o == 'RAN' for o in gm.values())}, HUNG on "
        f"{sum(o == 'HUNG' for o in gm.values())} of {len(gm)} builds; last RAN "
        f"{max((v for v, o in gm.items() if o == 'RAN'), key=vkey)}, first HUNG "
        f"{min((v for v, o in gm.items() if o == 'HUNG'), key=vkey)}"
    )
    # 3. failure replies
    for reply, name in (("R9", "timeout"), ("R5", "empty"), ("R7", "exit2"), ("R10b", "dead")):
        parts = []
        for h in HARNESS_NAMES:
            per = outcome_by_build(h, reply, rows, live[h])
            if per:
                tally = Counter(per.values())
                parts.append(f"{HARNESS_NAMES[h]} {', '.join(f'{o} on {k} of {len(per)}' for o, k in sorted(tally.items()))}")
        out[f"fail_{name}"] = f"{reply}, {LABELS[name]}: " + "; ".join(parts)
    # 4. state outside the reply
    untrusted = [r for r in rows if r["harness"] == "codex" and r["state"] == "untrusted"]
    out["codex_untrusted"] = (
        f"Codex untrusted hooks: {len(untrusted)} rows, hook ran in "
        f"{sum(r['hook_invoked'] is True for r in untrusted)}, call ran in "
        f"{sum(r['outcome'] == 'RAN' for r in untrusted)}, "
        f"{len({r['version'] for r in untrusted})} builds"
    )
    bypass = [r for r in rows if r["harness"] == "codex" and r["state"] == "trusted-bypass" and r["reply"] == "R1"]
    bypass += [r for r in read("codex", "r4-integration", "bisect", "runs.jsonl") if r["reply"] == "R1"]
    nohook = sorted({r["version"] for r in bypass if r["hook_invoked"] is False}, key=vkey)
    hook = sorted({r["version"] for r in bypass if r["hook_invoked"] is True}, key=vkey)
    out["codex_bypass"] = (
        f"Codex bypass flag: hook did not run on {len(nohook)} builds ({nohook[0]} to {nohook[-1]}), ran on "
        f"{len(hook)} builds ({hook[0]} to {hook[-1]})"
    )
    return out


def guards() -> dict[str, str]:
    """The guard comparison. k and n come from the committed summaries; the intervals are recomputed here."""
    out: dict[str, str] = {}
    fresh = json.loads((RES / "detect" / "fresh" / "summary.json").read_text())
    same = fresh["same_items"]
    sn, kx = same["safety-net"], same["knox"]
    sn_is, sn_g = sn["intentshield-r8fix"], sn["safety-net"]
    kx_is, kx_g = kx["intentshield-r8fix"], kx["knox"]
    total = fresh["by_guard"]["intentshield-r8fix"]
    pre = fresh["by_guard"]["intentshield"]
    out["fresh_is_before"] = (
        f"IntentShield before the rules, 214-item set: lets through {fmt(*_kn(pre, 'false_allow'))} harmful calls"
    )
    out["fresh_is_after"] = f"IntentShield with the rules, same set: lets through {fmt(*_kn(total, 'false_allow'))} harmful calls"
    out["fresh_vs_safety_net"] = (
        f"on safety-net's shell scope, {sn_g['false_allow']['n']} harmful items: safety-net lets through "
        f"{fmt(sn_g['false_allow']['k'], sn_g['false_allow']['n'])}, IntentShield "
        f"{fmt(sn_is['false_allow']['k'], sn_is['false_allow']['n'])}"
    )
    out["fresh_denies_only"] = (
        f"denies alone on those items: safety-net {sn_g['deny']}/{sn_g['false_allow']['n']}, IntentShield "
        f"{sn_is['deny']}/{sn_is['false_allow']['n']}; IntentShield asks on {sn_is['ask']} more"
    )
    out["fresh_vs_knox"] = (
        f"on knox's scope, {kx_g['false_allow']['n']} harmful items: knox lets through "
        f"{fmt(kx_g['false_allow']['k'], kx_g['false_allow']['n'])}, IntentShield "
        f"{fmt(kx_is['false_allow']['k'], kx_is['false_allow']['n'])}; denies alone knox {kx_g['deny']}, "
        f"IntentShield {kx_is['deny']}"
    )
    out["fresh_benign"] = (
        f"benign calls: IntentShield asks on {_kn(total, 'false_ask', benign=True)[0]} of "
        f"{_kn(total, 'false_ask', benign=True)[1]}, denies {_kn(total, 'false_deny', benign=True)[0]}; "
        f"safety-net denies {sn_g['false_deny']['k']} of {sn_g['false_deny']['n']}"
    )
    det = json.loads((RES / "detect" / "summary.json").read_text())["decisions"]

    def held(gid: str) -> dict:
        return det[gid]["claimed"]["heldout"]

    i, s, k = held("intentshield"), held("safety-net"), held("knox")
    out["detect_is"] = (
        "467-fixture set, held-out harmful items, before the rules: IntentShield lets through "
        f"{fmt(i['false_allow'], i['n_harmful'])}, asks on {i['harmful_ask']}"
    )
    out["detect_sn"] = (
        f"safety-net on its scope: {fmt(s['false_allow'], s['n_harmful'])}; "
        f"knox on its scope: {fmt(k['false_allow'], k['n_harmful'])}"
    )
    return out


def _kn(g: dict, key: str, benign: bool = False) -> tuple[int, int]:
    node = g["benign"]["scope"][key] if benign else g["harmful"]["all_run"]["false_allow"]
    return node["k"], node["n"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rows = stub_rows()
    m = matrix(rows)
    result = {
        "matrix_md": matrix_md(m),
        "excluded": m["excluded"],
        "findings": findings(rows),
        "guards": guards(),
        "rows": len(rows),
    }
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    print(f"{len(rows)} committed stub rows\n")
    print(result["matrix_md"])
    print("\nbuilds excluded (neutral control did not run the hook):", {HARNESS_NAMES[h]: v for h, v in m["excluded"].items()})
    for section in ("findings", "guards"):
        print(f"\n[{section}]")
        for key, text in result[section].items():
            print(f"{key}: {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
