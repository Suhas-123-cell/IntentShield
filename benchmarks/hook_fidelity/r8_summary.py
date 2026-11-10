# ruff: noqa: E501  (the markdown tables are long f-strings; wrapping them would make the table text harder to read)
"""Round 8 (lane r8-close) tables: derived from ``runs-r8.jsonl`` (rows with ``"round": "r8"``), the committed round 7 rows in
``runs.jsonl`` and the captured guard bytes. Nothing here launches anything.

    r8_summary.py OUT_DIR      writes ``summary-r8.json``, ``table-r8.md`` and ``r8-allow-fraction.json`` into OUT_DIR
                               (``compare.py summarize`` calls it when ``runs-r8.jsonl`` exists)

Parts: (1) the 12 launched wrapped (build, cell) failure pairs of round 7 and the wrapped ask cells, re-run on the merged HEAD with the
detected mode logged; (2) the failure cells under ``--on-empty allow``; (2b) what the default ``--on-empty deny`` blocks among the
captured benign allows, by calling the shim's own ``classify`` on the captured bytes (no guard is run).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import compare  # noqa: E402

from intentshield import wrap_hook  # noqa: E402

GUARDS = ROOT / "results" / "hook-fidelity" / "guards"


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def kn(k: int, n: int, interval: bool = True) -> str:
    """k/n with the percentage and a Wilson 95% interval, formatted from the counts."""
    if n == 0:
        return "0/0"
    text = f"{k}/{n} ({100 * k / n:.0f}%)"
    if interval:
        lo, hi = wilson(k, n)
        text += f", Wilson 95% [{100 * lo:.0f}%, {100 * hi:.0f}%]"
    return text


def _jsonl(path: Path) -> list[dict]:
    return compare._jsonl(path) if path.exists() else []


def label(rows: list[dict]) -> str:
    valid = [r for r in rows if r["outcome"] != "INVALID"]
    if not valid:
        return "INVALID"
    counts: dict[str, int] = {}
    for r in valid:
        counts[compare.row_outcome(r)] = counts.get(compare.row_outcome(r), 0) + 1
    return " + ".join(f"{k} {v}/{len(valid)}" for k, v in sorted(counts.items()))


def blocked_all(rows: list[dict]) -> bool:
    valid = [r for r in rows if r["outcome"] != "INVALID"]
    return bool(valid) and all(compare.row_outcome(r) in compare.BLOCKING for r in valid)


def allow_fraction() -> dict:
    """Over the BENIGN-scenario captures of ``guards/captures.jsonl`` (a guard's own entry point on a benign payload, run in a no-network
    sandbox in round 3): what each reply is, and what the shim's ``classify`` does with it under ``--on-empty deny`` and ``allow``. Pure
    function over bytes: no guard code runs here."""
    caps = [json.loads(line) for line in (GUARDS / "captures.jsonl").read_text().splitlines() if line.strip()]
    benign = [c for c in caps if c.get("scenario") == "benign"]
    items = []
    for c in benign:
        out = base64.b64decode(c["stdout_b64"]).decode("utf-8", "replace")
        err = base64.b64decode(c["stderr_b64"]).decode("utf-8", "replace")
        deny_mode = wrap_hook.classify(c["exit_code"], out, err, "deny")[0]
        allow_mode = wrap_hook.classify(c["exit_code"], out, err, "allow")[0]
        if c["exit_code"] == 0 and not out.strip():
            kind = "silent"
        elif deny_mode == "allow":
            kind = "explicit-allow"
        else:
            kind = "guard-denied-or-failed"
        # a documented fail-open (the policy server was unreachable) is a silent reply that is not a decision to allow
        fail_open = kind == "silent" and "unreachable" in c["entry"]
        items.append(
            {
                "guard": c["guard"],
                "shape": c["harness_shape"],
                "entry": c["entry"][:60],
                "exit": c["exit_code"],
                "kind": kind,
                "fail_open": fail_open,
                "deny_default": deny_mode,
                "on_empty_allow": allow_mode,
            }
        )
    in_lane = [i for i in items if i["shape"] in ("claude", "codex", "gemini")]

    def tally(sub: list[dict]) -> dict:
        silent = [i for i in sub if i["kind"] == "silent"]
        explicit = [i for i in sub if i["kind"] == "explicit-allow"]
        allows = silent + explicit
        return {
            "n": len(sub),
            "silent": len(silent),
            "explicit_allow": len(explicit),
            "guard_denied_or_failed": len(sub) - len(allows),
            "allows": len(allows),
            "allows_blocked_by_default": sum(i["deny_default"] != "allow" for i in allows),
            "allows_blocked_by_on_empty_allow": sum(i["on_empty_allow"] != "allow" for i in allows),
            "silent_fail_open": sum(i["fail_open"] for i in silent),
        }

    pairs: dict = {}
    for i in items:
        pairs.setdefault((i["guard"], i["shape"]), []).append(i)
    pair_rows = []
    for (guard, shape), sub in sorted(pairs.items()):
        kinds = sorted({i["kind"] for i in sub})
        pair_rows.append(
            {"guard": guard, "shape": shape, "captures": len(sub), "kinds": kinds, "fail_open": any(i["fail_open"] for i in sub)}
        )

    def pair_tally(shapes: tuple[str, ...]) -> dict:
        # a (guard, shape) pair counts as an allow pair when at least one benign capture of it is an allow; silent when ALL its allows are silent
        sel = [p for p in pair_rows if p["shape"] in shapes]
        allow_pairs = [p for p in sel if "silent" in p["kinds"] or "explicit-allow" in p["kinds"]]
        silent_pairs = [p for p in allow_pairs if "explicit-allow" not in p["kinds"]]
        return {
            "shapes": list(shapes),
            "pairs": len(sel),
            "allow_pairs": len(allow_pairs),
            "silent_allow_pairs": len(silent_pairs),
            "silent_allow_pairs_excluding_fail_open": len([p for p in silent_pairs if not p["fail_open"]]),
            "allow_pairs_excluding_fail_open": len([p for p in allow_pairs if not p["fail_open"]]),
            "list": [{k: p[k] for k in ("guard", "shape", "kinds", "fail_open")} for p in sel],
        }

    return {
        "source": "results/hook-fidelity/guards/captures.jsonl, scenario 'benign', classified by intentshield.wrap_hook.classify",
        "all_shapes": tally(items),
        "claude_codex_gemini_shapes": tally(in_lane),
        "by_pair_claude_codex_gemini": pair_tally(("claude", "codex", "gemini")),
        "items": items,
        "note": "captures of one guard share bytes and are not independent items; (guard, shape) pairs are a convenience sample "
        "of the corpus, so the intervals are descriptive only",
    }


def summarize(out: Path) -> dict:
    r8 = _jsonl(out / "runs-r8.jsonl")
    r7_all = _jsonl(out / "runs.jsonl")
    r7 = [r for r in r7_all if r.get("lane") == compare.LANE_R7]
    pair_keys = {(b, a, c) for b, a, c, _, _ in compare.R8_PAIR_ARMS} | {(b, a, "ask") for b, a, _ in compare.R8_ASK_ARMS}
    by8: dict[tuple, list[dict]] = {}
    by7: dict[tuple, list[dict]] = {}
    for r in r8:
        if (r["build"], r["arm"], r["cell"]) in pair_keys:
            by8.setdefault((r["build"], r["arm"], r["cell"]), []).append(r)
    for r in r7:
        if (r["build"], r["arm"], r["cell"]) in pair_keys:
            by7.setdefault((r["build"], r["arm"], r["cell"]), []).append(r)
    groups = []
    for key in sorted(by8):
        a, b = by8[key], by7.get(key, [])
        modes: dict[str, int] = {}
        for r in a:
            tag = f"{r.get('detected_mode')}: {str(r.get('detected_how')).split(' [')[0]}"
            modes[tag] = modes.get(tag, 0) + 1
        groups.append(
            {
                "build": key[0],
                "arm": key[1],
                "cell": key[2],
                "r8": label(a),
                "r7": label(b),
                "same": label(a) == label(b),
                "n_r8": len(a),
                "n_r7": len(b),
                "detected": modes,
                "shim_sent": sorted({s for r in a for s in r.get("shim_sent", [])}),
            }
        )
    rows1 = [r for r in r8 if (r["build"], r["arm"], r["cell"]) in pair_keys]
    rows_same = sum(
        1
        for key, a in by8.items()
        for r in a
        if compare.row_outcome(r) in {compare.row_outcome(x) for x in by7.get(key, [])}
        and len({compare.row_outcome(x) for x in by7.get(key, [])}) == 1
    )
    pair_rows = []
    for b, a, c, _regime, _reps in compare.R8_PAIR_ARMS:
        if a.endswith("+wrap-nohint"):
            continue
        x8, x7 = by8.get((b, a, c), []), by7.get((b, a, c), [])
        pair_rows.append(
            {
                "build": b,
                "cell": c,
                "arm": a,
                "r8": label(x8),
                "r7": label(x7),
                "r8_survived": blocked_all(x8),
                "r7_survived": blocked_all(x7),
            }
        )
    nohint = [
        {"build": b, "arm": a, "cell": c, "r8": label(by8.get((b, a, c), [])), "r7": label(by7.get((b, a, c), []))}
        for b, a, c, _, _ in compare.R8_PAIR_ARMS
        if a.endswith("+wrap-nohint")
    ]
    ask8 = [r for r in r8 if r["cell"] == "ask"]
    ask7 = [r for k, v in by7.items() if k[2] == "ask" for r in v]
    changes = [g for g in groups if not g["same"]]
    detector: dict = {
        "rows": len(r8),
        "source": {
            s: sum(r.get("detected_source") == s for r in r8) for s in sorted({str(r.get("detected_source")) for r in r8})
        },
        "complete": sum(bool(r.get("detected_complete")) for r in r8),
        "errors": sum(bool(r.get("detected_error")) for r in r8),
        "how": {},
        "ask_rows_shim_own_read": {},
        "code_commits": sorted({r.get("code_commit", "") for r in r8}),
    }
    for r in r8:
        key = f"{r.get('detected_mode')}: {str(r.get('detected_how')).split(' [')[0]}"
        detector["how"][key] = detector["how"].get(key, 0) + 1
    for r in ask8:
        for m in r.get("shim_mode_read", []):
            if m:
                key = f"{m[0]}: {m[1].split(' [')[0]}"
                detector["ask_rows_shim_own_read"][key] = detector["ask_rows_shim_own_read"].get(key, 0) + 1
    p2 = [r for r in r8 if r["arm"] == "ALLOW+wrap" and r["cell"] in compare.R8_EMPTY_ALLOW_CELLS]
    part2 = {
        "rows": len(p2),
        "ran": sum(r["outcome"] == "RAN" for r in p2),
        "by_cell": {},
        "cells": [
            {
                "build": r["build"],
                "cell": r["cell"],
                "outcome": r["outcome"],
                "on_empty": r.get("on_empty"),
                "shim_sent": r.get("shim_sent"),
                "guard_exit": r.get("shim_guard_exit"),
                "tool_result": (r.get("tool_result_text") or [""])[0][:160],
            }
            for r in sorted(p2, key=lambda x: (compare.R8_EMPTY_ALLOW_CELLS.index(x["cell"]), x["build"]))
        ],
    }
    for cell in compare.R8_EMPTY_ALLOW_CELLS:
        sub = [r for r in p2 if r["cell"] == cell]
        part2["by_cell"][cell] = {"ran": sum(r["outcome"] == "RAN" for r in sub), "n": len(sub)}
    return {
        "round": "r8",
        "rows": len(r8),
        "invalid": sum(r["outcome"] == "INVALID" for r in r8),
        "launches": sum(1 for line in _jsonl(out / "launches-r8.jsonl")),
        "part1": {
            "rows": len(rows1),
            "pairs": {
                "n": len(pair_rows),
                "r8_survived": sum(p["r8_survived"] for p in pair_rows),
                "r7_survived": sum(p["r7_survived"] for p in pair_rows),
                "list": pair_rows,
            },
            "nohint": nohint,
            "ask": {
                "r8_blocked": sum(compare.row_outcome(r) in compare.BLOCKING for r in ask8),
                "r8_n": len(ask8),
                "r7_blocked": sum(compare.row_outcome(r) in compare.BLOCKING for r in ask7),
                "r7_n": len(ask7),
            },
            "groups": groups,
            "groups_same": sum(g["same"] for g in groups),
            "groups_n": len(groups),
            "rows_same_outcome_as_r7": rows_same,
            "changes": changes,
        },
        "detector": detector,
        "part2": part2,
        "allow_fraction": allow_fraction(),
    }


def table(s: dict) -> str:
    p1, p2, det, af = s["part1"], s["part2"], s["detector"], s["allow_fraction"]
    L = [
        "# Round 8 closeout tables (derived by `r8_summary.py` from `runs-r8.jsonl`, `runs.jsonl` and the captured guard bytes)",
        "",
        f"Rows: {s['rows']} (field `round: r8`, lane `r8-close`), {s['invalid']} INVALID, {s['launches']} launches in `launches-r8.jsonl`; "
        f"code under test `{', '.join(det['code_commits'])}` (the merged HEAD with the `ps`-free detector; round 7 wrapped rows ran on `31a38db`).",
        "",
        "## Part 1: the 12 wrapped failure pairs and the wrapped ask cells, re-run",
        "",
        f"* Pairs (the guard launched wrapped in round 7 for each of the 12 (build, cell) pairs): every valid rep blocked in "
        f"{p1['pairs']['r8_survived']}/{p1['pairs']['n']} pairs now, {p1['pairs']['r7_survived']}/{p1['pairs']['n']} in round 7.",
        f"* Wrapped ask cells: BLOCKED {p1['ask']['r8_blocked']}/{p1['ask']['r8_n']} reps now, {p1['ask']['r7_blocked']}/{p1['ask']['r7_n']} in round 7.",
        f"* (build, arm, cell) groups with the same outcome label as round 7: {p1['groups_same']}/{p1['groups_n']}; rows whose outcome equals "
        f"round 7's single outcome for the group: {p1['rows_same_outcome_as_r7']}/{p1['rows']}. Changes: "
        f"{', '.join(f'{c["build"]} {c["arm"]} {c["cell"]}' for c in p1['changes']) or 'none'}.",
        "* `+wrap-nohint` (no `--hook-timeout`, so the deadline is the shim's 30 s): "
        + "; ".join(f"{n['build']} {n['arm']}: now {n['r8']}, round 7 {n['r7']}" for n in p1["nohint"])
        + ".",
        "",
        "| build | arm | cell | round 8 | round 7 | same | detected mode and reason in the shim's own process (rows) |",
        "|---|---|---|---|---|---|---|",
    ]
    for g in p1["groups"]:
        det_text = "; ".join(f"{k} x{v}" for k, v in g["detected"].items())
        L.append(
            f"| {g['build']} | {g['arm']} | {g['cell']} | {g['r8']} | {g['r7']} | {'yes' if g['same'] else 'NO'} | {det_text} |"
        )
    L += [
        "",
        "## Detector reading in every round 8 row",
        "",
        f"* Ancestry source: {', '.join(f'{k} {v}/{det["rows"]}' for k, v in det['source'].items())}; complete walk {det['complete']}/{det['rows']}; "
        f"detector exceptions {det['errors']}/{det['rows']}; `ps` was not used in any row (its sandbox profile blocks it, as in round 7).",
        "* Mode and reason: "
        + "; ".join(f"{k} {v}/{det['rows']}" for k, v in sorted(det["how"].items(), key=lambda kv: -kv[1]))
        + ".",
        "* What the shim itself read, in the ask rows (the shim reads a mode only to decide an ask): "
        + "; ".join(f"{k} {v}" for k, v in det["ask_rows_shim_own_read"].items())
        + ".",
        "",
        "## Part 2: failure cells under `--on-empty allow` (arm `ALLOW+wrap`: silent-allow bytes, matcher and 3 s hook timeout of the round 7 allow arm, deadline 2 s; n=1)",
        "",
        f"The call RAN in {p2['ran']}/{p2['rows']} runs. By cell: "
        + ", ".join(f"`{c}` {v['ran']}/{v['n']}" for c, v in p2["by_cell"].items())
        + ".",
        "",
        "| build | cell | outcome | `--on-empty` | shim sent | guard exit | tool result the harness returned |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in p2["cells"]:
        L.append(
            f"| {c['build']} | {c['cell']} | {c['outcome']} | {c['on_empty']} | {', '.join(c['shim_sent']) or 'nothing (deadline)'} | "
            f"{', '.join(map(str, c['guard_exit'])) or '-'} | {c['tool_result'].replace('|', '/').replace(chr(10), ' ')} |"
        )
    a, c3, pr = af["all_shapes"], af["claude_codex_gemini_shapes"], af["by_pair_claude_codex_gemini"]
    L += [
        "",
        "## Part 2b: what the default `--on-empty deny` blocks among the captured benign allows (no launch)",
        "",
        f"Source: {af['source']}. {af['note']}.",
        "",
        f"* All {a['n']} benign captures: {a['silent']} silent (exit 0, nothing on stdout; {a['silent_fail_open']} of them axonflow-codex's documented "
        f"fail-open when its policy server is unreachable), {a['explicit_allow']} an explicit `{{}}` allow, {a['guard_denied_or_failed']} the guard "
        f"denied or failed on a benign call. Of the {a['allows']} replies that let the call through, the default blocks "
        f"{kn(a['allows_blocked_by_default'], a['allows'], False)}; `--on-empty allow` blocks {a['allows_blocked_by_on_empty_allow']}/{a['allows']}.",
        f"* The Claude, Codex and Gemini shapes only (the three harnesses of this study): {c3['n']} benign captures, {c3['silent']} silent, "
        f"{c3['explicit_allow']} explicit; of {c3['allows']} allows the default blocks {kn(c3['allows_blocked_by_default'], c3['allows'], False)}.",
        f"* By (guard, shape) pair, those three shapes: {pr['pairs']} pairs with a benign capture, {pr['allow_pairs']} allow somewhere; "
        f"{pr['silent_allow_pairs']} of those {pr['allow_pairs']} are silent only, {kn(pr['silent_allow_pairs'], pr['allow_pairs'])}; "
        f"leaving out the fail-open guard, {kn(pr['silent_allow_pairs_excluding_fail_open'], pr['allow_pairs_excluding_fail_open'])}.",
        "* In a harness (round 7, unchanged): `ALLOW+wrap-strict` (a captured silent allow, default flag) BLOCKED 6/6 builds; `ALLOW+wrap` "
        "(`--on-empty allow`) RAN 12/12 reps; `ALLOW+wrap-json` (a captured `{}`) RAN 5/5.",
        "",
        "| guard | shape | entry | exit | kind | blocked by default | blocked under `--on-empty allow` |",
        "|---|---|---|---|---|---|---|",
    ]
    for i in af["items"]:
        L.append(
            f"| {i['guard']} | {i['shape']} | {i['entry']} | {i['exit']} | {i['kind']}{' (fail-open)' if i['fail_open'] else ''} | "
            f"{'yes' if i['deny_default'] != 'allow' else 'no'} | {'yes' if i['on_empty_allow'] != 'allow' else 'no'} |"
        )
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    out = Path(args[0]).resolve()
    s = summarize(out)
    (out / "summary-r8.json").write_text(json.dumps(s, indent=1, default=str))
    (out / "r8-allow-fraction.json").write_text(json.dumps(s["allow_fraction"], indent=1))
    (out / "table-r8.md").write_text(table(s))
    print(
        json.dumps(
            {
                "rows": s["rows"],
                "pairs": s["part1"]["pairs"]["n"],
                "r8_survived": s["part1"]["pairs"]["r8_survived"],
                "part2_ran": s["part2"]["ran"],
                "groups_same": f"{s['part1']['groups_same']}/{s['part1']['groups_n']}",
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
