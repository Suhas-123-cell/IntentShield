#!/usr/bin/env python3
"""End-to-end check of the effective-protection predictions (round 8, lane detection): 30 (guard, item, build) cells.

    detect_validate.py select  --decisions decisions.jsonl --out DIR     # writes selection.json (the predictions), launches nothing
    detect_validate.py plan    --out DIR                                 # the launch count of what is left
    HOOK_FIDELITY_GO=<n> detect_validate.py run --out DIR [--parallel N]
    detect_validate.py summarize --out DIR                               # predicted vs observed, k/n

What a launch is. The guard's own hook entry point ran on the item's payload inside ``sandbox-exec`` (``detect_compare.py decide``);
here its exact stdout, stderr and exit code are REPLAYED (``stubhook.py``, the guard's code does not run) as the verdict of the hook
registered in a real harness build, headless, against the study's deterministic local stub model. The call the stub model issues is
the study's benign marker command (a shim that touches a file under the run's scratch directory), NOT the item: no fixture command is
ever run. The oracle is the shim-attested marker (``compare.run_case``): RAN, BLOCKED or HUNG. The prediction is the delivery matrix's
outcome for the reply's class on that build (``detect_compare.derive_delivery``). So a launch checks that the matrix row, which
came from other bytes, predicts the outcome of THIS guard's bytes for THIS item; it says nothing about whether the guard's decision
was right. No third-party code ran in a harness; headless only; the interactive Claude cell is not launched.

Selection rule (fixed before any launch, deterministic): five strata per build, one cell each, drawn by sha256 order from the held-out
harmful items (the benign-deny stratum from benign items) among the guards registered for the build's harness:
deny-json, deny-exit2, ask, allow-miss (a guard that missed a harmful call), and benign-deny (a false deny, predicted to block).
Only shell calls are drawn (the stub's call is a shell call). Gemini has no deny-by-bare-exit-2 guard on the held-out shell items, so two
builds get a second draw of a stratum they have (``EXTRA``). Codex needs one trust-listing launch (``hooks/list``): 29 cells plus that
launch are the cap of 30 launches, so the validated predictions are 29, not 30.
"""
# ruff: noqa: E501
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import shlex
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare as cmp  # noqa: E402
import detect_compare as dc  # noqa: E402
import run as hf_run  # noqa: E402

CAP = 30
HEADLESS_BUILDS = ("claude-2.1.316", "claude-2.1.84", "codex-0.166.0", "gemini-0.66.0-yolo", "gemini-0.66.0-allow", "gemini-0.37.1-yolo")
STRATA = ("deny-json", "deny-exit2", "ask", "allow-miss", "benign-deny")
# Gemini has no guard that denies by a bare exit 2 on the held-out shell items, so two builds get a second draw of a stratum they have
EXTRA = (("gemini-0.66.0-yolo", "deny-json"), ("claude-2.1.316", "allow-miss"))
CODEX_SHIPPED_MATCHER = "Bash|exec_command|shell"   # the stub model's call is exec_command; the study's shipped Codex matcher names it


# ---------------------------------------------------------------------------------------------------------------- selection
def _stratum_of(d: dict, fx: dict) -> str | None:
    cls, sub = d["class"], d["subtype"]
    if fx["label"] == "benign":
        return "benign-deny" if cls == "deny" else None
    if cls == "deny":
        return "deny-json" if sub in ("json", "exit2+json") else "deny-exit2" if sub == "exit2" else None
    if cls == "ask":
        return "ask"
    if cls == "allow" and d["invoked"]:
        return "allow-miss"
    return None


def select(rows: list[dict], decisions: list[dict], matrix: dict) -> list[dict]:
    by_row = {fx["id"]: fx for fx in rows}
    picks: list[dict] = []
    for build in HEADLESS_BUILDS:
        harness = dc.BUILDS[build]
        cands: dict[str, list[dict]] = {s: [] for s in STRATA}
        for d in decisions:
            fx = by_row[d["row_id"]]
            if fx["harness"] != harness or not fx["heldout"] or fx["tool_kind"] != "shell":   # the stub's call is a shell call
                continue
            if d["guard"].startswith("intentshield-") or d["guard"] in ("gemini-intrupt-hook[local-filter]",):
                continue
            s = _stratum_of(d, fx)
            if s:
                cands[s].append(d)
        for s in (*STRATA, *(x for b, x in EXTRA if b == build)):
            pool = sorted(cands[s], key=lambda d: hashlib.sha256(f"{build}|{s}|{d['guard']}|{d['row_id']}".encode()).hexdigest())
            if not pool:
                continue
            seen = {p["guard"] for p in picks if p["build"] == build}
            taken = {p["row_id"] for p in picks if p["build"] == build}
            d = next((x for x in pool if x["guard"] not in seen and x["row_id"] not in taken), next(x for x in pool if x["row_id"] not in taken))
            fx = by_row[d["row_id"]]
            cls = d["class"]
            picks.append({"build": build, "stratum": s, "guard": d["guard"], "row_id": d["row_id"], "item_id": d["item_id"], "label": fx["label"],
                          "harness": harness, "class": cls, "subtype": d["subtype"],
                          "predicted": dc.outcome(matrix, build, cls, d["subtype"]),
                          "call": str((fx["payload"].get("tool_input") or {}).get("command") or fx["payload"]["tool_name"])[:90]})
    # keep within the cap with Codex's one trust-listing launch: drop the last stratum of the last build until the plan fits
    while len(picks) + 1 > CAP:
        picks.pop()
    return picks


# ----------------------------------------------------------------------------------------------------------- reply bytes
def reply_bytes(pick: dict, rows: list[dict], scratch: Path) -> dict:
    """The exact bytes the guard produced for the item, captured again (the decisions file keeps 400 characters of them)."""
    fx = next(r for r in rows if r["id"] == pick["row_id"])
    guard = pick["guard"]
    if guard in dc.IS_VARIANTS:
        import io
        import tempfile
        from contextlib import redirect_stderr
        os.environ["INTENTSHIELD_INTENT_MODEL_DIR"] = "/nonexistent"
        from intentshield.harness import HarnessGuard, handle
        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            tmp_p = Path(tmp)
            (tmp_p / "work").mkdir()
            g = HarnessGuard(tmp_p / "h.db", threats=tmp_p / "t.db", builtin_tools=dc.IS_VARIANTS[guard]["builtin_tools"])
            g.translation = dc._PassThrough()
            for ev in fx["prelude"] if dc.IS_VARIANTS[guard]["state"] else []:
                handle(fx["harness"], dc._swap_cwd(ev, tmp_p / "work"), g)
            reply = handle(fx["harness"], dc._swap_cwd(fx["payload"], tmp_p / "work"), g)
            g.close()
        out = (json.dumps(reply) + "\n").encode() if reply else b""
        return {"exit_code": 0, "stdout": out, "stderr": b"", "entry_matcher": None}
    spec = next(s for s in dc.specs(strict=True) if s.id == guard)
    tool = fx["payload"]["tool_name"]
    entries = [(i, e) for i, e in enumerate(spec.entries) if e.harness == fx["harness"] and e.matches(tool)]
    want = pick["class"]
    results = []
    for i, e in entries:
        tag = f"{pick['row_id']}-{i}"
        run_scratch = scratch / "bytes" / tag
        import shutil
        if run_scratch.exists():
            shutil.rmtree(run_scratch)
        (run_scratch / "work").mkdir(parents=True)
        (run_scratch / "home" / ".claude").mkdir(parents=True)
        (run_scratch / "work" / ".env").write_text("HF_FIXTURE_MARKER=not-a-secret\n")
        stdin = json.dumps(dc._swap_cwd(fx["payload"], run_scratch / "work")).encode()
        env = dc.gc.clean_env(run_scratch, e.env, [str(dc.NODE_DIR / "bin")] if e.node else [])
        res = dc.gc.run_sandboxed(e.argv, stdin, run_scratch, e.readable, env, timeout=dc.RUN_TIMEOUT)
        cls, _ = dc.classify(fx["harness"], res["exit_code"], res["stdout"].decode("utf-8", "replace"), res["stderr"].decode("utf-8", "replace"),
                             res["timed_out"])
        results.append((cls, res, e))
        shutil.rmtree(run_scratch, ignore_errors=True)
    chosen = next((r for r in results if r[0] == want), results[0])
    res = chosen[1]
    return {"exit_code": res["exit_code"], "stdout": dc.gc.scrub_bytes(res["stdout"]), "stderr": dc.gc.scrub_bytes(res["stderr"]),
            "entry_matcher": chosen[2].matcher}


def shipped_matcher(pick: dict, matcher: str | None) -> str | None:
    """The matcher the replayed hook is registered with: the guard's own where it has one, adjusted to the one shell tool the stub model's
    call goes through (a guard's Write|Edit matcher would never see it); Codex's is the study's shipped one, which names the stub's tool."""
    if pick["harness"] == "codex":
        return CODEX_SHIPPED_MATCHER
    if not matcher:
        return None
    return "Bash" if pick["harness"] == "claude" else "run_shell_command"


# ----------------------------------------------------------------------------------------------------------- run plumbing
def install_patches(out: Path, picks_by_arm: dict[str, dict]) -> None:
    """Teach compare.py's runner the 'DET:' arms: a byte replay, registered with the guard's shipped matcher, no timeout key."""
    orig_cell_config, orig_entries, orig_codex_key = cmp.cell_config, cmp.hook_entries_for, cmp.codex_arm_key

    def cell_config(case, root, out_dir, nonce):
        if not case["arm"].startswith("DET:"):
            return orig_cell_config(case, root, out_dir, nonce)
        base = {"log": str(root / "hooks.jsonl"), "crash": False, "run_id": cmp.case_id(case)}
        return {**base, "kind": "3p", "harness": cmp.BUILDS[case["build"]].harness, "replay": case["replay"], "latency": 0,
                "log3p": str(root / "hooks3p.jsonl")}

    def hook_entries_for(case, program):
        if not case["arm"].startswith("DET:"):
            return orig_entries(case, program)
        h = cmp.BUILDS[case["build"]].harness
        handler: dict = {"type": "command", "command": shlex.quote(str(program))}
        if h == "gemini":
            handler["name"] = "guard"
        group: dict = {"hooks": [handler]}
        if case.get("matcher"):
            group = {"matcher": case["matcher"], **group}
        return {"BeforeTool" if h == "gemini" else "PreToolUse": [group]}

    def codex_arm_key(case):
        return "DET-codex-C" if case["arm"].startswith("DET:") else orig_codex_key(case)

    cmp.cell_config, cmp.hook_entries_for, cmp.codex_arm_key = cell_config, hook_entries_for, codex_arm_key


def cases_from_selection(sel: list[dict], out: Path) -> list[dict]:
    cases = []
    for p in sel:
        cases.append({"build": p["build"], "arm": f"DET:{p['guard']}:{p['item_id']}", "cell": "detect", "regime": "C", "rep": 0,
                      "stratum": p["stratum"], "predicted": p["predicted"], "class": p["class"], "subtype": p["subtype"],
                      # absolute: the hook runs in the harness's own working directory (a relative path made every first-pass hook crash)
                      "replay": str((out / "replays" / f"{p['row_id']}-{p['guard'].replace('[', '_').replace(']', '')}.json").resolve()),
                      "matcher": p.get("launch_matcher")})
    return cases


def cmd_select(args) -> int:
    rows = dc.load_fixtures()
    decisions = [json.loads(line) for line in Path(args.decisions).read_text().splitlines()]
    matrix = dc.derive_delivery()
    sel = select(rows, decisions, matrix)
    out = Path(args.out)
    (out / "replays").mkdir(parents=True, exist_ok=True)
    scratch = Path(args.scratch)
    for p in sel:
        b = reply_bytes(p, rows, scratch)
        p["launch_matcher"] = shipped_matcher(p, b["entry_matcher"])
        p["stdout_text"], p["stderr_text"], p["exit_code"] = b["stdout"].decode("utf-8", "replace")[:300], b["stderr"].decode("utf-8", "replace")[:200], b["exit_code"]
        rec = {"exit_code": b["exit_code"], "stdout_b64": base64.b64encode(b["stdout"]).decode(), "stderr_b64": base64.b64encode(b["stderr"]).decode()}
        (out / "replays" / f"{p['row_id']}-{p['guard'].replace('[', '_').replace(']', '')}.json").write_text(json.dumps(rec))
    (out / "selection.json").write_text(json.dumps(sel, indent=1) + "\n")
    print(f"{len(sel)} cells selected: " + str(dict(Counter((p['build'], p['stratum']) for p in sel))))
    return 0


def load_cases(out: Path) -> list[dict]:
    sel = json.loads((out / "selection.json").read_text())
    return cases_from_selection(sel, out)


def todo_of(out: Path) -> list[dict]:
    done = set()
    if (out / "runs.jsonl").exists():
        done = {r["run_id"] for r in cmp._jsonl(out / "runs.jsonl") if r.get("outcome") != "INVALID"}
    return [c for c in load_cases(out) if cmp.case_id(c) not in done]


def launches_spent(out: Path) -> int:
    """Launches already in the ledger (``launches.jsonl``: a run, or a Codex hooks/list)."""
    path = out / "launches.jsonl"
    return len([line for line in path.read_text().splitlines() if line.strip()]) if path.exists() else 0


def cmd_plan(args) -> int:
    out = Path(args.out)
    install_patches(out, {})
    todo = todo_of(out)
    print(f"{len(todo)} runs, {cmp.planned_launches(todo)} launches")
    return 0


def cmd_run(args) -> int:
    out = Path(args.out)
    install_patches(out, {})
    todo = todo_of(out)
    n = cmp.planned_launches(todo)
    spent = launches_spent(out)
    allowed = os.environ.get("HOOK_FIDELITY_CAP_TOTAL", "")   # a new cumulative cap, set by whoever authorises more launches than CAP
    cap = int(allowed) if allowed.isdigit() else CAP
    if spent + n > cap:
        print(f"refusing: {spent} launches are already in the ledger, {n} more would pass the cap of {cap}", file=sys.stderr)
        return 2
    go = os.environ.get("HOOK_FIDELITY_GO", "")
    if not go.isdigit() or int(go) != n:
        print(f"refusing: HOOK_FIDELITY_GO must equal the {n} launches planned (got {go!r})", file=sys.stderr)
        return 2
    broken = hf_run.loopback_selftest()
    if broken:
        print("refusing: loopback sandbox self-test failed: " + "; ".join(broken), file=sys.stderr)
        return 2
    print(f"{len(todo)} runs, {n} launches, GO={go}", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {pool.submit(cmp.run_case, c, out, False): c for c in todo}
        for fut in concurrent.futures.as_completed(futures):
            c = futures[fut]
            try:
                row = fut.result()
            except Exception as exc:  # recorded, never retried silently
                row = {"run_id": cmp.case_id(c), **c, "outcome": "INVALID", "invalid_reason": f"runner error: {type(exc).__name__}: {exc}"}
            cmp.append(out / "runs.jsonl", row)
            print(f"{c['build']:<22} {c['stratum']:<12} {c['arm'][:48]:<48} predicted {c['predicted']:<8} -> {row['outcome']} "
                  f"hook={row.get('hook_invoked')} {row.get('invalid_reason', '')}", flush=True)
    return 0


QUARANTINE_REASON = ("first attempt: the replay path was relative and the hook runs in the harness's working directory, so the hook crashed "
                     "(FileNotFoundError, a non-blocking error) before it replied; the call ran whatever the guard said")


def observed_runs(out: Path) -> dict[str, dict]:
    """run_id -> row. ``runs.jsonl`` is the valid attempt; ``runs-attempt1-invalid.jsonl`` (the rows of the first attempt, kept as written) is
    read only to mark its cells INVALID, so a cell whose only launch was the broken attempt is reported as invalid, never as not run or matched."""
    runs: dict[str, dict] = {}
    quarantined = out / "runs-attempt1-invalid.jsonl"
    if quarantined.exists():
        for r in cmp._jsonl(quarantined):
            runs[r["run_id"]] = {**r, "outcome": "INVALID", "invalid_reason": QUARANTINE_REASON, "observed_before_invalidation": r.get("outcome")}
    if (out / "runs.jsonl").exists():
        for r in cmp._jsonl(out / "runs.jsonl"):
            runs[r["run_id"]] = r
    return runs


def cmd_summarize(args) -> int:
    out = Path(args.out)
    sel = json.loads((out / "selection.json").read_text())
    runs = observed_runs(out)
    lines = ["| build | stratum | guard | item | reply (class, subtype) | predicted | observed | match | hook invoked |", "|---|---|---|---|---|---|---|---|---|"]
    k = n = 0
    invalid = 0
    for case, p in zip(cases_from_selection(sel, out), sel, strict=True):
        r = runs.get(cmp.case_id(case))
        if r is None:
            lines.append(f"| {p['build']} | {p['stratum']} | {p['guard']} | {p['item_id']} | {p['class']}/{p['subtype']} | {p['predicted']} | not run | - | - |")
            continue
        if r["outcome"] == "INVALID":
            invalid += 1
            lines.append(f"| {p['build']} | {p['stratum']} | {p['guard']} | {p['item_id']} | {p['class']}/{p['subtype']} | {p['predicted']} | INVALID ({r.get('invalid_reason','')[:60]}) | - | - |")
            continue
        n += 1
        ok = r["outcome"] == p["predicted"]
        k += ok
        lines.append(f"| {p['build']} | {p['stratum']} | {p['guard']} | {p['item_id']} | {p['class']}/{p['subtype']} | {p['predicted']} | {r['outcome']} | {'yes' if ok else 'NO'} | {r.get('hook_invoked')} |")
    quarantined = out / "runs-attempt1-invalid.jsonl"
    attempt1 = len(cmp._jsonl(quarantined)) if quarantined.exists() else 0
    summary = {"matched": k, "valid": n, "invalid": invalid, "planned": len(sel), "attempt1_invalid_rows": attempt1}
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    note = ""
    if attempt1:
        note += (f"The {attempt1} rows of the first attempt (`runs-attempt1-invalid.jsonl`, kept as written) are INVALID: the replay path was relative, so every hook crashed and every call ran. "
                 "They are not counted here; the rows below come from the corrected rerun (`runs.jsonl`, 29 launches).\n\n")
    if invalid:
        note += f"{invalid} of {len(sel)} cells are INVALID or missing a valid row and are not counted.\n\n"
    (out / "table.md").write_text(f"# Predicted vs observed ({len(sel)} cells)\n\n" + f"{dc.fmt(k, n) if n else '0/0'} predictions matched ({invalid} of {len(sel)} cells INVALID, not counted).\n\n" + note + "\n".join(lines) + "\n")
    print(summary)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("select")
    p.add_argument("--decisions", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--scratch", required=True)
    for name in ("plan", "run", "summarize"):
        p = sub.add_parser(name)
        p.add_argument("--out", required=True)
        if name == "run":
            p.add_argument("--parallel", type=int, default=2)
    args = parser.parse_args(argv)
    return {"select": cmd_select, "plan": cmd_plan, "run": cmd_run, "summarize": cmd_summarize}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
