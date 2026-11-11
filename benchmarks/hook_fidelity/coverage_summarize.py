#!/usr/bin/env python3
"""Summarise the coverage re-run: k/n per surface per harness build, and the longitudinal table.

    coverage_summarize.py results/hook-fidelity/coverage     # reads rows.jsonl, writes cells.json and summary.md

A "cell" is (harness, build, variant, surface). Its n is the number of VALID launches of the run that exercises the surface
(the "tools" run for description, instructions, changed description and result; "resource" for the resource read;
"prompt" for the prompt). Invalid launches (no model request, scripted tool not offered, dead hook config) are listed
separately and never counted in n. Per cell:

    k_model          launches in which the stub's request log shows the marker in a request to the model
    k_server_read    launches in which the probe server's log shows the harness requested that surface from the server
    k_decision_hook  launches in which a PreToolUse/BeforeTool/PermissionRequest hook event carried the marker as input
                     (the TOOL-GATE hooks; Gemini's BeforeModel/BeforeAgent/BeforeToolSelection and the Claude and Codex
                     UserPromptSubmit hooks can also block and are counted under k_any_hook only; PermissionRequest
                     fired in 0 launches because every launch ran with permissions skipped or auto-approved)
    k_result_hook    ... a PostToolUse/AfterTool event carried it
    k_any_hook       ... ANY hook event carried it (including model-request events such as BeforeModel)
    k_any_pre_model  ... some hook event carried it before the first model request that carried it

Rates are never stored rounded: only k and n are written; Wilson 95% bounds are computed here at display time.
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from pathlib import Path

SURFACES = [  # (name, marker key, launch that exercises it, probe method that proves the server was asked)
    ("tool_description", "DESC", "tools", "tools/list"),
    ("server_instructions", "INSTR", "tools", "start"),  # initialize carries them; no separate request exists
    ("changed_description", "VDESC2", "tools", "tools/list>=2"),  # the server was asked for the list AGAIN after the change
    ("tool_result", "RESULT", "tools", "tools/call"),
    ("resource_read", "RES", "resource", "resources/read"),
    ("prompt_content", "PROMPT", "prompt", "prompts/get"),
]
FIELDS = ("k_model", "k_server_read", "k_decision_hook", "k_result_hook", "k_any_hook", "k_any_pre_model")


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt(k: int, n: int) -> str:
    if n == 0:
        return "-"
    lo, hi = wilson(k, n)
    return f"{k}/{n} [{lo * 100:.0f},{hi * 100:.0f}]"


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("-")[0].split(".") if p.isdigit())


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def cells(rows: list[dict]) -> tuple[dict, list[dict]]:
    out: dict[tuple, dict] = {}
    invalid = []
    for row in rows:
        if not row.get("valid"):
            invalid.append({k: row.get(k) for k in ("harness", "version", "variant", "surface_run", "rep", "problems")})
            continue
        for name, key, run, method in SURFACES:
            if row["surface_run"] != run:
                continue
            s = row["surfaces"][key]
            cell = out.setdefault((row["harness"], row["version"], row.get("variant", "base"), name), {
                "harness": row["harness"], "version": row["version"], "variant": row.get("variant", "base"),
                "surface": name, "n": 0, **{f: 0 for f in FIELDS}, "hook_events": set(), "model_sections": set(),
                "scripted_call_pre_hooked": [0, 0]})
            cell["n"] += 1
            cell["k_model"] += s["model_requests_carrying"] > 0
            asked = row["probe_requests"].get(method.split(">=")[0], 0)
            cell["k_server_read"] += asked >= (int(method.split(">=")[1]) if ">=" in method else 1)
            cell["k_decision_hook"] += s["seen_by_decision_hook"]
            cell["k_result_hook"] += s["seen_by_result_hook"]
            cell["k_any_hook"] += s["seen_by_any_hook"]
            cell["k_any_pre_model"] += s["seen_by_any_hook_before_model"] and s["seen_by_any_hook"]
            cell["hook_events"] |= set(s["hook_event_names"])
            cell["model_sections"] |= set(s["model_sections"])
            if row.get("scripted_call_pre_hooked") is not None and name in ("tool_result", "resource_read"):
                cell["scripted_call_pre_hooked"][0] += bool(row["scripted_call_pre_hooked"])
                cell["scripted_call_pre_hooked"][1] += 1
    for cell in out.values():
        cell["hook_events"] = sorted(cell["hook_events"])
        cell["model_sections"] = sorted(cell["model_sections"])
    return out, invalid


def build_name(c: dict) -> str:
    return f"{c['harness']} {c['version']}" + ("" if c["variant"] == "base" else f" ({c['variant']})")


def visibility_class(c: dict) -> str:
    """What kind of hook event carried the surface in this build, for the longitudinal comparison (event names are listed
    per build in the cell tables; a build that merely adds an event of the same kind is not a change)."""
    if c["n"] == 0:
        return "not run"
    kinds = []
    if c["k_decision_hook"]:
        kinds.append("tool-gate hook")
    if c["k_result_hook"]:
        kinds.append("result hook")
    if c["k_any_hook"] and not kinds:
        kinds.append("model-request/agent events only")
    return " + ".join(kinds) if kinds else "no hook"


def longitudinal(cs: dict) -> list[str]:
    lines = ["| harness | surface | builds sampled (old to new) | hook-visible per build "
             "| first / last build where any hook carried it |", "|---|---|---|---|---|"]
    by = defaultdict(list)
    for c in cs.values():
        if c["variant"] == "base":
            by[(c["harness"], c["surface"])].append(c)
    for (harness, surface), group in sorted(by.items()):
        group.sort(key=lambda c: version_key(c["version"]))
        seen = [(c["version"], c["k_any_hook"], c["n"]) for c in group]
        visible = [v for v, k, n in seen if k > 0]
        classes = [visibility_class(c) for c in group]
        changed = len(set(classes)) > 1
        per = "; ".join(f"{c['version']}: {cls}" for c, cls in zip(group, classes))
        if not visible:
            span = "never hook-visible in any sampled build"
        elif len(visible) == len(seen) and not changed:
            span = f"all sampled builds ({visible[0]} .. {visible[-1]}); no change"
        else:
            span = f"first {visible[0]}, last {visible[-1]}" + ("; class changed between builds" if changed else "")
        lines.append(f"| {harness} | {surface} | {', '.join(v for v, _, _ in seen)} | {per} | {span} |")
    return lines


def main(argv: list[str]) -> int:
    out = Path(argv[0])
    rows = load(out / "rows.jsonl")
    cs, invalid = cells(rows)
    ledger = load(out / "ledger.jsonl") if (out / "ledger.jsonl").exists() else []
    (out / "cells.json").write_text(json.dumps(sorted(cs.values(), key=lambda c: (
        c["harness"], version_key(c["version"]), c["variant"], c["surface"])), indent=1))
    md = ["# Coverage re-run: which MCP surfaces reach a hook, per harness build (no model)", "",
          "Every cell is k/n with a Wilson 95% interval in brackets (percent, computed here from k and n). n counts valid "
          "launches of one stub-model run; the stub model is deterministic, so n=3 shows run-to-run stability of the "
          "harness, not sampling variance of a model. See "
          "`docs/research-notes/hook-fidelity/hook-fidelity-coverage-rerun.md` for the method and limits.", ""]
    harness_builds = sorted({(c["harness"], c["version"], c["variant"]) for c in cs.values()},
                            key=lambda t: (t[0], version_key(t[1]), t[2]))
    for harness, version, variant in harness_builds:
        name = f"{harness} {version}" + ("" if variant == "base" else f" ({variant})")
        md += [f"## {name}", "",
               "| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) "
               "| result hook | any hook "
               "| any hook before the model | hook events that carried it | where in the model request |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        for surface, *_ in SURFACES:
            c = cs.get((harness, version, variant, surface))
            if not c:
                md.append(f"| {surface} | 0 | not run | | | | | | | |")
                continue
            n = c["n"]
            md.append(f"| {surface} | {n} | {fmt(c['k_model'], n)} | {fmt(c['k_server_read'], n)} | "
                      f"{fmt(c['k_decision_hook'], n)} | {fmt(c['k_result_hook'], n)} | {fmt(c['k_any_hook'], n)} | "
                      f"{fmt(c['k_any_pre_model'], n)} | {', '.join(c['hook_events']) or 'none'} | "
                      f"{', '.join(c['model_sections']) or 'none'} |")
        calls = [(s, cs.get((harness, version, variant, s))) for s in ("tool_result", "resource_read")]
        md += ["", "Scripted call reached a PreToolUse-class hook event: " + "; ".join(
            f"{s}: {fmt(*c['scripted_call_pre_hooked'])}" for s, c in calls if c and c["scripted_call_pre_hooked"][1]) + ".", ""]
    md += ["## Longitudinal: first and last sampled build where a hook carried each surface", ""] + longitudinal(cs) + [""]
    not_offered = ["the scripted tool was not among the tools the harness offered"]
    invalid = [r for r in invalid if r["problems"] != not_offered]  # those get their own table below
    if invalid:
        md += ["## Invalid launches (excluded from every n)", ""]
        md += [f"- {r['harness']} {r['version']} {r['variant']} {r['surface_run']} rep{r['rep']}: "
               f"{'; '.join(r['problems'] or [])}" for r in invalid] + [""]
    offered = [r for r in rows if not r.get("valid") and r.get("problems") == [
        "the scripted tool was not among the tools the harness offered"]]
    if offered:
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for r in offered:
            groups[(r["harness"], r["version"], r.get("variant", "base"), r["surface_run"])].append(r)
        md += ["## Launches where the harness did not offer the scripted tool up front", "",
               "These are not in any n above. The harness did not list the tool the stub was scripted to call among the tools "
               "the model was offered in its first request (tool search or a resource tool the build lacks), so the cell "
               "is read from the logs instead: what the model was sent, whether the call was dispatched anyway (a tool "
               "result reached the model), and which hook events saw it.", "",
               "| build | launch | launches | tool declaration (DESC) in the model request "
               "| instructions (INSTR) in the model request | scripted call dispatched anyway (RESULT reached the model) "
               "| result hook saw it | resources/list asked | resources/read asked | tools offered in the first request |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        for (h, v, var, run), rs in sorted(groups.items()):
            n = len(rs)

            def count(f):
                return sum(1 for r in rs if f(r))

            tools = sorted({t for r in rs for t in r["offered_tools_first_request"]})
            mcp = [t for t in tools if "probe" in t or "resource" in t]
            md.append(
                f"| {h} {v}{'' if var == 'base' else ' (' + var + ')'} | {run} | {n} | "
                f"{count(lambda r: r['surfaces']['DESC']['model_requests_carrying'] > 0)}/{n} | "
                f"{count(lambda r: r['surfaces']['INSTR']['model_requests_carrying'] > 0)}/{n} | "
                f"{count(lambda r: r['surfaces']['RESULT']['model_requests_carrying'] > 0)}/{n} | "
                f"{count(lambda r: r['surfaces']['RESULT']['seen_by_result_hook'])}/{n} | "
                f"{count(lambda r: r['probe_requests'].get('resources/list'))}/{n} | "
                f"{count(lambda r: r['probe_requests'].get('resources/read'))}/{n} | "
                f"{len(tools)} tools; probe or resource tools among them: {', '.join(mcp) or 'none'} |")
        md.append("")
    launched = sum(1 for r in ledger if r.get("launched"))
    md += ["## Launch ledger", "",
           f"Launches recorded in this directory's ledger: {launched} (rows: {len(rows)}). "
           "Preliminary and debug launches that are not rows here are listed in `launches.json`.", ""]
    (out / "summary.md").write_text("\n".join(md))
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
