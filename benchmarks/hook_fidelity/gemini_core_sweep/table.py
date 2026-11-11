"""Tables and a manifest from the raw rows of the Gemini hook-runner sweep (driver.mjs). Reads only raw rows.

    python3 table.py RAW_DIR OUT_DIR [SWEEP_DIR]

RAW_DIR holds one <version>.jsonl per release (one record per scripted reply). OUT_DIR gets

  table-per-version.txt  every scenario x every version (decision/proceeds, with * where layers A and B disagree)
  table.md               the same, with consecutive versions that behave identically merged into one column; the groups are
                         also split at HOOK_DEFAULT_BOUNDARY (hooks are opt-in before it, on by default from it), because
                         the runner-level behaviour alone does not say whether a hook runs at all
  raw/<version>.jsonl    the raw rows with scratch and home paths scrubbed (what is committed)
  manifest.json          per version: the package version and, when SWEEP_DIR (the scratch installs) is given, the npm
                         integrity hash of the installed @google/gemini-cli-core from its package-lock.json, and, when
                         OUT_DIR/registry-integrity.json exists (registry_integrity.sh: `npm view ... dist.integrity`), the
                         registry's hash and whether the two agree
  table-layer-c.md       the real HookSystem (settings-shaped hooks.BeforeTool config) scenarios, from RAW_DIR/layerc/<v>.jsonl
  table-consumer.md      the Scheduler, policy and tool probe (hook ask at the consumer, headless, MCP trust), from
                         RAW_DIR/consumer/<v>.jsonl
  boundary.md            runs of releases with byte-identical hook runner files, from boundary-raw.jsonl (next to RAW_DIR or in
                         OUT_DIR; boundary_scan.sh)

Cell notation: ``decision/proceeds``. ``proceeds`` is ``yes`` (the tool call goes ahead), ``no`` (blocked), ``ask-kept`` (the
aggregator kept an ask: what the scheduler and the tool do with it is NOT driven here) or ``hang`` (the runner did not return).
``none`` means the runner produced no output object: the call goes ahead and the hook error is ignored.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# core and CLI both turn hooks on by default from this release (read in the 0.22.5, 0.25.2 and 0.26.0 packages)
HOOK_DEFAULT_BOUNDARY = "0.26.0"


def version_key(version: str) -> list:
    base, _, pre = version.partition("-")
    numbers = [int(x) if x.isdigit() else 0 for x in base.split(".")]
    return [*numbers, 1 if pre else 0, pre]


_TMP = re.compile(r"/(?:private/)?(?:tmp|var/folders)/[^\s\"\\']*")
_HOME = re.compile(r"/(?:Users|home)/[^/\s\"\\']+")


def scrub(text: str) -> str:
    """Scratch-directory and home paths removed from a raw row before it is committed."""
    return _HOME.sub("/<user>", _TMP.sub("<tmp>", text))


def load(raw: Path) -> tuple[list[str], dict[tuple[str, str], dict], list[str]]:
    versions = sorted((f.stem for f in raw.glob("*.jsonl")), key=version_key)
    rows: dict[tuple[str, str], dict] = {}
    scenarios: list[str] = []
    for version in versions:
        for line in (raw / f"{version}.jsonl").read_text().splitlines():
            record = json.loads(line)
            rows[(version, record["scenario"])] = record
            if record["scenario"] not in scenarios:
                scenarios.append(record["scenario"])
    return versions, rows, scenarios


def cell(record: dict | None) -> str:
    if record is None:
        return "-"
    if "driverError" in record:
        return "DRIVER-ERROR"
    a, b = record["layerA"], record["layerB"]
    text = f"{a['decision']}/{a['proceeds']}"
    if a["decision"] == "no-return":
        return text
    if not b.get("ok", False) or (b.get("decision"), b.get("proceeds")) != (a["decision"], a["proceeds"]):
        text += "*"
    return text


def exit_codes(rows: dict, versions: list[str], scenario: str) -> str:
    seen = {str(rows[(v, scenario)]["layerA"]["run"]["exitCode"]) for v in versions
            if (v, scenario) in rows and "layerA" in rows[(v, scenario)]}
    return ",".join(sorted(seen))


def groups(versions: list[str], rows: dict, scenarios: list[str]) -> list[list[str]]:
    out: list[list[str]] = []
    for version in versions:
        vector = tuple(cell(rows.get((version, s))) for s in scenarios)
        if out:
            previous = tuple(cell(rows.get((out[-1][-1], s))) for s in scenarios)
            boundary = version == HOOK_DEFAULT_BOUNDARY
            if vector == previous and not boundary:
                out[-1].append(version)
                continue
        out.append([version])
    return out


def label(group: list[str]) -> str:
    short = [v.replace("0.67.0-nightly.20261031.g6814e00d6", "nightly") for v in group]
    return short[0] if len(short) == 1 else f"{short[0]} .. {short[-1]}"


def per_version(versions: list[str], rows: dict, scenarios: list[str]) -> str:
    lines = ["scenario | exit codes seen | " + " | ".join(v.replace("0.67.0-nightly.20261031.g6814e00d6", "nightly")
                                                          for v in versions)]
    for s in scenarios:
        cells = [cell(rows.get((v, s))) for v in versions]
        flag = "" if len(set(cells)) == 1 else "   <-- VARIES"
        lines.append(f"{s} | {exit_codes(rows, versions, s)} | " + " | ".join(cells) + flag)
    errors = sum(1 for r in rows.values() if "driverError" in r)
    lines.append(f"driver errors {errors}")
    return "\n".join(lines)


def grouped(versions: list[str], rows: dict, scenarios: list[str]) -> str:
    gs = groups(versions, rows, scenarios)
    head = "| scenario (exit codes) | " + " | ".join(f"`{label(g)}`" for g in gs) + " |"
    lines = [head, "|---|" + "---|" * len(gs)]
    for s in scenarios:
        cells = [cell(rows.get((g[0], s))) for g in gs]
        lines.append(f"| {s} ({exit_codes(rows, versions, s)}) | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Version groups: " + "; ".join(f"[{label(g)}] = {', '.join(g)}" for g in gs))
    lines.append("")
    lines.append(f"Groups are consecutive SAMPLED releases that behave identically at the runner level, split at "
                 f"{HOOK_DEFAULT_BOUNDARY} where hooks become enabled by default. Behaviour between two sampled releases is "
                 "inferred, not run. `ask-kept` means the aggregator kept the ask; it is not a statement about prompting.")
    lines.append("")
    lines.append("Where the behaviour changes (each change happened between the two SAMPLED releases named, not at a release "
                 "this sweep ran; boundary_scan.sh hashes the hook runner of the unsampled releases in between):")
    for before, after in zip(gs, gs[1:]):
        changed = [s for s in scenarios if cell(rows.get((before[-1], s))) != cell(rows.get((after[0], s)))]
        lines.append(f"- between sampled releases {before[-1]} and {after[0]}: "
                     + (", ".join(changed) if changed else
                        f"no runner-level change (split because {after[0]} is where hooks become enabled by default)"))
    return "\n".join(lines)


def manifest(versions: list[str], rows: dict, sweep: Path | None, registry: dict | None = None) -> dict:
    out = {}
    for version in versions:
        record = next((r for (v, _), r in rows.items() if v == version), {})
        entry = {"pkgVersion": record.get("pkgVersion"), "integrity": None}
        if registry is not None:
            entry["registry_integrity"] = registry.get(version)
        if sweep:
            lock = sweep / version / "package-lock.json"
            try:
                packages = json.loads(lock.read_text()).get("packages", {})
                entry["integrity"] = packages.get("node_modules/@google/gemini-cli-core", {}).get("integrity")
            except (OSError, ValueError):
                pass
        if registry is not None:
            entry["integrity_match"] = bool(entry["integrity"]) and entry["integrity"] == entry.get("registry_integrity")
        out[version] = entry
    return out


# ---------------------------------------------------------------------------------------------------------------
# Layer C (real HookSystem) and the consumer probe: separate raw directories, same grouping idea
def load_dir(directory: Path) -> tuple[list[str], dict[tuple[str, str], dict], list[str]]:
    return load(directory) if directory.is_dir() else ([], {}, [])


def cell_c(record: dict | None) -> str:
    if record is None:
        return "-"
    if "driverError" in record:
        return "DRIVER-ERROR"
    if record.get("kind") == "default":
        return f"getEnableHooks={record.get('getEnableHooks')}"
    text = f"{record['decision']}/{record['proceeds']}"
    if record.get("kind") in ("multi", "matcher", "trust"):
        text += f" hook-runs={record.get('invocations')}"
    return text


def cell_consumer(record: dict | None) -> str:
    if record is None:
        return "-"
    if "driverError" in record:
        return "DRIVER-ERROR"
    if record.get("kind") == "direct":
        forced = record.get("forced", {})
        short = lambda t: t.replace("false(no confirmation: proceeds)", "no-prompt").replace("details:", "prompt:")
        return f"no-forced: {short(forced.get('none', '?'))}; ask_user: {short(forced.get('ask_user', '?'))}"
    outcome = record.get("outcome", "?")
    error = record.get("error") or ""
    if outcome == "ERROR":
        if "not found" in error:
            return "ERROR:tool-not-offered"
        if "blocked" in error:
            return "ERROR:hook-deny"
        if "denied by policy" in error:
            return "ERROR:policy-deny"
        if "non-interactive" in error:
            return "ERROR:noninteractive-ask"
        return "ERROR:" + error[:40]
    return outcome


def boundary_report(rows: list[dict]) -> str:
    """Runs of releases whose hook runner, aggregator and event handler files are byte-identical (boundary_scan.sh rows, every
    non-nightly release in the scanned range, in publish-semver order: a preview sorts before its stable release). Says where
    a changed behaviour between two SAMPLED releases can have come in: only at a release whose files differ from the one
    before."""
    def key(version: str) -> tuple:
        base, _, pre = version.partition("-")
        return (*[int(x) for x in base.split(".")], 1 if not pre else 0, pre)
    ok = sorted((r for r in rows if "error" not in r), key=lambda r: key(r["version"]))
    files = ("hookRunner.js", "hookAggregator.js", "hookEventHandler.js")
    runs: list[list[dict]] = []
    for row in ok:
        if runs and all(runs[-1][-1].get(f) == row.get(f) for f in files):
            runs[-1].append(row)
        else:
            runs.append([row])
    lines = ["## Hook runner files across every non-nightly release in the range", "",
             f"{len(ok)} releases hashed ({len(rows) - len(ok)} failed to download). A line is a run of consecutive "
             "releases whose "
             "hookRunner.js, hookAggregator.js and hookEventHandler.js are byte-identical (first 16 hex digits of sha256, "
             "`hookRunner/hookAggregator/hookEventHandler`). The files are compared, not executed: a different file is not shown "
             "to behave differently, and an identical file is not shown to behave identically if something it calls changed.", ""]
    for run in runs:
        first, last = run[0], run[-1]
        lines.append(f"- `{first['version']}` .. `{last['version']}` ({len(run)} releases): "
                     + "/".join(str(first.get(f))[:8] for f in files))
    shell = [r for r in ok if r.get("shell_forcedDecision_mentions") is not None]
    if shell:
        lines += ["", "Mentions of `forcedDecision` in the shell tool's source (0 means its `shouldConfirmExecute` takes no "
                  "forced decision, so a hook `ask` on a shell call is dropped there):", ""]
        marks: list[list[dict]] = []
        for row in shell:
            if marks and marks[-1][-1]["shell_forcedDecision_mentions"] == row["shell_forcedDecision_mentions"]:
                marks[-1].append(row)
            else:
                marks.append([row])
        for run in marks:
            lines.append(f"- `{run[0]['version']}` .. `{run[-1]['version']}` ({len(run)} releases): "
                         f"{run[0]['shell_forcedDecision_mentions']}")
    return "\n".join(lines)


def grouped_generic(versions: list[str], rows: dict, scenarios: list[str], cellfn, title: str, note: str) -> str:
    gs: list[list[str]] = []
    for version in versions:
        vector = tuple(cellfn(rows.get((version, s))) for s in scenarios)
        if gs and vector == tuple(cellfn(rows.get((gs[-1][-1], s))) for s in scenarios) and version != HOOK_DEFAULT_BOUNDARY:
            gs[-1].append(version)
        else:
            gs.append([version])
    head = "| scenario | " + " | ".join(f"`{label(g)}`" for g in gs) + " |"
    lines = [f"## {title}", "", head, "|---|" + "---|" * len(gs)]
    for s in scenarios:
        lines.append(f"| {s} | " + " | ".join(cellfn(rows.get((g[0], s))) for g in gs) + " |")
    lines += ["", "Version groups: " + "; ".join(f"[{label(g)}] = {', '.join(g)}" for g in gs), "", note]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    raw, out = Path(argv[0]), Path(argv[1])
    sweep = Path(argv[2]) if len(argv) > 2 else None
    versions, rows, scenarios = load(raw)
    if not versions:
        print(f"no rows in {raw}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "raw").mkdir(exist_ok=True)
    for version in versions:  # the committed copy of the raw rows, scrubbed of local paths
        (out / "raw" / f"{version}.jsonl").write_text(scrub((raw / f"{version}.jsonl").read_text()))
    (out / "table-per-version.txt").write_text(per_version(versions, rows, scenarios) + "\n")
    (out / "table.md").write_text(grouped(versions, rows, scenarios) + "\n")
    registry = None
    try:
        registry = json.loads((out / "registry-integrity.json").read_text())
    except (OSError, ValueError):
        pass
    (out / "manifest.json").write_text(json.dumps(manifest(versions, rows, sweep, registry), indent=1, sort_keys=True) + "\n")
    for sub, name, cellfn, title, note in (
            ("layerc", "table-layer-c.md", cell_c,
             "Layer C: the real HookSystem built from a settings-shaped hooks.BeforeTool config",
             "Cells are `decision/proceeds`; `hook-runs` is how many times a hook process ran (a matcher that does not "
             "select the tool gives none/yes with 0 runs). One Config, one HookSystem, the event handler of that release; "
             "nothing downstream of the hook output is driven here (see table-consumer.md)."),
            ("consumer", "table-consumer.md", cell_consumer,
             "Consumer side: the Scheduler, the policy engine and the tools",
             "RAN = the marker was written. PROMPT-WAIT = the call reached awaiting_approval and nothing answered within "
             "the bounded wait (a TUI user would see a prompt; the CLI end-to-end runs show what a headless run does). "
             "ERROR:* = the scheduler ended the call with that error (tool-not-offered: the registry did not hold the "
             "tool). `direct|...` rows call the invocation's own shouldConfirmExecute with and without forcedDecision "
             "'ask_user'. Boundaries are between the SAMPLED releases named.")):
        extra_versions, extra_rows, extra_scenarios = load_dir(raw / sub)
        if extra_versions:
            (out / "raw" / sub).mkdir(exist_ok=True)
            for version in extra_versions:
                (out / "raw" / sub / f"{version}.jsonl").write_text(scrub((raw / sub / f"{version}.jsonl").read_text()))
            (out / name).write_text(grouped_generic(extra_versions, extra_rows, extra_scenarios, cellfn, title, note) + "\n")
    boundary_src = raw.parent / "boundary-raw.jsonl"
    if not boundary_src.is_file():
        boundary_src = out / "boundary-raw.jsonl"
    if boundary_src.is_file():
        brows = [json.loads(line) for line in boundary_src.read_text().splitlines() if line.strip()]
        (out / "boundary.md").write_text(boundary_report(brows) + "\n")
        if boundary_src.parent != out:
            (out / "boundary-raw.jsonl").write_text(boundary_src.read_text())
    bad = sum(1 for r in rows.values() if "driverError" in r)
    print(f"{len(versions)} versions, {len(scenarios)} scenarios, {bad} driver errors; wrote {out}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
