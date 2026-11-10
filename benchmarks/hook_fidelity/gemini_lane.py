"""The cell lists of the Gemini end-to-end lane (round 3): what `run.py run --cells-json` is given. Launches nothing.

    python3 gemini_lane.py cells main  > cells-main.json      # 0.66.0, headless (M1) and yolo (M2), shell and MCP
    python3 gemini_lane.py cells sweep > cells-sweep.json     # shell, yolo, replies R1 R3 R4 R10b across the installed releases
    python3 gemini_lane.py bins RELEASES_DIR                  # the --bin gemini:<version>=<path> arguments
    python3 gemini_lane.py report RUNS.jsonl [--by-version [--transpose]]   # outcome counts k/n per cell, from the rows only
    python3 gemini_lane.py merge OUT_DIR RUN_DIR...           # rows and streams of several run.py output dirs, deduplicated

Arm S only (the loopback stub model endpoint, a fake key, an isolated HOME). The replies are the matrix's: R2 allow, R3 ask,
R4 deny, R5 empty stdout, R9 sleeps past the hook timeout, R10a a hook file that is not executable (exit 126, bash text), R10b a
shebang to a missing interpreter (exit 126, bash text), R13 a missing hook file (exit 127, bash text); R0 is no hook, R1 a
neutral hook (the controls of every block).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CURRENT = "0.66.0"
FULL = ("R2", "R3", "R4", "R5", "R9", "R10a", "R10b", "R13")
SHORT = ("R2", "R3", "R4")
SWEEP_REPLIES = ("R3", "R4", "R10b")
MAIN_REPS = 3
SWEEP_REPS = 2


def _cell(version: str, mode: str, kind: str, reply: str, state: str, reps: int) -> dict:
    return {"harness": "gemini", "version": version, "mode": mode, "kind": kind, "reply": reply, "state": state,
            "arm": "S", "tier": 0, "reps": reps}


def block(version: str, mode: str, kind: str, state: str, replies: tuple[str, ...], reps: int,
          controls=("R0", "R1")) -> list[dict]:
    return [_cell(version, mode, kind, r, state, reps) for r in (*controls, *replies)]


def main_cells() -> list[dict]:
    out: list[dict] = []
    for mode in ("M2", "M1"):
        out += block(CURRENT, mode, "shell", "-", FULL if mode == "M2" else SHORT, MAIN_REPS)
        for state in ("notrust", "trust"):
            full = mode == "M2" or state == "trust"   # headless default: only a trusted server is offered to the model at all
            out += block(CURRENT, mode, "mcp", state, FULL if full else SHORT, MAIN_REPS)
    return out


def sweep_cells(versions: list[str]) -> list[dict]:
    out: list[dict] = []
    for version in versions:
        out += block(version, "M2", "shell", "-", SWEEP_REPLIES, SWEEP_REPS, controls=("R1",))
    return out


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) if x.isdigit() else 0 for x in version.split("-")[0].split("."))


def installed(releases: Path) -> dict[str, Path]:
    found = {}
    for entry in releases.iterdir():
        binary = entry / "node_modules" / ".bin" / "gemini"
        if binary.exists():
            found[entry.name] = binary
    return dict(sorted(found.items(), key=lambda kv: version_key(kv[0])))


def report(rows: list[dict], by_version: bool = False, transpose: bool = False) -> str:
    """Outcome counts per cell as k/n, from the committed rows only. INVALID runs are listed apart and never counted in n.
    Rates are
    not computed: arm S is deterministic by construction, so a count that is not n/n or 0/n is a flaky cell to investigate."""
    from collections import Counter, defaultdict
    valid: dict[tuple, Counter] = defaultdict(Counter)
    invalid: Counter = Counter()
    versions: list[str] = []
    for row in rows:
        key = (row["mode"], row["kind"], row["state"], row["reply"])
        col = row["version"] if by_version else "all"
        if col not in versions:
            versions.append(col)
        if row["outcome"] == "INVALID":
            invalid[(key, col)] += 1
        else:
            valid[(key, col)][row["outcome"]] += 1
    versions.sort(key=version_key) if by_version else None
    order = {"R0": 0, "R1": 1}
    def reply_key(reply: str) -> tuple:
        return (order.get(reply, 2), int("".join(c for c in reply if c.isdigit()) or 0), reply)
    keys = sorted({k for k, _ in (*valid, *invalid)}, key=lambda k: (k[0], k[1], k[2], reply_key(k[3])))
    def text_of(key: tuple, col: str) -> str:
        counts, bad = valid.get((key, col), Counter()), invalid.get((key, col), 0)
        n = sum(counts.values())
        text = ", ".join(f"{o} {c}/{n}" for o, c in sorted(counts.items(), key=lambda kv: -kv[1])) or "-"
        return text + (f" (+{bad} INVALID)" if bad else "")
    if transpose:   # one row per version, one column per (mode, tool, trust, reply)
        heads = [" ".join(k) for k in keys]
        lines = ["| version | " + " | ".join(heads) + " |", "|---|" + "---|" * len(heads)]
        lines += [f"| {col} | " + " | ".join(text_of(key, col) for key in keys) + " |" for col in versions]
        return "\n".join(lines)
    lines = ["| mode | tool | trust | reply | " + " | ".join(versions) + " |", "|---|---|---|---|" + "---|" * len(versions)]
    for key in keys:
        lines.append(f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | " + " | ".join(text_of(key, col) for col in versions) + " |")
    return "\n".join(lines)


def merge(out: Path, run_dirs: list[Path]) -> dict:
    """One runs.jsonl and one streams/ from several `run.py run` output directories (a lane split over parallel runner processes,
    each seeded with the rows already done, so identical lines appear more than once). A line is kept once; the order is the
    order of first appearance. Returns counts."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "streams").mkdir(exist_ok=True)
    seen: set[str] = set()
    kept: list[str] = []
    copied = 0
    for directory in run_dirs:
        rows = directory / "runs.jsonl"
        if rows.is_file():
            for line in rows.read_text().splitlines():
                if line.strip() and line not in seen:
                    seen.add(line)
                    kept.append(line)
        for stream in sorted((directory / "streams").glob("*")) if (directory / "streams").is_dir() else []:
            target = out / "streams" / stream.name
            if not target.exists():
                target.write_text(stream.read_text())
                copied += 1
    (out / "runs.jsonl").write_text("".join(line + "\n" for line in kept))
    return {"rows": len(kept), "streams_copied": copied, "dirs": len(run_dirs)}


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "merge":
        print(json.dumps(merge(Path(argv[1]), [Path(a) for a in argv[2:]])))
        return 0
    if len(argv) >= 2 and argv[0] == "report":
        rows = [json.loads(line) for line in Path(argv[1]).read_text().splitlines() if line.strip()]
        print(report(rows, "--by-version" in argv, "--transpose" in argv))
        return 0
    if len(argv) >= 2 and argv[0] == "cells" and argv[1] in ("main", "sweep"):
        if argv[1] == "main":
            print(json.dumps(main_cells(), indent=1))
        else:
            versions = argv[2].split(",") if len(argv) > 2 else []
            if not versions:
                print("usage: gemini_lane.py cells sweep V1,V2,...", file=sys.stderr)
                return 2
            print(json.dumps(sweep_cells(versions), indent=1))
        return 0
    if len(argv) == 2 and argv[0] == "bins":
        for version, binary in installed(Path(argv[1])).items():
            print(f"--bin gemini:{version}={binary}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
