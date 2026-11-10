"""The Codex lane's cell lists (arm S, stub model endpoint): named selections for ``run.py run --matrix NAME``.

Written for the r3-codex lane. The generic ``cells.generate()`` has two Codex versions (0.165.0, 0.155.1) and n=2; this lane
runs the releases that are installed locally (0.131.0 to 0.166.0, 22 of them) with explicit repetitions, and the replies
R15 and R16 (exit 126 and 127), under a hard budget of 600 launches. Nothing here launches anything.

  pilot     the 10-run pilot of the study document (section 17) on 0.165.0
  bundled   a bundled model slug instead of the stub slug, to record the tool surface (R1 shell, R1 mcp, R4 shell)
  stage2    tier 0 and tier 1 cells on 0.165.0 and 0.166.0 at n=5 (controls included), headless (exec), shell and MCP,
            trusted-bypass and untrusted
  live      the neutral control R1 of sweep1 alone (shell, headless, trusted-bypass, n=2, every release except the two of
            stage2): proves per release that the hook is invoked at all, before the replies are spent on it
  sweep1    the key replies on shell, headless, trusted-bypass (R1 R3 R4 R7 R11 R16 R9) and untrusted (R4), n=2, every
            installed release except the two of stage2
  sweep1b   the same reply set on the two stage2 releases plus R5 R6 R8 R15 (the replies stage2 does not carry), n=2
  sweep2    the remaining replies (R5, R6, R8, R15) on every other release, n=2 (only if the budget allows)
  yolo      --dangerously-bypass-approvals-and-sandbox (M2): R1 R3 R4 R7 on shell at n=2, 0.165.0 and 0.166.0
  persisted the trusted-persisted state (the trust record a person creates through /hooks, written by codex_trust.py from
            the vendor loader's hooks/list answer; no bypass flag): R1 R3 R4 R7 on shell at n=2 for the releases whose
            trusted-bypass control showed no hook (DEAD_UNDER_BYPASS, found by `live`), R1 and R4 on 0.165.0 as the
            same-state check against its trusted-bypass block. Each run is two launches (the app-server, then exec).
  untrusted_r1  the neutral control of the untrusted block (shell, n=1) for the releases of sweep1l, so that the untrusted R4
            cells have a control in their own block (their liveness is borrowed from the trusted-bypass block anyway)
  sweep1l   sweep1 minus the releases of DEAD_UNDER_BYPASS (their bypass block cannot be scored: the hook never ran)
"""
from __future__ import annotations

import json
from pathlib import Path

from hook_fidelity import cells

RELEASES = ("0.131.0", "0.133.0", "0.134.0", "0.136.0", "0.140.0", "0.143.0", "0.145.0", "0.148.0", "0.149.0", "0.150.0",
            "0.152.0", "0.155.0", "0.158.0", "0.162.0", "0.164.0", "0.165.0", "0.166.0")
STAGE2_VERSIONS = ("0.165.0", "0.166.0")
PERSISTED = "trusted-persisted"
# Releases whose neutral control R1 showed no hook invocation under --dangerously-bypass-hook-trust (set from the `live` rows;
# tests/test_hook_fidelity.py checks the list against results/hook-fidelity/codex/runs.jsonl when that file exists).
DEAD_UNDER_BYPASS: tuple[str, ...] = ("0.131.0", "0.133.0", "0.134.0", "0.136.0", "0.140.0")
BYPASS, UNTRUSTED = "trusted-bypass", "untrusted"
SWEEP1_REPLIES = ("R1", "R3", "R4", "R7", "R11", "R16", "R9")
SWEEP1B_EXTRA = ("R5", "R6", "R8", "R15")


def _cell(version: str, mode: str, kind: str, reply: str, state: str, reps: int, tier: int) -> cells.Cell:
    return cells.Cell("codex", version, mode, kind, reply, state, arm="S", tier=tier, reps=reps)


def pilot() -> list[cells.Cell]:
    return cells.pilot_cells("codex")


def bundled() -> list[cells.Cell]:
    picks = (("shell", "R1"), ("mcp", "R1"), ("shell", "R4"))
    return [_cell("0.165.0", "M1", kind, reply, BYPASS, 1, 0) for kind, reply in picks]


def stage2() -> list[cells.Cell]:
    out = []
    for version in STAGE2_VERSIONS:
        for kind in ("shell", "mcp"):
            replies = ["R0", "R1", "R2", "R3", "R4", "R5", "R7", "R10b"] if kind == "shell" \
                else ["R0", "R1", "R3", "R4", "R5", "R7"]
            out += [_cell(version, "M1", kind, r, BYPASS, 5, 0 if r in ("R0", "R1", "R4") else 1) for r in replies]
            out += [_cell(version, "M1", kind, r, UNTRUSTED, 5, 0 if kind == "mcp" else 1) for r in ("R1", "R4")]
    return out


def live() -> list[cells.Cell]:
    return [c for c in sweep1() if c.reply == "R1"]


def sweep1() -> list[cells.Cell]:
    out = []
    for version in RELEASES:
        if version in STAGE2_VERSIONS:
            continue
        out += [_cell(version, "M1", "shell", r, BYPASS, 2, 2) for r in SWEEP1_REPLIES]
        out.append(_cell(version, "M1", "shell", "R4", UNTRUSTED, 2, 2))
    return out


def sweep1b() -> list[cells.Cell]:
    out = []
    for version in STAGE2_VERSIONS:
        out += [_cell(version, "M1", "shell", r, BYPASS, 2, 2) for r in ("R9", "R11", "R16", *SWEEP1B_EXTRA)]
    return out


def sweep2() -> list[cells.Cell]:
    return [_cell(v, "M1", "shell", r, BYPASS, 2, 3)
            for v in RELEASES if v not in STAGE2_VERSIONS for r in SWEEP1B_EXTRA]


def sweep1l() -> list[cells.Cell]:
    return [c for c in sweep1() if c.version not in DEAD_UNDER_BYPASS]


def untrusted_r1() -> list[cells.Cell]:
    return [_cell(c.version, "M1", "shell", "R1", UNTRUSTED, 1, 2) for c in sweep1l() if c.state == UNTRUSTED]


def persisted() -> list[cells.Cell]:
    out = [_cell(v, "M1", "shell", r, PERSISTED, 2, 2) for v in DEAD_UNDER_BYPASS for r in ("R1", "R3", "R4", "R7")]
    out += [_cell("0.165.0", "M1", "shell", r, PERSISTED, 2, 2) for r in ("R1", "R4")]
    return out


def r4_persisted() -> list[cells.Cell]:
    """Round 4 gap: the failure replies under the persisted trust state (no bypass flag) on the two stage2 releases, n=2, with the
    neutral control R1 and the deny control R4 of the same state on 0.166.0 (0.165.0 has them in the `persisted` matrix)."""
    out = [_cell(v, "M1", "shell", r, PERSISTED, 2, 2) for v in STAGE2_VERSIONS for r in ("R3", "R5", "R9", "R16", "R11")]
    out += [_cell("0.166.0", "M1", "shell", r, PERSISTED, 2, 2) for r in ("R1", "R4")]
    return out


def r4_persisted_b() -> list[cells.Cell]:
    """Round 4 integration: the persisted-trust replies the gap lane left out (malformed JSON, exit 1, exit 126), 0.166.0, n=2."""
    return [_cell("0.166.0", "M1", "shell", r, PERSISTED, 2, 2) for r in ("R6", "R8", "R15")]


def r4_r0() -> list[cells.Cell]:
    """Round 4 gap: one no-hook row (R0) for every sampled sweep release that has none (all but 0.165.0 and 0.166.0)."""
    return [_cell(v, "M1", "shell", "R0", BYPASS, 1, 2) for v in RELEASES if v not in STAGE2_VERSIONS]


def yolo() -> list[cells.Cell]:
    return [_cell(v, "M2", "shell", r, BYPASS, 2, 3) for v in STAGE2_VERSIONS for r in ("R1", "R3", "R4", "R7")]


MATRICES = {"pilot": pilot, "bundled": bundled, "stage2": stage2, "live": live, "sweep1": sweep1, "sweep1b": sweep1b,
            "sweep2": sweep2, "yolo": yolo, "persisted": persisted,
            "sweep1l": sweep1l, "untrusted_r1": untrusted_r1, "r4_persisted": r4_persisted, "r4_r0": r4_r0,
            "r4_persisted_b": r4_persisted_b}


def select(name: str) -> list[cells.Cell]:
    if name not in MATRICES:
        raise ValueError(f"unknown matrix {name!r}; known: {', '.join(MATRICES)}")
    return MATRICES[name]()


def manifest_binaries(manifest: Path) -> dict[str, str]:
    """``codex:<version>`` -> binary path for every release of the manifest that reported its version (the ones that hang on
    --version are left out)."""
    data = json.loads(Path(manifest).read_text())
    return {f"codex:{v['version']}": v["binary_path"] for v in data["versions"] if v.get("version_ok")}


if __name__ == "__main__":
    for name, fn in MATRICES.items():
        selection = fn()
        print(f"{name:8} {len(selection):3} cells {sum(c.reps for c in selection):4} runs")
