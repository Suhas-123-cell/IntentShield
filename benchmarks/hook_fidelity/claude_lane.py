"""The r3-claude lane: Claude Code verdict fidelity on arm S (a stub model endpoint), per release and permission mode.

    run.py run OUT --lane claude-core --dry-run          # plan: how many runs each stage is
    HOOK_FIDELITY_GO=<n> run.py run OUT --execute --lane claude-core --bin claude:2.1.316=<path> ...

Stages (each a list of cells; nothing here launches anything):

  pilot  the 10 runs of section 17 of hook-fidelity-study.md (research-notes branch), as cells of this lane's modes
         (kept for the record; the
         pilot of the study was a bash script, see results/hook-fidelity/claude/pilot/)
  core   2.1.316, kinds shell / write / mcp / resource, replies R0 R1 R3 R4, n=5, in M1h (--allowedTools, the default of -p) and
         M2 (--dangerously-skip-permissions), and M1 (prompts none) for shell and mcp; M0h (nothing pre-approved) for
         shell and mcp with R2 (allow) as well; the matcher cells (state mcpwild: `mcp__.*`) for the resource-read gap
  fail   2.1.316, M1h: failure replies R5 R6 R7 R8 R9 R10a R10b R11 R13 at n=3 on shell, a reduced set on mcp, and the same
         under onFailure=block (documented for >= 2.1.295)
  sweep  every installed release but 2.1.316, M1h, shell: R1 R3 R4 R9 R10a at n=2

Modes M1h and M0h exist only here (cells.LANE_MODES): cells.generate() does not know them.
"""
from __future__ import annotations

from hook_fidelity import cells

HARNESS = "claude"
CURRENT = "2.1.316"
RELEASES = ("2.0.41", "2.1.0", "2.1.47", "2.1.69", "2.1.89", "2.1.118", "2.1.139", "2.1.163", "2.1.214", "2.1.246", "2.1.268",
            "2.1.280", "2.1.281", "2.1.290", "2.1.292", "2.1.295", "2.1.296", "2.1.299", "2.1.300", "2.1.304", "2.1.309",
            "2.1.314", CURRENT)
STAGES = ("pilot", "core", "fail", "sweep")
FAILURE_REPLIES = ("R5", "R6", "R7", "R8", "R9", "R10a", "R10b", "R11", "R13")
MCP_FAILURE_REPLIES = ("R5", "R7", "R9", "R10a")
SWEEP_REPLIES = ("R1", "R3", "R4", "R9", "R10a")
CORE_REPLIES = ("R0", "R1", "R3", "R4")
ONFAILURE_MIN = "2.1.295"


def _cell(version: str, mode: str, kind: str, reply: str, reps: int, tier: int, state: str = "-",
          failcfg: str = "-") -> cells.Cell:
    return cells.Cell(HARNESS, version, mode, kind, reply, state, failcfg, "plain", "S", tier, reps)


def pilot() -> list[cells.Cell]:
    return [_cell(CURRENT, "M1", kind, reply, 1, 0) for reply, kind in cells.PILOT_RUNS]


def core(reps: int = 5) -> list[cells.Cell]:
    out: list[cells.Cell] = []
    for mode in ("M1", "M1h", "M2"):
        for kind in ("shell", "write", "mcp", "resource"):
            for reply in CORE_REPLIES:
                if mode == "M1" and kind in ("write", "resource"):
                    continue            # M1 differs from M1h only by --permission-prompts none: shell and mcp are enough (budget)
                if mode == "M2" and kind in ("write", "resource") and reply == "R0":
                    continue            # budget (600 launches): R0 only where the block is the main one
                out.append(_cell(CURRENT, mode, kind, reply, reps, 0))
    for reply in ("R0", "R1", "R2", "R3", "R4"):     # nothing pre-approved: does a hook allow lift the native denial?
        out.append(_cell(CURRENT, "M0h", "shell", reply, reps, 1))
    for reply in ("R1", "R2", "R3"):
        out.append(_cell(CURRENT, "M0h", "mcp", reply, reps, 1))
    for reply in ("R1", "R3", "R4"):                  # the matcher gap: `mcp__.*` against a resource read
        out.append(_cell(CURRENT, "M1h", "resource", reply, reps, 0, state="mcpwild"))
    for reply in ("R1", "R4"):
        out.append(_cell(CURRENT, "M1h", "mcp", reply, 3, 1, state="mcpwild"))
    return _unique(out)


def fail(reps: int = 3) -> list[cells.Cell]:
    out: list[cells.Cell] = []
    for reply in FAILURE_REPLIES:                     # the controls R0 and R1 of these blocks come from the core stage (n=5)
        out.append(_cell(CURRENT, "M1h", "shell", reply, reps, 1))
    for reply in MCP_FAILURE_REPLIES:
        out.append(_cell(CURRENT, "M1h", "mcp", reply, reps, 1))
    out.append(_cell(CURRENT, "M1h", "shell", "R1", reps, 1, failcfg="block"))
    for reply in FAILURE_REPLIES:
        out.append(_cell(CURRENT, "M1h", "shell", reply, reps, 1, failcfg="block"))
    return _unique(out)


def sweep(reps: int = 2) -> list[cells.Cell]:
    out = [_cell(v, "M1h", "shell", r, reps, 4) for v in RELEASES if v != CURRENT for r in SWEEP_REPLIES]
    return out


def _unique(items: list[cells.Cell]) -> list[cells.Cell]:
    return list({c.key: c for c in items}.values())


def stage(name: str) -> list[cells.Cell]:
    return {"pilot": pilot, "core": core, "fail": fail, "sweep": sweep}[name]()


def selection(lane: str) -> list[cells.Cell]:
    """``claude-<stage>`` or ``claude-all`` (core, fail, sweep; the pilot is separate)."""
    name = lane.removeprefix("claude-")
    if name == "all":
        return [c for s in ("core", "fail", "sweep") for c in stage(s)]
    if name not in STAGES:
        raise ValueError(f"unknown lane {lane!r}; stages: {', '.join('claude-' + s for s in (*STAGES, 'all'))}")
    return stage(name)
