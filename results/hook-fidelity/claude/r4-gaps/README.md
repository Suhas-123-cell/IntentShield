# Claude Code round 4 gap cells (lane r4-gaps)

Arm S only: the Claude Code binary runs against the local stub model on 127.0.0.1 with a fake key, an isolated HOME and
CLAUDE_CONFIG_DIR per run, the loopback-only `sandbox-exec` profile (`loopback-sandbox` on all 41 rows, 0 egress attempts, 0
INVALID), `ENABLE_TOOL_SEARCH=false`, telemetry and non-essential traffic off. M1h shell unless a cell says otherwise
(`-p --allowedTools Bash`, the default of `-p`), one `PreToolUse` hook, timeout 3 s. No real model, no paid API, no DeepSeek.
Rows: `onfailure/`, `bisect/`, `permissionrequest/` (each `runs.jsonl`, `streams/`, `launches.jsonl`).

## (c1) `onFailure: "block"` on a release before 2.1.295 (2.1.281), n=2

| harness | build | mode | tool | trust state | onFailure | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|---|
| claude | 2.1.281 | M1h | shell | - | - | R9 | RAN 2/2 | 2/2 |
| claude | 2.1.281 | M1h | shell | - | block | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.281 | M1h | shell | - | block | R8 | RAN 2/2 | 2/2 |
| claude | 2.1.281 | M1h | shell | - | block | R9 | RAN 2/2 | 2/2 |

- **The key has no effect on 2.1.281**: with `onFailure: "block"` set, R9 (timeout) RAN 2/2 and R8 (exit 1) RAN 2/2, hook invoked 2/2
  each, the same as R9 without the key (RAN 2/2) and the R1 control (RAN 2/2). On 2.1.316 the same cells were BLOCKED 3/3
  (round 3). So the fail-closed setting works from a release at or after the documented 2.1.295 and is silently ignored before it;
  no error was raised (the runs completed, 0 INVALID). 2.1.295 itself had no `block` cell here; the round-3 sweep has R9 plain
  RAN 2/2 on it. The boundary between 2.1.281 and 2.1.316 is not bisected.

## (c2) Bisect of the `ask` flip between the sampled 2.1.69 and 2.1.89 (M1h shell, Bash pre-approved, R1 R3 R4 at n=2 per step)

Five steps (2.1.78, 2.1.83, 2.1.86, 2.1.84, 2.1.85), each an installable bundled `cli.js` release installed with `--ignore-scripts` in
seconds (the 17 releases 2.1.70 to 2.1.87 were installed; only these five were run).

| harness | build | mode | tool | trust state | onFailure | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|---|
| claude | 2.1.78 | M1h | shell | - | - | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.78 | M1h | shell | - | - | R3 | RAN 2/2 | 2/2 |
| claude | 2.1.78 | M1h | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.83 | M1h | shell | - | - | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.83 | M1h | shell | - | - | R3 | RAN 2/2 | 2/2 |
| claude | 2.1.83 | M1h | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.84 | M1h | shell | - | - | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.84 | M1h | shell | - | - | R3 | RAN 2/2 | 2/2 |
| claude | 2.1.84 | M1h | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.85 | M1h | shell | - | - | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.85 | M1h | shell | - | - | R3 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.85 | M1h | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.86 | M1h | shell | - | - | R1 | RAN 2/2 | 2/2 |
| claude | 2.1.86 | M1h | shell | - | - | R3 | BLOCKED 2/2 | 2/2 |
| claude | 2.1.86 | M1h | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |

- **The flip is between 2.1.84 and 2.1.85**: R3 (ask) RAN 2/2 on 2.1.78, 2.1.83 and 2.1.84 (hook invoked 2/2) and BLOCKED 2/2 on
  2.1.85 and 2.1.86, with the R1 control RAN 2/2 and R4 BLOCKED 2/2 on every step. Together with round 3 (RAN 2/2 on 2.0.41,
  2.1.47, 2.1.69; BLOCKED 2/2 on 2.1.89 onward), the ask stops the call from 2.1.85, on the releases that exist: 2.1.84 and 2.1.85
  are adjacent published releases (consecutive patch numbers, so no release lies between them), so the boundary is exact for this
  cell, at n=2 per build.
- The public CHANGELOG entry of 2.1.85 (fetched 2026-11-01 from the vendor repository, not archived here) has no line saying that a hook
  `ask` is now denied in `-p`. It has two hook and permission lines: a conditional `if` field for hooks written in permission-rule
  syntax, and "PreToolUse hooks can now satisfy `AskUserQuestion` by returning `updatedInput` alongside `permissionDecision: \"allow\"`
  (headless integrations)". Whether either is the cause is not established; the change may be undocumented.
- Round-3 caveat stands: Bash was pre-approved, so this cannot say whether the old builds ignored the ask or whether the allow rule
  beat it. A nothing-pre-approved (M0h) pair on 2.1.84 versus 2.1.85 would separate them; it was **not run** (outside the cells
  asked for).

## (c3) Does `PermissionRequest` fire in `-p` without bypass and without `--allowedTools`? (2.1.316, M0h, R1, 3 launches)

Config: `-p` with nothing pre-approved and no `--dangerously-skip-permissions`; the neutral `PreToolUse` hook R1 plus a passive
`PermissionRequest` hook (`coverage_hook.py`, replies nothing) registered through `--settings`. Events and raw payloads are in
`permissionrequest/hook-events/` (payload paths scrubbed).

| harness | build | mode | tool | trust state | onFailure | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|---|
| claude | 2.1.316 | M0h | mcp | - | - | R1 | BLOCKED 1/1 | 1/1 |
| claude | 2.1.316 | M0h | shell | - | - | R1 | BLOCKED 2/2 | 2/2 |

- **`PermissionRequest` fired in 3 of 3 launches** (shell 2/2, MCP 1/1), once per launch, for the tool the stub called. The call
  was then denied by the native flow ("needs approval" / "haven't granted it yet"), so BLOCKED 3/3 with the hook replying nothing.
  In round 3 the event fired 0 times because every launch ran under a bypass mode.
- **What it carries** (raw event keys): `session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode` (`default`),
  `effort`, `hook_event_name`, `tool_name`, `tool_input` (for Bash the command, e.g. `touch ran-<nonce>.txt`),
  `permission_suggestions` (add-directories and set-mode suggestions) and, for the MCP tool, `mcp_server`
  (`{"name": "notes", "source": "dynamic"}`). 822 to 872 bytes. It carries no tool description, no server instructions and no
  prompt text: a `PermissionRequest` guard sees what a `PreToolUse` guard sees plus the suggestions.
- Not measured: whether a `PermissionRequest` hook's `allow` or `deny` is honoured in `-p` (the hook here answered nothing), and whether
  the event fires on builds other than 2.1.316.

## Accounting

`HOOK_FIDELITY_GO`: onfailure 8, bisect 6 per step (5 steps, 30), permissionrequest 3; actual runs equal planned. Version probes
1, 5 and 1. See `../../r4-gaps-ledger.json`.
