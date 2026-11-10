# Gemini CLI round 4 gap cells (lane r4-gaps): default headless approval with shell offered through an allowlist

Arm S only: the CLI runs against the local stub model on 127.0.0.1 with a fake key (`sk-stub-not-a-real-key`), an isolated HOME
(`GEMINI_CLI_HOME`) per run and the loopback-only `sandbox-exec` profile (`containment: loopback-sandbox` on all 35 rows, 0
egress attempts, 0 INVALID). Headless `-p`, **M1 = default approval mode** (no `--approval-mode yolo`), shell tool, one scripted
call, hook cap 90 s. Rows: `main/runs.jsonl` (30 rows), `smoke/runs.jsonl` (5 R1 rows run first to check the shell is
offered), each with `streams/`.

The variant, which no row field records: `--allowed-tools=run_shell_command` appended to the argv by `r4_variant.py`
(`R4_ADD_ARGS`), then the normal runner. Per-release key search: `gemini --help` of the installed 0.24.5 and 0.66.0 lists
`--allowed-tools` on both ("Tools that are allowed to run without confirmation"; on 0.66.0 marked DEPRECATED in favour of the
policy engine, still honoured). The flag was used on all five builds and worked on all five: `run_shell_command` was in the stub's
offered tool list in 35 of 35 rows, and R1 RAN 2/2 on every build. The settings-file equivalent (`tools.allowed`) and a policy-file
rule (`--policy`, 0.66.0) were **not** run.

Why this cell: in round 3, M1 without an allowlist had no shell tool at all (`tool_not_registered`), so no hook ask was observed
in M1 and the only headless ask cells were yolo. Here the shell is offered without yolo.

## k/n per cell (n=2, build x reply)

| harness | build | mode | tool | trust state | onFailure | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|---|
| gemini | 0.24.5 | M1 | shell | - | - | R1 | RAN 2/2 | 2/2 |
| gemini | 0.24.5 | M1 | shell | - | - | R3 | RAN 2/2 | 2/2 |
| gemini | 0.24.5 | M1 | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| gemini | 0.36.0 | M1 | shell | - | - | R1 | RAN 2/2 | 2/2 |
| gemini | 0.36.0 | M1 | shell | - | - | R3 | RAN 2/2 | 2/2 |
| gemini | 0.36.0 | M1 | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| gemini | 0.37.1 | M1 | shell | - | - | R1 | RAN 2/2 | 2/2 |
| gemini | 0.37.1 | M1 | shell | - | - | R3 | RAN 2/2 | 2/2 |
| gemini | 0.37.1 | M1 | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| gemini | 0.38.2 | M1 | shell | - | - | R1 | RAN 2/2 | 2/2 |
| gemini | 0.38.2 | M1 | shell | - | - | R3 | HUNG 2/2 | 2/2 |
| gemini | 0.38.2 | M1 | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |
| gemini | 0.66.0 | M1 | shell | - | - | R1 | RAN 2/2 | 2/2 |
| gemini | 0.66.0 | M1 | shell | - | - | R3 | HUNG 2/2 | 2/2 |
| gemini | 0.66.0 | M1 | shell | - | - | R4 | BLOCKED 2/2 | 2/2 |

Reading:

- **Deny is enforced** with the shell allow-listed: R4 BLOCKED 2/2 on each of 0.24.5, 0.36.0, 0.37.1, 0.38.2 and 0.66.0 (10/10),
  hook invoked each time, against R1 RAN 2/2 on each.
- **Ask (R3), M1 plus allowlist, equals the yolo outcome on every build tested**: RAN 2/2 on 0.24.5, 0.36.0 and 0.37.1 (hook
  invoked 2/2, the ask did not stop the call); HUNG 2/2 on 0.38.2 and 0.66.0 (hook invoked 2/2, no tool result, killed at the
  90 s cap). The yolo cells of round 3 for the same builds: RAN 2/2 on 0.24.5, 0.36.0, 0.37.1 and HUNG 2/2 on 0.38.2, and
  HUNG 3/3 on 0.66.0 (M2 shell).
- What this separates: the silent run of the ask on 0.24.5 to 0.37.1 and the hang on 0.38.2 and later are **not** products of yolo's
  auto-approval. They occur when the shell is merely allow-listed in the default mode: on 0.24.5 the runner coerces ask to allow
  (round-3 probe) and on 0.36.0 and 0.37.1 the shell tool drops the forced decision, so the call runs; on 0.38.2 and 0.66.0 the
  ask is kept and, with an allow rule present, the hook's ask still overrides it into a confirmation that headless mode cannot
  answer. The two causes on 0.24.5 versus 0.36.0 and 0.37.1 are from the offline probes of round 3, not from these rows.
- Caveats: n=2 on a deterministic stub; HUNG is a bounded 90 s wait and not proof of an unbounded one; the allowlist form tested is
  the CLI flag only; MCP tools were not run in this block; builds between the five are inferred, not run.

## Accounting

`HOOK_FIDELITY_GO` 5 for `smoke` (5 runs) and 30 for `main` (30 runs); version probes 5 and 5. See `../../r4-gaps-ledger.json`.
