# Codex round 4 integration cells

Arm S only: the same containment as `../r4-gaps/` (stub model on 127.0.0.1, fake key, isolated HOME and CODEX_HOME per run, apps and plugins
off, refusing egress proxy on 127.0.0.1:18997 whose log file was never created: 0 requests in all 10 runs). `codex exec`, M1, shell, one scripted
call. Rows: `runs.jsonl` (6 rows), `bisect/runs.jsonl` (4 rows), 0 INVALID, `home_isolated` true on all 10. No real model, no paid API, no Cursor.

## Persisted-trust failure replies the gap lane left out (`r4_persisted_b`, 0.166.0, n=2)

| harness | build | mode | tool | trust state | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|
| codex | 0.166.0 | M1 | shell | trusted-persisted | R6 malformed JSON | RAN 2/2 | 2/2 |
| codex | 0.166.0 | M1 | shell | trusted-persisted | R8 exit 1 | RAN 2/2 | 2/2 |
| codex | 0.166.0 | M1 | shell | trusted-persisted | R15 exit 126 | RAN 2/2 | 2/2 |

With `../r4-gaps/` (R3, R5, R9, R11, R16 on 0.165.0 and 0.166.0, 20 of 20 RAN), persisted trust now covers every failure reply of the study except
R10b on 0.166.0, and R6, R8, R15 on 0.165.0 are not run. Fail-open holds without the bypass flag for these replies on these builds.

## Bypass-flag boundary bisect (`bisect/`, R1, trusted-bypass, n=2)

| harness | build | mode | tool | trust state | reply | outcome k/n | hook invoked |
|---|---|---|---|---|---|---|---|
| codex | 0.141.0 | M1 | shell | trusted-bypass | R1 | RAN 2/2 | 2/2 |
| codex | 0.142.0 | M1 | shell | trusted-bypass | R1 | RAN 2/2 | 2/2 |

Round 3: R1 under the same flag had the hook invoked 0/2 on 0.131.0, 0.133.0, 0.134.0, 0.136.0 and 0.140.0 and 2/2 or 5/5 from 0.143.0. The
registry lists 0.140.0, 0.141.0, 0.142.x, 0.143.0 and no 0.140.x patch, so **the boundary is exact: 0.140.0 (hook not run) to 0.141.0 (hook runs)**
at n=2 per build. 0.141.0 and 0.142.0 were installed with `npm install --ignore-scripts` (no manifest entry; rows carry `binary_sha256`).

Reproduce: `codex_matrix.py` matrix `r4_persisted_b` (`run.py run OUT --matrix r4_persisted_b --execute --codex-manifest ... --egress-proxy
http://127.0.0.1:18997 --egress-log ...`); the bisect used `--cells-json` with R1 trusted-bypass cells for the two versions and a two-entry manifest.
`HOOK_FIDELITY_GO` was 6 and 4, the exact planned run counts; the persisted matrix also made 6 app-server `hooks/list` launches and 1 `--version`
probe, the bisect 2 probes.
