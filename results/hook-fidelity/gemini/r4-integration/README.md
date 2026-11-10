# Gemini CLI round 4 integration cells: the bound on the yolo ask hang

Arm S only: stub model on 127.0.0.1, a fake credential name only (`GEMINI_API_KEY` set to a placeholder to satisfy the runner's isolated-HOME
gate; the harness itself gets the stub key), isolated HOME (`GEMINI_CLI_HOME`), loopback-only `sandbox-exec` profile (`containment:
loopback-sandbox`, 0 egress attempts, `home_isolated` true on both rows). Headless `-p --approval-mode yolo` (M2), shell tool, reply R3 (ask), one
scripted call, **wall-clock cap 900 s** (the sweep used 90 s and 0.66.0 300 s). No real model, no paid API. Rows: `runs.jsonl` (2).

| harness | build | mode | tool | reply | outcome k/n | hook invoked | wall s |
|---|---|---|---|---|---|---|---|
| gemini | 0.66.0 | M2 | shell | R3 | HUNG 1/1 | 1/1 | 900.68 (cap hit) |
| gemini | 0.38.2 | M2 | shell | R3 | HUNG 1/1 | 1/1 | 900.71 (cap hit) |

Reading: with a cap of 900 s, ten times the sweep's, the ask still gets no answer on the newest build and on the first build with the held ask. A
bounded wait is still not proof of an unbounded one, but the hang is not an artefact of a short cap at 90 s or 300 s. n=1 per build on a
deterministic stub. `HOOK_FIDELITY_GO` 2 (the exact planned runs); 2 `--version` probes.

Reproduce: `run.py run OUT --execute --cells-json CELLS --cap-s 900 --pass-env GEMINI_API_KEY` with the Gemini bins of `gemini_lane.py bins`.
