# Guard byte captures and replay cells (round 3, lane guard-replay)

Files
* `captures.jsonl`: one record per (guard, hook entry point, payload shape, scenario): the exact stdout and stderr bytes (base64 and text), exit code and wall time of
  the guard's own hook entry point, run inside `sandbox-exec` (deny default, no network, writes only under a scratch directory, home unreadable) on a fixture payload.
  Four guards are `NOT-CAPTURED` records with the reason (dcg, tool-gate-hook: Rust, crates not cached offline; ggshield, hol-guard: dependencies not installed). `captures-meta.json`
  has the sandbox self-test, tool versions and the cargo evidence. Paths are scrubbed to `<scratch>` and `<home>`.
* `replay/`: the 21 distinct (stdout, stderr, exit) replies, `index.json` with the intent read from the bytes and the captures that produced each.
* `gemini-replay/<version>.jsonl`: each reply through the Gemini hook runner and aggregator, 22 core releases (the sweep's install tree), no model.
* `stub-rows.jsonl`: one row per harness launch of the final data set (Claude Code and Codex CLI against the local stub model, headless); `launches-final.jsonl` is its ledger.
  `stub-rows-attempt1-invalid.jsonl` is a first pass of 87 launches that is NOT data: its controls failed (Claude Code's shell tool could not make its task directory and Codex's
  seatbelt could not nest inside the outer sandbox), so every shell cell was blocked with or without a hook. Launch total: 3 wiring pilots + 87 invalid + 153 final = 243 (cap 300).
* `summary.json` and `table.md`: derived from the rows by `guard_replay.py table` (k/n and Wilson bounds at display).

Reproduce: `guard_capture.py capture`, `guard_replay.py index`, `guard_replay.py gemini`, `HOOK_FIDELITY_GO=<n> guard_replay.py stub-run --go <n>`, `guard_replay.py publish`, `guard_replay.py table`
(`benchmarks/hook_fidelity/`). The clones and the release installs live in the session scratch directory (`HF_SCRATCH`) and are not committed.

Headline (live harness cells): 5 of 38 tested cells let the guarded call run, by cause {'untrusted skip': 5}; Gemini runner layer: 0 of 110. Per run (`table.md` and `summary.json` `headline.per_run`): Claude Code the call ran in 0 of 66 runs; Codex trusted 0 of 18; Codex untrusted 12 of 12 with the hook invoked in 0 of 12. The replay index is committed (`replay/`): `guard_replay.py table --index replay --stub stub-rows.jsonl --gemini gemini-replay ...` regenerates `table.md` and `summary.json` from the branch alone; capture and stub-run still need `HF_SCRATCH` (clones and release installs).
