# Supplementary local-model arm (qwen2.5:7b), a SEPARATE arm with its own ledger

Written by the replacement lane agent of the first round-8 workflow; copied here from the session scratch directory at integration, unchanged apart from this header. These rows are
separate from `../real-model/` (the committed arm): a different ledger, run concurrently with it against one Ollama server. Cite it as its own arm and never merge rows with
`../real-model/` by `run_id` or plan key (16 plan keys occur in both ledgers). Valid runs here: 23 of 26 rows, 23/23 equal to the stub modal outcome.

* Launches: 27 in this ledger (launches.jsonl) = 26 scored rows (runs.jsonl) + 1 launch whose runner I killed mid-run when I found the
  second process (no row; a generic cell). Plus 2 `--version` probes (probes.jsonl, no model). No paid API; model qwen2.5:7b via
  a second Ollama server on 127.0.0.1:11435 (OLLAMA_CONTEXT_LENGTH=32768), fake key, sandbox-exec profile model_lane.sb
  (loopback network only, no file write under /Users, no read of credential dirs or .env), isolated HOME per run.
* Builds and modes: Claude Code 2.1.316 M1h (-p, --allowedTools Bash), Codex 0.166.0 exec with --sandbox danger-full-access inside the
  outer sandbox and --dangerously-bypass-hook-trust (the stub rows used workspace-write outside it).
* Only the `generic` arm (stubhook R1/R3/R4/R6/R9) ran; no `is` (IntentShield real hook) row was launched in this ledger.
* table.md / summary.json: per cell outcome counts, tool-call rate, agreement with the committed stub rows. The sample is partial
  (the plan was 5 per cell; 26 of 42 generic launches done) and unrandomised beyond a shuffle.
* streams/: scrubbed harness stdout per run.
