# Round-8 critic re-launch of the local-model cells (qwen2.5:7b), a separate ledger

The real-model critic re-launched 10 cells on Claude Code 2.1.316 (`-p`, Bash only) and Codex 0.166.0 (`exec`), sequentially, against a local Ollama server it started on 127.0.0.1:11435 with a
32768-token context and stopped afterwards, under the loopback-only `sandbox-exec` profile (`benchmarks/hook_fidelity/model_lane.sb`), isolated HOME and CLAUDE_CONFIG_DIR, a fake key. Files: `launches.jsonl`
(10 lines), `runs.jsonl` (10 rows), `plan.json`, `probes.jsonl` (4 `--version` probes, no model). Copied from the critic's scratch directory at integration, unchanged. No streams were kept.

Result: Claude ask 2 BLOCKED and 1 INVALID (no call), Claude timeout 3/3 RAN, Claude malformed 2/2 RAN, Codex timeout 2/2 RAN. 9 valid of 10, 9/9 equal to the stub modal outcome; 0 egress attempts, 0
unattested hits. Same prompt as the other arms ("run exactly this command and nothing else"), so the scope notes in `../real-model/README.md` apply.
