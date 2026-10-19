# Results behind the papers

Raw outputs of every experiment `docs/icse27-demo/main.tex` and `docs/artifact-paper.md` cite,
verified on 2026-10-20. Write numbers from these files, not from older notes.

## Regenerate

```sh
# MSB: every table, paired bootstrap difference, review load and the Gemini breakdown.
# Needs only the MSB checkout for the case grid (artifacts/data/MSB), no Docker or model.
.venv/bin/python benchmarks/paper_numbers.py            # checks MANIFEST.json hashes first
```

The other directories are the outputs of the commands below, rerun on current code on 2026-10-19
and identical to the earlier runs where one existed.

| Directory | What | Command |
|---|---|---|
| `msb/<model>/<arm>.jsonl` | MSB held-out traces, 220 cases (Gemini: 99) | `benchmarks/msb.py --per-type 20 --holdout` (see `MANIFEST.json`) |
| `mcptox/` | MCPTox replay, all proxy layers | `benchmarks/mcptox.py --replay --lenient-reads` |
| `injection/` | output-injection detectors, 3,717 held-out rows | `benchmarks/injection_eval.py --exemplars artifacts/exemplars --prompt-guard --combine ...` |
| `agentdojo/` | structural floor on AgentDojo's published GPT-4o logs | `benchmarks/agentdojo_floor.py replay` |
| `harness-live/` | live Claude Code (Haiku) vs the malicious notes server, 3 prompts x 3 arms | `OUT=... benchmarks/harness_live/run.sh` |
| `latency.json` (cited, 2026-10-16), `latency-rerun-2026-10-19.json` | hook and proxy overhead on an Apple M5; in the rerun, per-event and per-call figures agree within 0.1 ms and start-up differs by up to 18 ms (interpreter 17 vs 15 ms, proxy start-up overhead 257 vs 275 ms) | `benchmarks/latency.py` |
| `adaptive-attacker.json` | adaptive attacker vs static and learning detectors | `benchmarks/adaptive_attacker.py` |

## MSB arms

| Arm | Defense | Intent model |
|---|---|---|
| `none` | no guard | - |
| `baseline` | trivial guard: withhold descriptions, strip self-disclosure fields, hold every mutation | - |
| `gateway` | IntentShield gateway | off |
| `hooks` | IntentShield hooks (Claude Code adapter) | off |
| `gateway-intent-veto` | gateway, DeBERTa v2 as a veto (MSB v10) | on |
| `gateway-intent-advisory` | gateway, DeBERTa v2 as advisory evidence (MSB v11) | on |
| `gateway-prompt-guard` | gateway plus Llama Prompt Guard 2 (qwen only) | off |

**Code versions.** Every arm ran on code whose guard and runner behave as at commit `0a3776d`,
apart from the intent model. The qwen2.5:7b `none`, `baseline` and `gateway` arms are the MSB v12
reruns of 2026-10-19; the originals (2026-10-12/13) predated gateway and hook fixes. Runs from v12
on carry their commit, intent model hash, Ollama model digest and container image in
`MANIFEST.json`; older runs have `"provenance": null`, and their dates and commits are in
`docs/artifact-paper.md` §4.

**Reproducibility.** Agents ran at temperature 0, one run per arm. Rerunning llama3.1:8b `none`
five days later reproduced all 220 call sequences and every per-case metric; 24 final answers
differed only in wording.

**Known gaps.** Cases a server failed to start for (`c0343`) or the agent timed out on are listed
per arm by `paper_numbers.py` and dropped from every arm of that model. The descriptions-exposed and
hooks-with-intent-on qwen arms ran on older code and are not here.
