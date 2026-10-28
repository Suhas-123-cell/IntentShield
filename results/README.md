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
and identical to the earlier runs where one existed. On 2026-10-21 the scripts stopped rounding rates and Wilson
bounds to 4 places before display (`7bd8b2e`), which had shifted some figures by 0.1 point.
`mcptox/report-replay-lenient.json` was regenerated and `injection/table.txt` rebuilt from its
report; every count is unchanged. Corrected figures: MCPTox rules recall 96.3% (290/301), call
layer benign review 46.7%, quarantine + provenance interval [0.8, 1.9].

On 2026-10-29 `mcptox/report-replay-lenient.json` was regenerated once more on current code, with the
command in the table below (offline, intent model off). Four counts moved: quarantine + provenance
attack success 19/1579 = 1.2% [0.8, 1.9] (was 20/1579 = 1.3% [0.8, 1.9]); call layer + provenance
attack success 550/1579 = 34.8% [32.5, 37.2] (was 552, 35.0%) and reached human 594/1579 (was 593);
full proxy reached human 12/1579 = 0.8% [0.4, 1.3] (was 13). Every other count is unchanged.

| Directory | What | Command |
|---|---|---|
| `msb/<model>/<arm>.jsonl` | MSB held-out traces, 220 cases (Gemini: 99) | `benchmarks/msb.py --per-type 20 --holdout` (see `MANIFEST.json`) |
| `mcptox/` | MCPTox replay, all proxy layers | `INTENTSHIELD_INTENT_MODEL_DIR=/nonexistent benchmarks/mcptox.py --data artifacts/data/MCPTox-Benchmark --replay --lenient-reads --out results/mcptox` |
| `injection/` | output-injection detectors, 3,717 held-out rows | `benchmarks/injection_eval.py --exemplars artifacts/exemplars --prompt-guard --combine ...` |
| `agentdojo/` | structural floor on AgentDojo's published GPT-4o logs | `benchmarks/agentdojo_floor.py replay` |
| `harness-live/` | live Claude Code (Haiku) vs the malicious notes server, 3 prompts x 3 arms | `OUT=... benchmarks/harness_live/run.sh` |
| `harness-live-gemini/` | the same check in Gemini CLI (gemini-3.1-flash-lite), with each agent's tool-call trace | `OUT=... benchmarks/harness_live/run_gemini.sh` |
| `real-incidents/report.txt` | four documented in-the-wild malicious-MCP incidents replayed through the guard (citations in `benchmarks/real_incidents/SOURCES.md`) | `benchmarks/real_incidents.py` |
| `latency.json` (2026-10-16), `latency-rerun-2026-10-19.json` | hook and proxy overhead on an Apple M5 before the threat memory was on by default: hook p50 35 ms per event as a process (the "35 ms" figure), 0.02 to 1.1 ms in process; transparent proxy +1.9 ms per call (p50 2.43 vs 0.54 ms direct). In the rerun, per-event and per-call figures agree within 0.1 ms and start-up differs by up to 18 ms (interpreter 17 vs 15 ms, proxy start-up overhead 257 vs 275 ms) | `benchmarks/latency.py` |
| `improve/baseline/latency.json` (code at `4dac01f`, threat memory on) | the source of the README's "about 42 ms per MCP call": hook p50 41 to 47 ms per event as a process, 0.02 to 2 ms in process; transparent proxy +1.9 ms per call (2.55 vs 0.65 ms) | `benchmarks/latency.py` (see `improve/README.md`) |
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

## Evaluation inputs copied from `artifacts/`

`artifacts/` is gitignored, so the inputs behind the injection and judge tables are copied here
(2026-10-29, byte for byte, all under 1.4 MB; checked for keys and real addresses: the only e-mail
addresses are the fictional ones in AgentDojo's and MCPTox's own task text).

| File | What | Feeds |
|---|---|---|
| `injection/dataset.jsonl` | 3,509 texts from `benchmarks/injection_data.py`: MCPTox poisoned (1,302) and clean (310) descriptions, their translations, and generated tool outputs; fields `text, label (instruction/data), source, group, split (train 1,931 / validation 660 / test 918)` | the injection table scores its `test` split (716 instruction, 202 data); `train` is what `intentshield.exemplars` builds the exemplar index from |
| `injection/hard_negatives.jsonl` | 294 hard benign texts from `benchmarks/hard_negatives.py` (usage guidance in descriptions, agent hints, human requests, quoted attacks, a few translated), all `label: data` | the table's 142 hard benign rows are its `test` split |
| `injection/agentdojo-strings.jsonl` | 532 AgentDojo strings from `benchmarks/agentdojo_export.py`: 397 environment texts (`data`) and 135 injected instructions, 27 per attack (`agentdojo_*`); copied from `artifacts/data/agentdojo-strings.jsonl` | the `external` split's `agentdojo_*` families |
| `judge/report-gemini_gemini-3.5-flash-lite.json` | `benchmarks/judge_eval.py --judge gemini` on 2026-10-12: Gemini 3.5 Flash-Lite on the held-out MCPTox descriptions; rates in this older file are rounded to 4 places (300/301 = 0.9967, 5/108 = 0.0463) | the README's "LLM judge on held-out descriptions" row for Gemini |
