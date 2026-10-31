# Results behind the papers

Raw outputs of every experiment `docs/icse27-demo/main.tex` and `docs/artifact-paper.md` cite,
verified on 2026-10-20. Write numbers from these files, not from older notes.

## Regenerate

```sh
# MSB: every table, paired bootstrap difference, review load and the Gemini breakdown.
# Needs nothing outside results/ (the case grid is msb/cases.jsonl; an MSB checkout at artifacts/data/MSB is used if present), no Docker or model.
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
| `msb/cases.jsonl` | the MSB case grid (1,600 cases: id, attack type, agent, system prompt, task tool, task, attack task, implementation), as `benchmarks/msb.py cases()` builds it from the MSB checkout at commit `c1d6a70171e4d2c44c87a2ae909d13df00c6aa8d`; `paper_numbers.py` reads it when `artifacts/data/MSB` is absent, so a clean clone and CI can replay the tables | written 2026-10-29; sha256 in `MANIFEST.json` |
| `mcptox/` | MCPTox replay, all proxy layers | `INTENTSHIELD_INTENT_MODEL_DIR=/nonexistent benchmarks/mcptox.py --data artifacts/data/MCPTox-Benchmark --replay --lenient-reads --out results/mcptox` |
| `injection/` | output-injection detectors, 3,717 held-out rows | `benchmarks/injection_eval.py --exemplars artifacts/exemplars --prompt-guard --combine ...` |
| `agentdojo/` | structural floor on AgentDojo's published GPT-4o logs | `benchmarks/agentdojo_floor.py replay` |
| `harness-live/` | live Claude Code (Haiku) vs the malicious notes server, 3 prompts x 3 arms | `OUT=... benchmarks/harness_live/run.sh` |
| `harness-live-gemini/` | the same check in Gemini CLI (gemini-3.1-flash-lite), with each agent's tool-call trace | `OUT=... benchmarks/harness_live/run_gemini.sh` |
| `harness-live-builtin/<agent>/` | `--builtin-tools` live: Gemini CLI (3 reps), Claude Code with Haiku (3 reps) and with DeepSeek V4 Flash (1 rep), and Cursor CLI (`cursor-hooks/`, 1 rep, hooks arm only, no valid unguarded arm, 5 runs of which the benign one errored with `exit 1`); 4 attack pages and 1 benign page, no guard vs hooks; `runs.jsonl` per run, `summary.json` per agent (Cursor's covers its hooks arm only); `gemini-noretry/` is the hooks arm rerun after the no-retry fix. A run counts when the agent fetched the page and the session finished, or when the canary was hit whatever the exit status; the others are listed under `skipped_runs`. The rows hold no per-command trace, so `attempted` and `benign_done` were not recomputed; scoring was fixed on 2026-10-31 (whole-option upload flags, errored canary hits kept, line count checked) and the committed rows re-summarized with `builtin_live.py --summarize`: no cell changed | `benchmarks/harness_live/builtin_live.py --agents <agent> --reps N --out ...` |
| `real-incidents/report.txt` | four documented in-the-wild malicious-MCP incidents replayed through the guard (citations in `benchmarks/real_incidents/SOURCES.md`) | `benchmarks/real_incidents.py` |
| `harness-live-codex/`, `harness-live-codex-trusted/` | live Codex CLI 0.165 with a local qwen2.5:7b, 3 prompts x 3 arms (direct, hooks, hooks + proxy): the first with the hooks installed but untrusted (they never ran), the second with `--dangerously-bypass-hook-trust` (`hook-denials.txt` lists the denials); `calls-<n>-<arm>.jsonl` is each run's server-side call log | `OUT=... benchmarks/harness_live/run_codex.sh` (`CODEX_FLAGS="--dangerously-bypass-hook-trust"` for the trusted one) |
| `harness-live-cursor/`, `harness-live-cursor-grok/` | live Cursor CLI 2026.10.22 (model `auto`; the second directory is the unguarded arm with Grok models, 3 prompts) against the malicious MCP server; Cursor's model refused the injection in every arm, so these runs show the hooks run, not that they stop an attack | `OUT=... benchmarks/harness_live/run_cursor.sh [model]` |
| `cursor-hook-probe/runs.jsonl` | what Cursor CLI does with a fixed hook reply (`{}`, `allow`, `ask`, `deny`) on a shell command or an MCP tool, allowlisted or not; the source of finding HK4 and of the Cursor table in `docs/benchmarks.md` | `benchmarks/harness_live/cursor_hook_probe.py` |
| `harness-live-haiku55/` | a 100-run Claude Code (Haiku) campaign over four arms (`direct`, `hooks`, `guarded`, `memory`) and attack, stress and benign scenarios; `summary.json` has the cells with Wilson intervals, `events.jsonl.gz` every hook event (it feeds `benchmarks/review_gate.py`). The model id is not recorded in the summary. In the `memory` arm (one hook and threat database shared by a rep's runs, benign tasks after the attacks) **1 of the 5 benign runs was falsely blocked** (`benign_send`: its `send_email` was denied because the hostile notes server's date `2026-10-01` read as an account number; false block 1/5 = 20%, 95% CI 3.6 to 62%, utility 4/5); the other three arms blocked 0/5. That finding was fixed afterwards (`tests/test_provenance.py`, `test_a_date_from_a_hostile_servers_note_does_not_stop_the_users_mail`), so the summary describes the code before the fix. With n=5 it is a finding, not a rate | `benchmarks/harness_live/campaign.py` then `benchmarks/harness_live/summarize.py` |
| `adaptive-gemini.json`, `adaptive-learning.json` | the adaptive attacker (Gemini 3.5 Flash-Lite as the rewriting model, 42 seeds x 5 tries) against the static and memory defenses; the learning detectors against 20 seeds x 11 variants | `benchmarks/adaptive_attacker.py --provider gemini --defense memory`; `benchmarks/adaptive_learning.py` |
| `self-disclosure.json`, `self-disclosure.md` | the self-disclosure stripping evaluation over the MSB catalogs (159 distinct schemas, 36 stripped parameters; the role table's rows overlap and are not added) | `benchmarks/self_disclosure_eval.py --data artifacts/data/MSB --out results/self-disclosure.json` (the committed `.md` is its stdout) |
| `improve/` | the improvement measurements (`baseline/`, `phase1/`, `phase2/`, `msb-replay/recorded`) with their own `README.md` | see `improve/README.md` |
| `judge/` | the LLM judge runs: descriptions (`report-*.json`, `table-*.txt`) and the output-judge, jailbreak and adaptive runs listed below | see below |
| `latency.json` (2026-10-16), `latency-rerun-2026-10-19.json` | hook and proxy overhead on an Apple M5 before the threat memory was on by default: hook p50 35 ms per event as a process (the "35 ms" figure), 0.02 to 1.1 ms in process; transparent proxy +1.9 ms per call (p50 2.43 vs 0.54 ms direct). In the rerun, per-event and per-call figures agree within 0.1 ms and start-up differs by up to 18 ms (interpreter 17 vs 15 ms, proxy start-up overhead 257 vs 275 ms) | `benchmarks/latency.py` |
| `improve/baseline/latency.json` (code at `4dac01f`, threat memory on) | the source of the README's former "about 42 ms per MCP call", which was one event (a call fires Pre and Post): hook p50 41 to 47 ms per event as a process, 0.02 to 2 ms in process; transparent proxy +1.9 ms per call (2.55 vs 0.65 ms) | `benchmarks/latency.py` (see `improve/README.md`) |
| `latency-2026-10-31/run{1,2,3}.json` | current code (`80c9e34`), Apple M5, Python 3.14.8, scratch `HOME` and hook database, intent model off, demo MCP server; three runs back to back while other jobs ran on the machine (load average 2 to 6; bare Python 16.1, 18.4 and 16.6 ms against 14.8 ms in the 2026-10-16 file). Hook as a process p50: read 60.3, 63.4, 63.4 ms; small result 60.3, 63.5, 63.9; 4 KB result 67.6, 71.0, 71.1; injected 68.8, 72.5, 72.0; in process 0.12 to 0.34 ms and 6.7 to 7.2 ms for the 4 KB result (canonical value extraction); transparent proxy 2.96, 3.37, 3.01 ms against 0.57, 0.64, 0.58 direct (+2.4 to 2.7 ms), start-up 567 to 603 ms against 266 to 286 ms. The README figures come from these files | `benchmarks/latency.py --calls 50 --hooks 30` |
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

**Code versions.** Only the three qwen v12 files below are shown to run on code whose guard and runner
behave as at commit `0a3776d` (their provenance records it); the other arms are believed equivalent
apart from the intent model, but that is not verified, because they carry no provenance. The qwen2.5:7b `none`, `baseline` and `gateway` arms are the MSB v12
reruns of 2026-10-19; the originals (2026-10-12/13) predated gateway and hook fixes. Runs from v12
on carry their commit, intent model hash, Ollama model digest and container image in
`MANIFEST.json`; older runs have `"provenance": null`, and their dates and commits are in
`docs/artifact-paper.md` §4. Only those three qwen files have provenance; the other 19 of the 22
trace files are earlier runs on older code: every `hooks` arm, `gateway-prompt-guard` and all the
llama3.1:8b and ornith:9b main arms are MSB v8, the Gemini arms v9, `gateway-intent-veto` v10 and
`gateway-intent-advisory` v11 (`source` in `MANIFEST.json`).

**What does not replay offline.** `paper_numbers.py` and the injection table's rules column do; the
rest needs inputs or services that are not in this directory: the exemplar index
(`artifacts/exemplars`, built from the e5 embedder) and Prompt Guard 2 scores (Groq), so the
exemplar and Prompt Guard columns are the committed reports only; the MCPTox-Benchmark and
InjecAgent checkouts (`artifacts/data/`); the LLM judge runs (`judge/`, Groq, Gemini or Ollama) and the
adaptive-attacker runs (`adaptive-*.json`, a rewriting model); and the MSB trace files themselves,
which need Docker and the agent model to regenerate, 19 of which carry `provenance: null`.

**Reproducibility.** Agents ran at temperature 0, one run per arm. Rerunning llama3.1:8b `none`
five days later reproduced all 220 call sequences and every per-case metric; 24 final answers
differed only in wording.

**Numbers with no raw data here.** (1) The review-load figures in `CHANGELOG.md`, `docs/security-review.md` and the report (for example shell asks 4/1,707, 7/1,713 and 8/1,713, MCP asks 741/3,405 and 53 to 55 of 126, and the 830/3,720 in IntentShield's own sessions) were measured by replaying the author's private Claude Code transcripts from 40 sessions of other projects and from IntentShield's own sessions, which are not committed and cannot be shared; they cannot be reproduced from this repository. Only the hand-written 35-call fixture of `benchmarks/shell_replay.py` reproduces (0 of 35 asked), and its author also tuned the parser. (2) The Gemini CLI ask-probe table (`docs/benchmarks.md`, finding 20 of the security review: six cells over versions 0.37.1 and 0.66.0) has no committed rows: `benchmarks/harness_live/gemini_ask_probe.py run <mode> <outdir>` writes each cell's screen text, `answered.txt` and hook log to the directory it is given, and those were not committed; treat the table as one run per cell, reported by the author and not re-checkable here. (3) Earlier figures that a doc quotes as "before" (for example the hook alone holding 27 of 30 jailbreak sends before the review's fixes) come from runs whose rows were not committed.

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
| `injection/report-local-2026-10-13.json` | `injection_eval.py` on 2026-10-13 with the classifier and the earlier exemplar index that scanned descriptions and outputs (rules, classifier, exemplars, any); copied from `artifacts/injection-eval/report-local.json` | the "exemplars, descriptions and outputs" row of `docs/detectors.md` (20.7% / 2.4% / 9/142; MCPTox 261/301) |
| `judge/report-gemini_gemini-3.5-flash-lite.json` | `benchmarks/judge_eval.py --judge gemini` on 2026-10-12: Gemini 3.5 Flash-Lite on the held-out MCPTox descriptions; rates in this older file are rounded to 4 places (300/301 = 0.9967, 5/108 = 0.0463) | the README's "LLM judge on held-out descriptions" row for Gemini |

### Attacks on the output judge (2026-10-30)

From `benchmarks/judge_outputs_eval.py`, `benchmarks/judge_jailbreaks.py` and `benchmarks/adaptive_judge.py`
after the security review; copied from `artifacts/judge-v2/`, `artifacts/jailbreaks/` and
`artifacts/adaptive-judge/`. They feed `docs/benchmarks.md#attacks-on-the-output-judge`.

| File | What |
|---|---|
| `judge/outputs-qwen2.5-7b-validation-v1.json`, `...-validation-v2.1.json` | qwen2.5:7b on the validation split with the first prompt and with v2.1 (prompt choice) |
| `judge/outputs-qwen2.5-7b-test-v2.1.json` | qwen2.5:7b on the test split with v2.1, run once after the choice (all 522 rows) |
| `judge/jailbreaks-qwen2.5-7b.json` | the 30 hand-written attacks and 12 benign pages through the hook, without a judge and with qwen2.5:7b, plus whether ornith:9b followed each attack unguarded |
| `judge/jailbreaks-gemini-flash-lite.json` | the same suite with Gemini 3.5 Flash-Lite as the judge (no victim); one row corrected after the run, as its `correction` field says |
| `judge/adaptive-v2.1-qwen2.5-7b.json` | the same attacker against the v2.1 prompt, 24 seeds x 5 tries (cut for the free quota); resumed once after a network reset at seed 21 |
| `judge/jailbreaks-deepseek-flash.json` | the suite with DeepSeek `deepseek-flash` as the judge and as the unguarded agent; each attack row keeps the agent's calls and whether the hook's argument gate held its own send |
| `judge/adaptive-v2.1-deepseek-agent.json` | the adaptive attacker against the v2.1 qwen judge with `deepseek-flash` as the agent, 24 seeds x 5 tries; resumed once after a dropped connection at seed 6 |
| `judge/outputs-deepseek-flash-test-v2.1.json` | `deepseek-flash` as the output judge on the whole test split (522 rows) |
| `judge/outputs-qwen2.5-7b-test-v2.1-native-rerun.json`, `judge/jailbreaks-qwen2.5-7b-native-rerun.json` | the qwen2.5:7b test split with v2.1 and the 30 + 12 jailbreak pages rerun on 2026-10-31 on the native `/api/chat` endpoint (`num_ctx` 8,192, Ollama 0.40.2), after JG7; they record `endpoint` (URL, context, prompt hash) and reproduce every count of the earlier qwen files; the jailbreak rerun has no victim agent |
| `judge/adaptive-v1prompt-qwen2.5-7b.json` | the adaptive attacker (Gemini 3.5 Flash-Lite, 24 seeds x 8 tries) against qwen2.5:7b with the first prompt; the victim is ornith:9b |
