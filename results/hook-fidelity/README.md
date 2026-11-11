# Hook verdict fidelity study: data

Raw rows, ledgers and derived tables of the study. Start with the short report, [`docs/hook-fidelity-report.md`](../../docs/hook-fidelity-report.md);
[`docs/hook-fidelity-study.md`](../../docs/hook-fidelity-study.md) is the full record.
The question: what do Claude Code, Codex CLI and Gemini CLI do with the verdict a `PreToolUse`-style hook returns (allow,
ask, deny, a crash, a timeout, an empty reply), and what does IntentShield's own hook decide on the same calls. Scope: macOS,
mostly headless against a scripted stub model, a pseudo-terminal lane for interactive sessions, a narrow real-model arm, a
Linux probe on dummy processes, and sampled builds of each harness (23 Claude Code, 17 Codex CLI and 28 Gemini CLI releases
the lanes could install, not every release). Cursor was not measured: its free plan ran out. The study's own verdict is a
measurement note and an artifact, not a paper (`docs/contribution.md`, section 13).

Each lane directory has its own README where one exists; this file is the map. The vendors' documentation pages are not
here: `vendor-archive/*/README.md` give their source URLs and sha256 (the page texts have no licence that allows a copy).

## What each directory holds

| path | what |
|---|---|
| `claude/`, `codex/`, `gemini/` | the stub-model matrix per harness: one row per launch in `runs.jsonl` (under `core/`, `fail/`, `sweep/`, `main/`, `r4-*`), scrubbed `streams/`, per-lane `table.md` or `summary.md`, `version-table.md` and `by-version.md` (outcome per release and reply), `launch-accounting.json` and `ledger.json` (every launch, written before it started). `codex/` also has the persisted-trust rows, `gemini/enable-default/` the hook opt-in cells before 0.26.0 |
| `gemini-core/` | the Gemini CLI hook runner's own aggregation, run without the CLI on 25 core releases: `table*.md`, `boundary.md`, `registry-integrity.json` |
| `cursor/` | what could be run on Cursor CLI before the plan limit: `runs.jsonl`, `table.md`. The study treats Cursor as unmeasured |
| `coverage/` | which MCP surfaces reach a hook per harness build, no model: `rows.jsonl`, `cells.json`, `summary.md` |
| `guards/` | byte captures of six third-party guards' hook entry points and their replay through the harnesses (`captures.jsonl`, `replay/`, `stub-rows.jsonl`, `table.md`); `README.md` lists the four guards that could not be captured and why |
| `mitigation/` | the held-out regression check of the verdict translation (`eval/`, `eval-r4/`, `ranges-*.json`, `lane-features*.json`); the table the product ships is derived from `lane-features.json` |
| `compare/` | the head-to-head of IntentShield's hook and captured third-party guards, the wrapped-guard (`wrap-hook`), allow and deny-all arms: `runs.jsonl`, `runs-r8.jsonl` (round-8 re-run), `table.md`, `table-r8.md`, `summary*.json`; `README.md` has the caveats |
| `interactive/` | the pty lane: `runs.jsonl`, `table.md`, per-run `runs/<run>/` (screen text, hook observer log, stub request log); the raw `transcript-head.bin` files are not committed |
| `detect/` | the decision comparison (467 fixtures, 10 guards): `fixtures.jsonl`, `decisions.jsonl`, `table.md`, `breakdown.md`, `delivery.json`; `r8fix/` re-scores the dangerous-command rules post hoc, `fresh/` scores them on 214 new calls, `validation/` and `mcp-benign/` hold the end-to-end validation cells and the MCP benign items. Each has a README |
| `linux/` | the `/proc` ancestry reader run in a Docker container on constructed process trees, no harness launched |
| `real-model/`, `real-model-supp/`, `real-model-critic/`, `real-model-deepseek/` | the narrow real-model arm: local qwen2.5:7b on two harnesses and one paid model on one; separate ledgers, never merge their rows by run id |
| `release-manifests/` | the package versions, publish dates and integrity hashes of the builds the study installed |
| `vendor-archive/` | source URLs and sha256 of the vendor documentation pages the sign-offs read, plus the `claude --help` text of each Claude Code release |
| `corpus.json`, `r4-gaps-ledger.json`, `r4-integration-ledger.json` | the inventory of 26 published guards (repository URL and commit of each clone) and the round-4 launch ledgers |

## What regenerates offline

Tables regenerate from the committed rows with no harness, no network and no model. Commands, from the repository root
(they write into the directory they are given, so copy it first if you only want to compare):

| table | command | needs |
|---|---|---|
| `compare/table*.md`, `compare/summary*.json` | `.venv/bin/python benchmarks/hook_fidelity/compare.py summarize results/hook-fidelity/compare` | the committed rows |
| `interactive/table.md` | `.venv/bin/python benchmarks/hook_fidelity/pty_lane.py table results/hook-fidelity/interactive` | the committed rows and screen text |
| `detect/fresh/table.md`, `summary.json` | `.venv/bin/python benchmarks/hook_fidelity/fresh_report.py` | `fixtures.jsonl`, `decisions.jsonl`, `detect/r8fix/delivery.json` |
| `detect/table.md`, `summary.json`, `breakdown.md`, `breakdown.json`, `delivery.json` | `detect_compare.py report --decisions results/hook-fidelity/detect/decisions.jsonl --out <copy of detect/>`, then the same with `breakdown`; `detect_compare.py matrix` for `delivery.json` alone | `detect/decisions.jsonl` and `fixtures.jsonl`. **No guard clone is needed**: both commands run in a clean clone with `HF_SCRATCH` pointing at an empty directory |
| every figure in `docs/hook-fidelity-report.md` | `.venv/bin/python benchmarks/hook_fidelity/report_numbers.py` (the report embeds its output; a test compares them) | the committed rows and the `detect` summaries |
| `detect/r8fix/` tables | `r8fix_report.py` | the committed decisions |
| `claude/`, `codex/` tables | `run.py summarize <runs.jsonl>`, `codex_report.py`, `summarize.py` | the committed rows |
| `coverage/summary.md` | `coverage_summarize.py results/hook-fidelity/coverage` | `coverage/rows.jsonl` |
| `mitigation/` tables and ranges | `mitigation_summary.py <runs.jsonl>`, `derive_table.py` | the committed rows |
| `guards/table.md` | `guard_replay.py table --index results/hook-fidelity/guards/replay ...` | the committed replay index |

The `compare`, `interactive` and `detect/fresh` commands were rerun on copies of the committed data for this page and
reproduced the committed tables byte for byte (`compare/table.md`, `table-r8.md`, `summary.json`, `summary-r8.json`;
`interactive/table.md`; `detect/fresh/table.md`, `summary.json`). `detect_compare.py report` and `breakdown` crashed in a clean clone
until `detect_compare.specs()` stopped reading the claimed-scope table from a guard clone's `hooks/hooks.json`; they now reproduce
`detect/table.md`, `summary.json`, `delivery.json`, `breakdown.md` and `breakdown.json` byte for byte with no clone present, and
`tests/test_hook_fidelity_reproduce.py` checks that on every run. The rest are as documented in the lane READMEs and
`docs/hook-fidelity-study.md` section 14. `corpus_counts.py --check` checks the corpus counts. The tests
`tests/test_hook_fidelity_study_numbers.py`, `tests/test_hook_fidelity_fresh_report.py`, `tests/test_hook_fidelity_report.py` and the other
`tests/test_hook_fidelity_*.py` recompute the figures the study cites from these rows; none of them launches a harness.

**Determinism of the coding.** `summarize.summarize`, which groups the rows into cells and assigns the liveness status, the prediction
hit or miss, the deviation class and the kill criterion, returns the same result over the 1,342 committed stub rows when run twice and
when the rows are shuffled with three fixed seeds (only the order of the flip lines depends on row order);
`test_the_coding_is_deterministic_over_the_committed_rows` checks it. That tests the coder, not the harnesses: re-scoring a launch from
its raw evidence needs the run directories, which are not committed, and the stub's own run-to-run repeatability (six cells repeated
twenty times, under load) was not measured.

**Interpreter.** Scripts the runners generate (hook shims, the wrapper, the pty relay) start with `<repo>/.venv/bin/python` when that
exists, which is where `uv sync` puts the environment, and otherwise with the interpreter running the benchmark code
(`mitigation_eval.pick_python`, used by `compare.py` and `pty_lane.py`). A clone whose environment lives elsewhere
(`UV_PROJECT_ENVIRONMENT`) works without a symlink; run the benchmark and the tests with that environment's Python.

## What a rerun of the guard decisions or launches needs

Not committed, so not regenerated here:

- **The guard corpus clones.** `detect_compare.py decide --scratch <dir>` and `guard_replay.py` read the other guards' hook
  entry points from clones of their repositories under `$HF_SCRATCH/corpus/<guard>/repo/` (`HF_SCRATCH` defaults to
  `<tmp>/intentshield-hook-fidelity`). The repository and commit of each guard are in `corpus.json`; the inventory is in
  `docs/hook-fidelity-corpus.md`. `benchmarks/hook_fidelity/fetch_corpus.py` clones the 26 guards at those pinned commits:
  `--dry-run` prints the plan with no network and no writes, a real run needs the network, `--only <guard>` limits it, and each
  clone is checked against its pinned commit. It runs no code from a clone (hooks disabled, no submodules). It does not build
  anything: `block-no-verify` also needs its build under `$HF_SCRATCH/guard-replay/block-no-verify/build`, and a pinned commit
  that an owner has removed cannot be fetched. Four guards (two Rust, two with uninstalled dependencies) were never run.
- **The harness release installs.** Launches need the exact builds under `$HF_SCRATCH/releases/` (for example
  `releases/claude-code/2.1.316/` and `releases/codex/0.166.0/`), installed with `npm install --ignore-scripts` from the
  public registry (`release-manifests/README.md`); the runner refuses to start a launch without `HOOK_FIDELITY_GO=<n>`.
  The runs also need macOS `sandbox-exec` for containment; `linux_probe.py docker` needs Docker; `model_lane.py` needs a
  local Ollama server; `deepseek_arm.py` needs a paid endpoint and the owner's approval.
- **Without them,** `tests/test_hook_fidelity_detect.py` skips 3 tests ("needs the guard corpus clones under HF_SCRATCH"; the
  tests that recompute `summary.json` and `table.md` from the decisions run without clones), and
  `guard_replay.py capture` and `stub-run`, `detect_compare.py decide`, every `run` subcommand and the prevalence scripts
  cannot run. The prevalence counts (`docs/hook-fidelity-prevalence.md`) came from a code-search index and are not
  reproducible from this repository.

## Rules since the study

The committed decisions, tables and summaries here are IntentShield's rules as they stood when the study ran. They were not
regenerated and must not be edited. A later change lets a deny from `src/intentshield/dangerous.py` win over a session ask.
Re-running the committed fixtures (`detect/fixtures.jsonl`, `detect/fresh/fixtures.jsonl`) through the current code, with
`detect_compare.decide_intentshield` and the `intentshield` variant, differs from the committed `intentshield-r8fix` rows in 45
decisions, all ask to deny: 27 rows (9 items) of the 467-fixture set and 18 rows (6 items) of the fresh set. All 45 are harmful
credential-exfiltration items; no benign row changed and none changed to allow. On the 214 primary fresh calls the 41 asked and 35
denied of `table.md` become 35 asked and 41 denied, and the 28 of 104 harmful calls let through and the 5 benign asks do not
change. The denies-alone comparison with `safety-net` (24/85 against 41/85) was not recomputed.

## Provenance caveat

The study cites commit hashes and branch names (for example `25b62ad`, "fixtures committed before any guard ran") from its
development branch, which was squash-merged into `main`. They do not appear in this repository's history, so the order in
which fixtures and guards were run cannot be checked from the public history alone; it rests on the ledgers and the
`provenance.md` files in these directories. The same holds for the predictions and the kill criterion: the author committed them
before the runs (a same-day commit, not blind, no external timestamp, no hash in the rows), the author archives those commits, and
an outside reader cannot verify them. Read "registered in advance" as the author's statement.
