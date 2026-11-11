# Contributing

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md). To report a security problem, follow [SECURITY.md](SECURITY.md) and do not open a public issue. If you cite IntentShield, [CITATION.cff](CITATION.cff) has the reference.

## Development setup

Python 3.12+ and [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/Suhas-123-cell/IntentShield.git && cd IntentShield
uv sync --extra dev
```

The optional ML extras (torch, transformers, sentencepiece, protobuf) are needed only for the local DeBERTa classifiers and the exemplar embedder:

```sh
uv pip install --python .venv/bin/python -r requirements-ml.txt
```

A plain `uv sync` removes them again. CI runs without them (`uv sync --extra dev --frozen`), so a new third-party import must be declared in `pyproject.toml` (then `uv lock`); the local `.venv` can hide a missing declaration.

## What contributions are wanted

- **False-positive reports.** A call, tool result or command the guard refused or asked about that was fine. Include the
  command that reproduces it (the hook event piped into `intentshield-hook <harness>`, or the `intentshield scan` run),
  the harness and version, and the decision and reason it printed. Use benign markers, not real data. These are the most useful.
- **New detection rules, with a measured benign check.** A rule is accepted with the texts it should flag, a count of what
  it flags in the repository's benign corpora, and no new false positive on them; a rule with no benign check is not
  accepted. Say plainly what it does not catch. [Add a detection rule](#add-a-detection-rule) gives the commands, and they
  run from a clean clone with no model and no network.
- **Harness adapters.** Support for another MCP client or agent harness's hook or configuration format, measured the way the
  existing ones are: run against the real harness where you can, and write down the build and what it did.
- **Benchmark replications.** Re-running a committed benchmark on other hardware, other models or newer harness builds,
  including results that disagree with the committed ones. Send the rows and the command; do not edit a cited number by hand.
- **Documentation fixes**, especially a statement about behaviour that the code does not bear out.

## Add a detection rule

Where a rule goes:

| What it reads | File | Tests to extend |
|---|---|---|
| tool descriptions, tool outputs, arguments (injected instructions, poisoning) | `src/intentshield/mcp_inspect.py` (`scan_description`, `scan_output`) | `tests/test_rules_detection.py`, `tests/test_output_rule_evasions.py` |
| credential formats | `src/intentshield/credentials.py` | `tests/test_credential_masking.py` |
| a built-in tool call: a shell command, a file read or write (`--builtin-tools`) | `src/intentshield/dangerous.py`, with `shell.py` for parsing | `tests/test_dangerous_rules.py` |

A rule that should ship as data, without a release, is a threat pack instead (`src/intentshield/rule_packs.py`, [guide](docs/guide.md#adaptive-threat-memory-and-threat-packs)).

The steps, none of which needs a local LLM or a download:

1. Measure the baseline before you change anything. For a rule on tool text (the first row of the table), score the rules on the
   committed corpus under `results/injection/`, 1,592 attack and benign texts in the test and external splits:

   ```sh
   INTENTSHIELD_INTENT_MODEL_DIR=/nonexistent uv run python benchmarks/injection_eval.py \
     --dataset results/injection/dataset.jsonl --hard results/injection/hard_negatives.jsonl \
     --agentdojo results/injection/agentdojo-strings.jsonl --injecagent /nonexistent \
     --out /tmp/injection-eval.json > /tmp/before.txt
   ```

   At 0.4.3 it prints `ALL instruction (recall) 432/851` and `ALL data (benign flagged) 16/741`, and takes a couple of
   seconds. Of the 16 benign texts flagged, 13 are texts that quote an attack (`data:hard_quoted_attack` and its
   translation): a known limit, since the rules flag legitimate quotations of attack phrases. The other three are the rest of the baseline.
   (`--injecagent /nonexistent` skips a dataset a clean clone does not have; `--out` keeps the report out of the repository.)
2. For a rule on a shell command or a file path, the baseline is the benign review load of the built-in-tools hook,
   replayed from a fixture inside the script: `uv run python benchmarks/shell_replay.py`. At 0.4.3 it prints
   `shell: 1/25 asked or denied` and `write: 1/3`.
3. Write the rule, and in the tests above add the texts or commands it must flag and at least as many near-misses it must leave alone.
4. Run the same command again into `/tmp/after.txt` and `diff /tmp/before.txt /tmp/after.txt`. A rule is accepted when the
   attack recall rises or holds, no benign family line gets a new flag, and `ALL data (benign flagged)` does not rise.
   Paste the two lines and the diff into the pull request.
5. Run the gates under [Tests and lint](#tests-and-lint), including the review-load gate.

`benchmarks/real_incidents.py` (documented incidents, `uv run python benchmarks/real_incidents.py`) and
`benchmarks/adaptive_learning.py` also run offline if you want to check a rule against them. The MCPTox checkout and the
other datasets under `artifacts/` are optional: they are not in the repository, and the benchmark runners that need them are
listed in [docs/architecture-and-testing.md](docs/architecture-and-testing.md#15-offline-evaluation-and-benchmarks).

## Tests and lint

CI runs the gates below, and a pull request has to pass all of them. Run them from a clone (the PyPI source distribution
has no tests). The tests read provider keys, the proxy configuration and the intent model from the environment, so run
them with those unset, as CI has them:

```sh
uv run ruff check src tests benchmarks
uv run mypy
INTENTSHIELD_PROXY_CONFIG= INTENTSHIELD_CONTROL_TOKEN= GEMINI_API_KEY= GROQ_API_KEY= INTENTSHIELD_INTENT_MODEL_DIR=/tmp/none uv run pytest -q
```

1. **ruff** and 2. **mypy**, as above. The mypy configuration is in `pyproject.toml`: it is near-strict, and the strict flags that
   some older modules still fail are switched off per module in its `[[tool.mypy.overrides]]` lists. A new module has to pass
   the full set, and a module leaves its list when it does.
3. **The tests**, with the command above. It takes a few minutes. To run one file while you work, add its path:
   `uv run pytest -q tests/test_dangerous_rules.py`. One CI job also measures coverage (`uv run pytest -q --cov`, with `--cov` last because
   it takes an optional argument that would be read as the source path); the floor is `fail_under` in `pyproject.toml`. A third-party
   import in `src/intentshield` has to be declared in `pyproject.toml`: `tests/test_import_declarations.py` fails when it is not.
4. **No bare wall-clock bounds in tests.** A test that asserts on wall-clock time uses `limit(seconds)` from
   `tests/timelimits.py` (`limit()`, or `within()` which wraps it), which allows more time on CI, never a bare number such as
   `< 1.5`: shared runners are slow and a hard-coded bound flakes. To compare one run with another use `fastest()`, the best
   of several runs, and a named ratio, not a single sample times a literal. CI fails the build on a match of this grep (the pattern is in `.github/workflows/ci.yml`):

   ```sh
   ! grep -rnE '(perf_counter|monotonic|time\.time)\(\) *- *[A-Za-z_0-9]+ *< *[0-9]|(took|elapsed) *< *[0-9]|< *[0-9.]+ *\* *[A-Za-z_]+\(' tests
   ```
5. **The real HTTP process test**, which is skipped unless asked for:
   `INTENTSHIELD_RUN_HTTP_E2E=1 uv run pytest -q tests/test_mcp_http_e2e.py`.
6. **The review-load gate:** `uv run python benchmarks/review_gate.py`. It takes about 4.5 minutes on a laptop (259 s when timed here). It fails if
   the benign reviews per task rise more than 0.05 above `results/improve/baseline` on any of the 25 pairs. Run it after
   a change to a detection rule or to what the hook asks about; a rule that passes its own tests can still fail it.

Two more checks run outside the test job: a Docker job builds the image and runs the demo proxy check in it, and an
`audit` workflow checks the locked dependencies against the PyPI advisory database on each push and weekly.
CI runs the test job on Linux with Python 3.12 to 3.14 and on macOS with 3.12. The module map, the test inventory by
area and how to diagnose a failure are in [docs/architecture-and-testing.md](docs/architecture-and-testing.md).

## Changelog

A change a user can see (a flag, a message, a decision, a fix) gets one line in [CHANGELOG.md](CHANGELOG.md) under `## Unreleased`, in the group it belongs to: Added, Changed or Fixed. Say what changed for the user, not how the code changed. The maintainer moves the entries under a version heading and a date at release. A pull request that changes nothing a user can see needs no entry.

## Releasing

For the maintainer. Pushing a tag `vX.Y.Z` builds, smoke-tests and publishes the wheel (`.github/workflows/publish.yml`), so before it:

1. Set the version in `pyproject.toml` and in `CITATION.cff` (`version` and `date-released`).
2. In `CHANGELOG.md`, rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD` and start a new empty `## Unreleased` above it.
3. Check that no document still calls a released feature unreleased: `grep -rn "not yet in a PyPI release" README.md docs/` and a search for "on main" print nothing that is still true.
4. Run the tests and lint as above, and check the wheel's rendered description on TestPyPI: PyPI does not rewrite the README's relative links.

## Benchmark numbers

Every number the README, `docs/` or a paper cites comes from `benchmarks/paper_numbers.py` over the committed traces in `results/` (see `results/README.md`). Do not type a number by hand or recompute one in a notebook; change the script or the traces and quote its output. Rates and intervals are stored unrounded and formatted from k/n at display time.

## Commit messages

Short, past tense, no prefixes (`fixed the hook's exit code on an unknown review value`, not `feat: ...`), no trailer lines.

## Scope

Security work stays defensive: use benign markers, measure what the guard itself observes, and do not add bypass techniques aimed at specific vendors' products. See `SECURITY.md` for how to report an issue.
