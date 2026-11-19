# Contributing

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md). To report a security problem, follow [SECURITY.md](SECURITY.md) and put no details in a public issue. If you cite IntentShield, [CITATION.cff](CITATION.cff) has the reference.

## Your first change

1. Clone the repository and run `uv sync --group dev` (see below).
2. Pick a task from the list below. The usual first one is a command the `--builtin-tools` rules ask about or deny that is harmless:

   ```sh
   uv run python -c "from intentshield.dangerous import assess_shell; print(assess_shell('git reset --hard HEAD~1', ''))"
   ```

   It prints the rule's verdict and reason (`None` means allow). Put your command in place of the example, which is a correct ask.
   If the verdict is wrong, add the command to the `ALLOW` list of `tests/test_dangerous_rules.py` (checked by
   `test_benign_near_misses_are_left_alone`) and change the rule in `src/intentshield/dangerous/` until
   `uv run pytest -q tests/test_dangerous_rules.py` passes.
3. Run the tests for the files you touched and `uv run ruff check src tests benchmarks`.
4. Open a pull request. A documentation-only change needs only `uv run pytest -q tests/test_docs_*.py` locally, which takes a few
   seconds; CI runs the rest. Of the boxes in the pull-request template, a documentation-only change needs only the one about
   checking a doc claim; the review-load gate (item 6 under [Tests and lint](#tests-and-lint)) is for a change to a detection rule
   or to what the hook asks about.

Starter tasks:

- Add a harmless command that is wrongly asked about to the `ALLOW` list, with the rule change that stops the ask.
- Fix a statement in the documentation that the code does not bear out (`uv run intentshield --help` and the tests are the check).
- Add an ordinary sentence that a tool-text rule wrongly flags to the benign lists of `tests/test_rules_detection.py` (for example `OVERRIDE_BENIGN`), with the rule change that stops the flag.
- Re-run a committed benchmark on other hardware and send the rows (see [What contributions are wanted](#what-contributions-are-wanted)).

## Development setup

Python 3.11 or later and [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/Suhas-123-cell/IntentShield.git && cd IntentShield
uv sync --group dev
```

The optional ML packages (torch, transformers, sentencepiece, protobuf) are needed only for the local DeBERTa classifiers and the exemplar embedder:

```sh
uv pip install --python .venv/bin/python -r requirements-ml.txt
```

There is no `ml` extra of the package, on purpose: `requirements-ml.txt` pins `transformers>=4.48,<5`, and the newest release that pin
allows (4.57.6 when this was checked) has published advisories whose fixes are only in 5.x. As an extra it would be in the locked
packages the `audit` workflow checks, and that workflow fails for an advisory that has a fix. The packages are therefore
installed from the file, in a clone, and are not locked.

A plain `uv sync` removes them again. CI runs without them (`uv sync --group dev --frozen`), so a new third-party import must be declared in `pyproject.toml` (then `uv lock`); the local `.venv` can hide a missing declaration.

## Where things are

- `src/intentshield/`: the package (the module map is in [docs/architecture-and-testing.md](docs/architecture-and-testing.md#2-components-and-responsibilities)).
- `tests/`: the test suite. It reads `results/` and `docs/`, so it runs from a clone, not from the PyPI source distribution.
- `benchmarks/`: the scripts that produce every cited number. `results/`: the committed rows and tables they read and write.
- `docs/`: the documentation, indexed in [docs/README.md](docs/README.md). `configs/`: example hook and proxy configurations.

## Sending a change

Fork the repository on GitHub, branch from `main`, make the change with its tests, run the gates under
[Tests and lint](#tests-and-lint), and open a pull request against `main`; the pull-request template lists what to include.
Contributions are licensed under the Apache License 2.0, the licence of the project ([LICENSE](LICENSE)): what you send is
licensed to the project and to everyone who uses it on the same terms (inbound = outbound), and you confirm you have the right to
send it. There is no separate contributor agreement.

Questions, and ideas you want to talk over before writing code, go in a [GitHub issue](https://github.com/Suhas-123-cell/IntentShield/issues).
There is no discussion board or chat.

## What contributions are wanted

- **False-positive reports.** A call, tool result or command the guard refused or asked about that was fine. Include the
  command that reproduces it (the hook event piped into `intentshield-hook <harness>`, or the `intentshield scan` run),
  the harness and version, and the decision and reason it printed. Use benign markers, not real data. A ready-to-paste event is in
  [Try it from a clone](docs/layers.md#try-it-from-a-clone). These are the most useful.
  - A shell command the `--builtin-tools` rules ask about or deny, as a hook event (it prints `permissionDecision`, here `ask`) and
    as the rule's own verdict:

    ```sh
    echo '{"hook_event_name":"PreToolUse","session_id":"fp","tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}' \
      | INTENTSHIELD_HOOK_DB=/tmp/fp.db uv run intentshield-hook claude --builtin-tools
    uv run python -c "from intentshield.dangerous import assess_shell; print(assess_shell('git reset --hard HEAD~1', ''))"
    ```

    With `INTENTSHIELD_HOOK_DB` set, the reply ends with a note that the variable moves the session database; that is expected. A
    harmless command that is wrongly asked about goes in the `ALLOW` list of `tests/test_dangerous_rules.py`
    (`test_benign_near_misses_are_left_alone`), with the rule change that stops the ask.
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
| tool descriptions, tool outputs, arguments (injected instructions, poisoning) | `src/intentshield/mcp_inspect/` (`scan_description`, `scan_output`) | `tests/test_rules_detection.py`, `tests/test_output_rule_evasions.py` |
| credential formats | `src/intentshield/credentials.py` | `tests/test_credential_masking.py` |
| a built-in tool call: a shell command, a file read or write (`--builtin-tools`) | `src/intentshield/dangerous/` (`rules.py`, `paths.py`), with `shell/` for parsing | `tests/test_dangerous_rules.py` |

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

   It prints `ALL instruction (recall) 432/851` and `ALL data (benign flagged) 16/741`, and takes a couple of
   seconds. Of the 16 benign texts flagged, 13 are texts that quote an attack (`data:hard_quoted_attack` and its
   translation): a known limit, since the rules flag legitimate quotations of attack phrases. The other three are the rest of the baseline.
   (`--injecagent /nonexistent` skips a dataset a clean clone does not have; `--out` keeps the report out of the repository.)
2. For a rule on a shell command or a file path, the baseline is the benign review load of the built-in-tools hook,
   replayed from a fixture inside the script: `uv run python benchmarks/shell_replay.py`. It prints
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
   There is no formatter: lines are at most 130 columns and the layout is kept by hand, so do not reformat a file you are not
   changing for another reason (`ruff format --check src` reports nearly every file).
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

Three more checks run outside the test job: a Docker job builds the image, runs the demo proxy check in it and runs the code tests there (`pytest -q -m "not study"`), a
`next-python` job runs the tests on Python 3.15, which is not supported yet, and is allowed to fail (a red mark on it is advisory and does not fail the workflow), and an
`audit` workflow checks the locked dependencies against the PyPI advisory database on each push and weekly.
CI runs the test job on Linux with Python 3.11 to 3.14 and on macOS with 3.12, and one job tests the lowest allowed versions of the direct dependencies on 3.11. The module map, the test inventory by
area and how to diagnose a failure are in [docs/architecture-and-testing.md](docs/architecture-and-testing.md).

### How pins are kept current

No bot bumps them; they change by hand, when a release or an advisory makes it worth doing.

- **GitHub Actions** are pinned by commit SHA with the tag in a comment, in `.github/workflows/ci.yml`, `publish.yml` and `audit.yml`: `actions/checkout`, `astral-sh/setup-uv`, `actions/upload-artifact`, `actions/download-artifact` and `pypa/gh-action-pypi-publish`. To move one, find the commit of the new tag on the action's releases page, replace the SHA in every workflow that names it, and update the comment.
- **uv** is `0.11.16`, written in six places: the `version:` of each `astral-sh/setup-uv` step (three in `ci.yml`, one in `publish.yml`, one in `audit.yml`) and the `COPY --from=ghcr.io/astral-sh/uv:0.11.16` line of the `Dockerfile`. Change them together. `pip-audit` has its own pin in `audit.yml`.
- **Python packages** are pinned by `uv.lock`. Refresh with `uv lock --upgrade` (everything) or `uv lock --upgrade-package NAME`, run the tests, and commit `uv.lock`. CI installs with `--frozen`, so a lock that does not match `pyproject.toml` fails there.
- **The weekly audit** (`audit.yml`) runs on every push to `main`, on pull requests and on Mondays at 05:17 UTC. It checks `uv.lock` against the PyPI advisory database and fails the run when an advisory has a fixed version; an advisory with no fix yet is printed and does not fail it. It reads only the Python packages: it says nothing about the Actions or the uv version, which stay as pinned until someone moves them.

## Changelog

A change a user can see (a flag, a message, a decision, a fix) gets one line in [CHANGELOG.md](CHANGELOG.md) under `## Unreleased`, in the group it belongs to: Added, Changed or Fixed (a release entry may also carry Upgrading, Internal, and Study and benchmarks sections). Say what changed for the user, not how the code changed. One or two lines per change; put the detail in the guide and link it. The maintainer moves the entries under a version heading and a date at release. A pull request that changes nothing a user can see needs no entry.

## Releasing

For the maintainer. Pushing a tag `vX.Y.Z` builds, smoke-tests and publishes the wheel (`.github/workflows/publish.yml`), so before it. The workflow's first step stops the release unless `pyproject.toml`, `CITATION.cff`, `uv.lock` and a `## X.Y.Z - date` heading in `CHANGELOG.md` name the same version and the tag is `vX.Y.Z`; it then runs `twine check` and installs the wheel in a clean environment (`intentshield --help`, `intentshield demo`, the README's demo one-liner).

1. Set the version in `pyproject.toml` and in `CITATION.cff` (`version` and `date-released`), then run `uv lock` and commit `uv.lock`: the lock records the package's own version, and a later non-frozen `uv sync` would otherwise rewrite it and leave the tree dirty.
2. In `CHANGELOG.md`, rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD` and start a new empty `## Unreleased` above it.
3. Check that no document still calls a released feature unreleased: delete the note under Quick start in `README.md` that says PyPI has an older version (if there is one), and make sure `grep -rn "not yet in a PyPI release" README.md docs/` and a search for "on main" print nothing that is still true.
4. Run the tests, `ruff` and `mypy` as above, and check the wheel's rendered description on TestPyPI: PyPI does not rewrite the README's relative links.

## Benchmark numbers

Every number the README, `docs/` or a paper cites comes from `benchmarks/paper_numbers.py` over the committed traces in `results/` (see `results/README.md`). Do not type a number by hand or recompute one in a notebook; change the script or the traces and quote its output. Rates and intervals are stored unrounded and formatted from k/n at display time.

## Commit messages

Short, past tense, no prefixes (`fixed the hook's exit code on an unknown review value`, not `feat: ...`), no trailer lines.

## Scope

Security work stays defensive: use benign markers, measure what the guard itself observes, and do not add bypass techniques aimed at specific vendors' products. See `SECURITY.md` for how to report an issue.
