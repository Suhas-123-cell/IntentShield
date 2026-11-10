# Contributing

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
  it flags in the repository's benign corpora (for example `benchmarks/hard_negatives.py`, the MCPTox clean descriptions),
  and no new false positive on them; a rule with no benign check is not accepted. Say plainly what it does not catch.
- **Harness adapters.** Support for another MCP client or agent harness's hook or configuration format, measured the way the
  existing ones are: run against the real harness where you can, and write down the build and what it did.
- **Benchmark replications.** Re-running a committed benchmark on other hardware, other models or newer harness builds,
  including results that disagree with the committed ones. Send the rows and the command; do not edit a cited number by hand.
- **Documentation fixes**, especially a statement about behaviour that the code does not bear out.

## Tests and lint

```sh
uv run ruff check src tests benchmarks && uv run pytest -q
```

Both must pass before a pull request. The tests read provider keys, the proxy configuration and the intent model from
the environment, so run them with those unset (CI has none of them):

```sh
INTENTSHIELD_PROXY_CONFIG= INTENTSHIELD_CONTROL_TOKEN= GEMINI_API_KEY= GROQ_API_KEY= INTENTSHIELD_INTENT_MODEL_DIR=/tmp/none uv run pytest -q
```

A test that asserts on wall-clock time uses `limit(seconds)` from `tests/timelimits.py`, which allows more time on CI,
never a bare number such as `< 1.5`: shared runners are slow and a hard-coded bound flakes. The module map, the test
inventory and how to diagnose a failure are in [docs/architecture-and-testing.md](docs/architecture-and-testing.md). `INTENTSHIELD_RUN_HTTP_E2E=1 uv run pytest -q tests/test_mcp_http_e2e.py` runs the opt-in real HTTP process test that CI also runs.

## Benchmark numbers

Every number the README, `docs/` or a paper cites comes from `benchmarks/paper_numbers.py` over the committed traces in `results/` (see `results/README.md`). Do not type a number by hand or recompute one in a notebook; change the script or the traces and quote its output. Rates and intervals are stored unrounded and formatted from k/n at display time.

## Commit messages

Short, past tense, no prefixes (`fixed the hook's exit code on an unknown review value`, not `feat: ...`), no trailer lines.

## Scope

Security work stays defensive: use benign markers, measure what the guard itself observes, and do not add bypass techniques aimed at specific vendors' products. See `SECURITY.md` for how to report an issue.
