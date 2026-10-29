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

## Tests and lint

```sh
uv run ruff check src tests benchmarks && uv run pytest -q
```

Both must pass before a pull request. `INTENTSHIELD_RUN_HTTP_E2E=1 uv run pytest -q tests/test_mcp_http_e2e.py` runs the opt-in real HTTP process test that CI also runs.

## Benchmark numbers

Every number the README, `docs/` or a paper cites comes from `benchmarks/paper_numbers.py` over the committed traces in `results/` (see `results/README.md`). Do not type a number by hand or recompute one in a notebook; change the script or the traces and quote its output. Rates and intervals are stored unrounded and formatted from k/n at display time.

## Commit messages

Short, past tense, no prefixes (`fixed the hook's exit code on an unknown review value`, not `feat: ...`), no trailer lines.

## Scope

Security work stays defensive: use benign markers, measure what the guard itself observes, and do not add bypass techniques aimed at specific vendors' products. See `SECURITY.md` for how to report an issue.
