## What changed and why

<!-- A few sentences. Link the issue if there is one. -->

## Checklist

- [ ] `uv run ruff check src tests benchmarks` and `uv run mypy` pass.
- [ ] The tests pass with the command in CONTRIBUTING.md, "Tests and lint" (`INTENTSHIELD_PROXY_CONFIG= INTENTSHIELD_CONTROL_TOKEN= GEMINI_API_KEY= GROQ_API_KEY= INTENTSHIELD_INTENT_MODEL_DIR=/tmp/none uv run pytest -q`), and a new behaviour has a test.
- [ ] A wall-clock assert in a test uses `limit()` from `tests/timelimits.py`, not a bare number.
- [ ] `CHANGELOG.md` has a line under `## Unreleased`, in Added, Changed or Fixed, for any change a user can see (see CONTRIBUTING.md, "Changelog").
- [ ] If a file under `results/` changed, every number that quotes it was regenerated from the output of `benchmarks/paper_numbers.py` (or the script that produced the file), not typed by hand.
- [ ] No new third-party import without its declaration in `pyproject.toml` (and `uv lock`); CI runs without the ML extras, so the local environment can hide a missing one.
- [ ] No secret, real address or working attack payload aimed at a third-party product in the diff; benign markers only.
- [ ] A doc claim about behaviour was checked against the code or by running the command.
- [ ] A new module under `src/intentshield/` or a new file under `tests/` is listed in `docs/architecture-and-testing.md`.
- [ ] A new detection rule comes with the before and after output of the benign check in CONTRIBUTING.md, "Add a detection rule".
- [ ] A change to a detection rule or to what the hook asks about passes `uv run python benchmarks/review_gate.py` (about 4.5 minutes).
