# Improvement measurements

Baseline = the code at `4dac01f`. Phase 1 = the code at `8cc227a`.

The baseline outputs are split across two commits:
- `52a2636`: `baseline/` pytest, injection-eval, real-incidents, latency, adaptive-learning,
  paper-numbers and harness-live-replay.
- `8cc227a`: `baseline/msb-replay.{json,txt}`, the MSB recordings in `msb-replay/recorded/`, and all of `phase1/`.

Every `msb-replay` score here, baseline and phase 1, comes from `benchmarks/msb_replay.py` at `8cc227a`
(scores only the calls before the first decision that differs from the stored trace; harm judged on the
arguments sent). Baseline scores ran that script with `PYTHONPATH` set to a `4dac01f` worktree's `src`.
Rerunning both reproduces the committed files byte for byte. No committed score used the `52a2636` version.
