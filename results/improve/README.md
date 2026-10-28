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

## Phase 2: review load

Phase 2 = the code at `phase2/COMMIT` (parent `2d24327`). Same scripts, same recordings, intent model off
(`INTENTSHIELD_INTENT_MODEL_DIR=/nonexistent`). Changes:

- `distinctive_values`/`authority_values`: dates (YYYY-MM-DD, DD/MM/YYYY, YYYYMMDD), numbers under nine digits and plain
  words ("read/write/execute") are not values; dates are masked before numbers are read, so "2026-10-01 10:00" is not
  the number 2026100110. Paths start where a token starts (relative paths are kept whole). URLs under any scheme
  (`s3://`, `ftp://`) are values; before, only their path part was, by accident.
- Threat memory: a source is hostile with 3 distinct runs within 7 days (was the 30-day TTL); approving a call to the
  server (proxy `decide_approval`, or a hook "ask" whose call then runs, matched by `tool_use_id`) or allowlisting it
  clears it, its tools included. Still weak evidence on outputs only.
- CI: `benchmarks/review_gate.py` reruns both offline replays and fails if any pair's benign reviews per task rise more
  than 0.05 over `baseline/`.

| metric | baseline | phase 1 | phase 2 |
|---|---|---|---|
| MSB replay, benign reviews / case (22 pairs pooled, n=4344) | 2573 (0.592) | 2575 (0.593) | 2571 (0.592) |
| MSB replay, only pair that changed vs phase 1 | | ornith gateway/gateway 1.589 | 1.571 (348 → 344 reviews) |
| live Claude Code replay, memory arm, benign calls stopped | 1/8 (0.20/run) | 1/8 (0.20/run) | 0/8 (0.00/run) |
| live replay, hooks and guarded arms, benign stopped | 0/8 | 0/8 | 0/8 |
| MSB replay, harmful calls reaching review / blocked / of | 105 / 250 / 814 | 105 / 250 / 814 | 105 / 250 / 814 |
| MSB replay, cases where harm ran | 9 | 9 | 9 |
| held-out injection recall, rules (test+external) | 1477/2959 49.9% | 1477/2959 49.9% | 1477/2959 49.9% |
| provenance coverage of injected outputs | | 2043/2589 78.9% | 1950/2589 75.3% |
| rules+provenance | | 2603/2959 88.0% | 2559/2959 86.5% |
| benign outputs naming a value (provenance cost) | | 117/590 19.8% | 114/590 19.3% |
| InjecAgent missed rows whose attacker instruction names a traceable value (dh / ds base) | | 119/493, 544/544 | 119/493, 544/544 |
| pytest | 423 passed, 1 skipped | 428 passed, 1 skipped | 436 passed, 1 skipped |

The provenance drop is all timestamps (`phase2/provenance_diff.py`): 93 injected outputs (92 InjecAgent dh, 1 AgentDojo)
and 3 benign ones were covered only by a date and hour that the old pattern read as one 10-digit account number
("2022-02-23 18:…" → 2022022318). No call that obeys those injections reuses that value; the attacker values InjecAgent
names stay traceable as before (last row but one). The 1-point recall bar does not apply to this drop: the 93 rows were false coverage
from the timestamp bug, not detections lost (accepted at review). The live false stop the change targets (`benign_send`, memory arm)
was the same misreading of the note's date, 2026-10-01 → 20261001. The memory arm's agreement with live falls to 96.7%
because that one call, denied live, is now allowed. Adaptive learning and real incidents are unchanged (`phase2/`; the
benign paragraph count is 1790, not 1789, because the threat memory docstring gained one).
