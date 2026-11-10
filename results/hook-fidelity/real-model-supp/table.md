# Arm M, local model `qwen2.5:7b` (26 launches)

Outcome counts are over launches; INVALID = the model issued no call (or the run failed to score). `agree` is the fraction of VALID model runs whose outcome equals the modal outcome of the stub rows on the same build, mode and reply (Wilson 95% interval, a rate over independent runs of one model).

| arm | build | cell | launches | RAN | BLOCKED | HUNG | INVALID | tool call | stub rows (same cell) | agree with stub modal | runs with >1 hook call |
|---|---|---|---|---|---|---|---|---|---|---|---|
| generic | claude 2.1.316 M1h | ask | 2 | 0 | 1 | 0 | 1 | 1/2 | BLOCKED 5 | 1/1 [0.21, 1.00] vs BLOCKED | 0/1 |
| generic | claude 2.1.316 M1h | control | 1 | 1 | 0 | 0 | 0 | 1/1 | RAN 5 | 1/1 [0.21, 1.00] vs RAN | 0/1 |
| generic | claude 2.1.316 M1h | deny | 3 | 0 | 3 | 0 | 0 | 3/3 | BLOCKED 5 | 3/3 [0.44, 1.00] vs BLOCKED | 0/3 |
| generic | claude 2.1.316 M1h | malformed | 3 | 2 | 0 | 0 | 1 | 2/3 | RAN 3 | 2/2 [0.34, 1.00] vs RAN | 0/2 |
| generic | claude 2.1.316 M1h | timeout | 4 | 3 | 0 | 0 | 1 | 3/4 | RAN 3 | 3/3 [0.44, 1.00] vs RAN | 0/3 |
| generic | codex 0.166.0 M1 | ask | 4 | 4 | 0 | 0 | 0 | 4/4 | RAN 5 | 4/4 [0.51, 1.00] vs RAN | 0/4 |
| generic | codex 0.166.0 M1 | control | 1 | 1 | 0 | 0 | 0 | 1/1 | RAN 5 | 1/1 [0.21, 1.00] vs RAN | 0/1 |
| generic | codex 0.166.0 M1 | deny | 3 | 0 | 3 | 0 | 0 | 3/3 | BLOCKED 5 | 3/3 [0.44, 1.00] vs BLOCKED | 0/3 |
| generic | codex 0.166.0 M1 | malformed | 3 | 3 | 0 | 0 | 0 | 3/3 | RAN 2 | 3/3 [0.44, 1.00] vs RAN | 0/3 |
| generic | codex 0.166.0 M1 | timeout | 2 | 2 | 0 | 0 | 0 | 2/2 | RAN 2 | 2/2 [0.34, 1.00] vs RAN | 0/2 |

Tool-call rate per harness (launches where the model issued the call):
* claude: 10/13 [0.50, 0.92]
* codex: 13/13 [0.77, 1.00]
