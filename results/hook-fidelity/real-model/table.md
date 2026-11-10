# Arm M, local model `qwen2.5:7b` (34 launches)

Outcome counts are over launches; INVALID = the model issued no call (or the run failed to score). `agree` is the fraction of VALID model runs whose outcome equals the modal outcome of the stub rows on the same build, mode and reply (Wilson 95% interval, a rate over independent runs of one model).

| arm | build | cell | launches | RAN | BLOCKED | HUNG | INVALID | tool call | stub rows (same cell) | agree with stub modal | runs with >1 hook call |
|---|---|---|---|---|---|---|---|---|---|---|---|
| generic | claude 2.1.316 M1h | ask | 4 | 0 | 2 | 0 | 2 | 2/4 | BLOCKED 5 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |
| generic | claude 2.1.316 M1h | control | 1 | 1 | 0 | 0 | 0 | 1/1 | RAN 5 | 1/1 [0.21, 1.00] vs RAN | 0/1 |
| generic | claude 2.1.316 M1h | deny | 2 | 0 | 2 | 0 | 0 | 2/2 | BLOCKED 5 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |
| generic | claude 2.1.316 M1h | malformed | 4 | 2 | 0 | 0 | 2 | 2/4 | RAN 3 | 2/2 [0.34, 1.00] vs RAN | 0/2 |
| generic | claude 2.1.316 M1h | timeout | 2 | 1 | 0 | 0 | 1 | 1/2 | RAN 3 | 1/1 [0.21, 1.00] vs RAN | 0/1 |
| generic | codex 0.166.0 M1 | ask | 3 | 3 | 0 | 0 | 0 | 3/3 | RAN 5 | 3/3 [0.44, 1.00] vs RAN | 0/3 |
| generic | codex 0.166.0 M1 | control | 1 | 1 | 0 | 0 | 0 | 1/1 | RAN 5 | 1/1 [0.21, 1.00] vs RAN | 0/1 |
| generic | codex 0.166.0 M1 | deny | 3 | 0 | 3 | 0 | 0 | 3/3 | BLOCKED 5 | 3/3 [0.44, 1.00] vs BLOCKED | 0/3 |
| generic | codex 0.166.0 M1 | malformed | 3 | 3 | 0 | 0 | 0 | 3/3 | RAN 2 | 3/3 [0.44, 1.00] vs RAN | 0/3 |
| generic | codex 0.166.0 M1 | timeout | 3 | 3 | 0 | 0 | 0 | 3/3 | RAN 2 | 3/3 [0.44, 1.00] vs RAN | 1/3 |
| is | claude 2.1.316 M1h | ask | 2 | 0 | 2 | 0 | 0 | 2/2 | BLOCKED 2 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |
| is | claude 2.1.316 M1h | timeout | 2 | 0 | 2 | 0 | 0 | 2/2 | BLOCKED 2 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |
| is | codex 0.166.0 M1 | ask | 2 | 0 | 2 | 0 | 0 | 2/2 | BLOCKED 2 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |
| is | codex 0.166.0 M1 | timeout | 2 | 0 | 2 | 0 | 0 | 2/2 | BLOCKED 2 | 2/2 [0.34, 1.00] vs BLOCKED | 0/2 |

Tool-call rate per harness (launches where the model issued the call):
* claude: 12/17 [0.47, 0.87]
* codex: 17/17 [0.82, 1.00]
