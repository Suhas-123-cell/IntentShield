Claude Code, M1h (-p --allowedTools Bash, default permission prompts), shell, stub model. k/n = runs where the touch marker was created (RAN). 2.1.316 is the core/fail data (R1 n=5, R3/R4 n=5, R9/R10a n=3); every other release n=2. 2.1.0 is CONFIG-INVALID (a stub artefact: the one scripted call was consumed by a Warmup request, so the control was blocked) and is not a finding.

| release | R1 neutral | R3 ask | R4 deny | R9 timeout (3 s) | R10a not executable (126) |
|---|---|---|---|---|---|
| 2.0.41 | 2/2 RAN | 2/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.0 | 0/2 RAN | 0/2 RAN | 0/2 RAN | 0/2 RAN | 0/2 RAN |
| 2.1.47 | 2/2 RAN | 2/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.69 | 2/2 RAN | 2/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.78 (r4) | 2/2 RAN | 2/2 RAN | 0/2 RAN | not run | not run |
| 2.1.83 (r4) | 2/2 RAN | 2/2 RAN | 0/2 RAN | not run | not run |
| 2.1.84 (r4) | 2/2 RAN | 2/2 RAN | 0/2 RAN | not run | not run |
| 2.1.85 (r4) | 2/2 RAN | 0/2 RAN | 0/2 RAN | not run | not run |
| 2.1.86 (r4) | 2/2 RAN | 0/2 RAN | 0/2 RAN | not run | not run |
| 2.1.89 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.118 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.139 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.163 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.214 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.246 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.268 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.280 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.281 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.290 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.292 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.295 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.296 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.299 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.300 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.304 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.309 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.314 | 2/2 RAN | 0/2 RAN | 0/2 RAN | 2/2 RAN | 2/2 RAN |
| 2.1.316 | 5/5 RAN | 0/5 RAN | 0/5 RAN | 3/3 RAN | 3/3 RAN |

Rows marked (r4) are round-4 bisect rows (`claude/r4-gaps/bisect/`, n=2 each, same cell as the others; R9 and R10a not run). The ask flip lies between 2.1.84 (RAN 2/2) and 2.1.85 (BLOCKED 2/2); 2.1.70 to 2.1.77, 2.1.79 to 2.1.81 and 2.1.87 were installed and not run. Round 4 also shows `onFailure: "block"` has no effect on 2.1.281 (R1, R8, R9 each RAN 2/2 with the key set; `claude/r4-gaps/onfailure/`).
