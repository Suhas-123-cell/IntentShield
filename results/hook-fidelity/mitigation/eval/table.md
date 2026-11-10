| harness | build | scenario | translation off | translation on |
|---|---|---|---|---|
| claude | 2.1.47 | ask | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.47 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.47 | timeout | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.47 | dead | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.89 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.89 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.89 | timeout | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.89 | dead | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.281 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.281 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.281 | timeout | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.281 | dead | RAN 2/2 | BLOCKED 2/2 |
| claude | 2.1.296 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.296 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.296 | timeout | BLOCKED 2/2 | BLOCKED 2/2 |
| claude | 2.1.296 | dead | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.143.0 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.143.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.143.0 | timeout | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.143.0 | dead | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.148.0 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.148.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.148.0 | timeout | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.148.0 | dead | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.155.0 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.155.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.155.0 | timeout | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.155.0 | dead | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.165.0 | ask | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.165.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| codex | 0.165.0 | timeout | RAN 2/2 | BLOCKED 2/2 |
| codex | 0.165.0 | dead | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.29.7 | ask | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.29.7 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| gemini | 0.29.7 | timeout | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.29.7 | dead | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.37.1 | ask | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.37.1 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| gemini | 0.37.1 | timeout | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.38.0 | ask | HUNG 2/2 | BLOCKED 2/2 |
| gemini | 0.38.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| gemini | 0.38.0 | timeout | RAN 2/2 | BLOCKED 2/2 |
| gemini | 0.43.0 | ask | HUNG 2/2 | BLOCKED 2/2 |
| gemini | 0.43.0 | deny | BLOCKED 2/2 | BLOCKED 2/2 |
| gemini | 0.43.0 | timeout | RAN 2/2 | BLOCKED 2/2 |

Changed from RAN or HUNG (off) to BLOCKED (on), paired runs:
- claude: 14/14 (95% Wilson 78 to 100%); by scenario: ask 2/2 (95% Wilson 34 to 100%), dead 6/6 (95% Wilson 61 to 100%), timeout 6/6 (95% Wilson 61 to 100%)
- codex: 16/16 (95% Wilson 81 to 100%); by scenario: timeout 8/8 (95% Wilson 68 to 100%), dead 8/8 (95% Wilson 68 to 100%)
- gemini: 18/18 (95% Wilson 82 to 100%); by scenario: ask 8/8 (95% Wilson 68 to 100%), timeout 8/8 (95% Wilson 68 to 100%), dead 2/2 (95% Wilson 34 to 100%)

Regressions (off BLOCKED, on RAN or HUNG):
- claude: 0/18 (95% Wilson 0 to 18%)
- codex: 0/16 (95% Wilson 0 to 19%)
- gemini: 0/8 (95% Wilson 0 to 32%)

INVALID runs (excluded from every rate):
- gemini 0.37.1 dead off #0: the stub issued no call
- gemini 0.37.1 dead off #1: the stub issued no call
- gemini 0.37.1 dead on #0: the stub issued no call
- gemini 0.37.1 dead on #1: the stub issued no call
- gemini 0.38.0 dead off #0: the stub issued no call
- gemini 0.38.0 dead off #1: the stub issued no call
- gemini 0.38.0 dead on #0: the stub issued no call
- gemini 0.38.0 dead on #1: the stub issued no call
- gemini 0.43.0 dead off #0: the stub issued no call
- gemini 0.43.0 dead off #1: the stub issued no call
- gemini 0.43.0 dead on #0: the stub issued no call
- gemini 0.43.0 dead on #1: the stub issued no call

Fit-only table against the held-out builds (translation OFF arm):

| harness | build | feature | class from fit-only ranges | predicted off | observed off | hit |
|---|---|---|---|---|---|---|
| claude | 2.1.47 | ask | dropped | RAN | RAN | yes |
| claude | 2.1.47 | dead | runs | RAN | RAN | yes |
| claude | 2.1.89 | ask | uncertain | - | BLOCKED | no prediction (class uncertain) |
| claude | 2.1.89 | dead | runs | RAN | RAN | yes |
| claude | 2.1.281 | ask | denied | BLOCKED | BLOCKED | yes |
| claude | 2.1.281 | dead | runs | RAN | RAN | yes |
| claude | 2.1.296 | ask | denied | BLOCKED | BLOCKED | yes |
| claude | 2.1.296 | dead | runs | RAN | BLOCKED | NO |
| codex | 0.143.0 | dead | unmeasured | - | RAN | no prediction (class unmeasured) |
| codex | 0.148.0 | dead | unmeasured | - | RAN | no prediction (class unmeasured) |
| codex | 0.155.0 | dead | unmeasured | - | RAN | no prediction (class unmeasured) |
| codex | 0.165.0 | dead | unmeasured | - | RAN | no prediction (class unmeasured) |
| gemini | 0.29.7 | ask | dropped | RAN | RAN | yes |
| gemini | 0.29.7 | dead | uncertain | - | RAN | no prediction (class uncertain) |
| gemini | 0.37.1 | ask | dropped | RAN | RAN | yes |
| gemini | 0.38.0 | ask | uncertain | - | HUNG | no prediction (class uncertain) |
| gemini | 0.43.0 | ask | hangs | HUNG | HUNG | yes |

