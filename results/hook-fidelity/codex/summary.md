<!-- round 4: regenerated from runs.jsonl (round 3, 428 rows) plus r4-gaps/runs.jsonl (39 rows): cat runs.jsonl r4-gaps/runs.jsonl | run.py summarize; the 5 CONFIG-INVALID blocks and every round-3 cell are unchanged, the r4 rows add R0 controls and persisted-trust failure replies -->
467 runs (0 INVALID, left out of n), 192 cells: config-invalid 5, control 54, scored 133
informative cells (scored and differing from P_guard, P_doc or the prediction): 91

CONFIG-INVALID blocks (the neutral control did not prove the hook fires under this exact config; this is NOT a harness finding, fix the config first):
  codex 0.131.0 M1 shell trusted-bypass - plain S: R1 hook invoked 0/2 valid runs
  codex 0.133.0 M1 shell trusted-bypass - plain S: R1 hook invoked 0/2 valid runs
  codex 0.134.0 M1 shell trusted-bypass - plain S: R1 hook invoked 0/2 valid runs
  codex 0.136.0 M1 shell trusted-bypass - plain S: R1 hook invoked 0/2 valid runs
  codex 0.140.0 M1 shell trusted-bypass - plain S: R1 hook invoked 0/2 valid runs

gated blocks scored on a partner's liveness proof:
  codex 0.143.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.145.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.148.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.149.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.150.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.152.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.155.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.158.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.162.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.164.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.165.0 M1 mcp untrusted - plain S <- proven by state trusted-bypass
  codex 0.165.0 M1 shell untrusted - plain S <- proven by state trusted-bypass
  codex 0.166.0 M1 mcp untrusted - plain S <- proven by state trusted-bypass
  codex 0.166.0 M1 shell untrusted - plain S <- proven by state trusted-bypass

R0 (no hook) versus R1 (neutral hook), per block:
  codex 0.131.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.131.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.133.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.133.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.134.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.134.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.136.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.136.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.140.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.140.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.143.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.143.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.145.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.145.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.148.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.148.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.149.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.149.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.150.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.150.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.152.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.152.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.155.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.155.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.158.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.158.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.162.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.162.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.164.0 M1 shell trusted-bypass - plain S: R0 RAN:1 | R1 RAN:2 | same
  codex 0.164.0 M1 shell untrusted - plain S: R0 none | R1 RAN:1 | no-r0
  codex 0.165.0 M1 mcp trusted-bypass - plain S: R0 RAN:5 | R1 RAN:5 | same
  codex 0.165.0 M1 mcp untrusted - plain S: R0 none | R1 RAN:5 | no-r0
  codex 0.165.0 M1 shell trusted-bypass - plain S: R0 RAN:5 | R1 RAN:5 | same
  codex 0.165.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.165.0 M1 shell untrusted - plain S: R0 none | R1 RAN:5 | no-r0
  codex 0.166.0 M1 mcp trusted-bypass - plain S: R0 RAN:5 | R1 RAN:5 | same
  codex 0.166.0 M1 mcp untrusted - plain S: R0 none | R1 RAN:5 | no-r0
  codex 0.166.0 M1 shell trusted-bypass - plain S: R0 RAN:5 | R1 RAN:5 | same
  codex 0.166.0 M1 shell trusted-persisted - plain S: R0 none | R1 RAN:2 | no-r0
  codex 0.166.0 M1 shell untrusted - plain S: R0 none | R1 RAN:5 | no-r0

cell                                                                       result                         class
codex 0.131.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.131.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        config-invalid | hook invoked 0/2
codex 0.131.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.131.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.131.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.131.0 M1 shell trusted-persisted - plain arm S R7                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.133.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.133.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        config-invalid | hook invoked 0/2
codex 0.133.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.133.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.133.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.133.0 M1 shell trusted-persisted - plain arm S R7                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.134.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.134.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        config-invalid | hook invoked 0/2
codex 0.134.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.134.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.134.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.134.0 M1 shell trusted-persisted - plain arm S R7                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.136.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.136.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        config-invalid | hook invoked 0/2
codex 0.136.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.136.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.136.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.136.0 M1 shell trusted-persisted - plain arm S R7                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.140.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.140.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        config-invalid | hook invoked 0/2
codex 0.140.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.140.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.140.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.140.0 M1 shell trusted-persisted - plain arm S R7                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.143.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.143.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.143.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.143.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.145.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.145.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.145.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.145.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.148.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.148.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.148.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.148.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.149.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.149.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.149.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.149.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.150.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.150.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.150.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.150.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.152.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.152.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.152.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.152.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.155.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.155.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.155.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.155.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.158.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.158.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.158.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.158.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.162.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.162.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.162.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.162.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R0                     1/1 RAN                        control
codex 0.164.0 M1 shell trusted-bypass - plain arm S R1                     2/2 RAN                        control | hook invoked 2/2
codex 0.164.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R3                     2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R4                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R7                     0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 1/1 R1 2/2 RAN
codex 0.164.0 M1 shell untrusted - plain arm S R1                          1/1 RAN                        control | hook invoked 0/1
codex 0.164.0 M1 shell untrusted - plain arm S R4                          2/2 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/2; ctl R0 - R1 1/1 RAN
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R0                       5/5 RAN                        control
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R1                       5/5 RAN                        control | hook invoked 5/5
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R3                       5/5 RAN                        VERDICT-DROPPED | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R4                       0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R5                       5/5 RAN                        FAILURE-OPEN | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 mcp trusted-bypass - plain arm S R7                       0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 mcp untrusted - plain arm S R1                            5/5 RAN                        control | hook invoked 0/5
codex 0.165.0 M1 mcp untrusted - plain arm S R4                            5/5 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/5; ctl R0 - R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R0                     5/5 RAN                        control
codex 0.165.0 M1 shell trusted-bypass - plain arm S R1                     5/5 RAN                        control | hook invoked 5/5
codex 0.165.0 M1 shell trusted-bypass - plain arm S R10b                   5/5 RAN                        FAILURE-OPEN | hook unobservable (file-level reply); ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R15                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R2                     5/5 RAN                        - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R3                     5/5 RAN                        VERDICT-DROPPED | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R4                     0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R5                     5/5 RAN                        FAILURE-OPEN | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R6                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R7                     0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R8                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.165.0 M1 shell trusted-persisted - plain arm S R11                 2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R16                 2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R5                  2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell trusted-persisted - plain arm S R9                  2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.165.0 M1 shell untrusted - plain arm S R1                          5/5 RAN                        control | hook invoked 0/5
codex 0.165.0 M1 shell untrusted - plain arm S R4                          5/5 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/5; ctl R0 - R1 5/5 RAN
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R0                       5/5 RAN                        control
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R1                       5/5 RAN                        control | hook invoked 5/5
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R3                       5/5 RAN                        VERDICT-DROPPED | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R4                       0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R5                       5/5 RAN                        FAILURE-OPEN | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 mcp trusted-bypass - plain arm S R7                       0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 mcp untrusted - plain arm S R1                            5/5 RAN                        control | hook invoked 0/5
codex 0.166.0 M1 mcp untrusted - plain arm S R4                            5/5 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/5; ctl R0 - R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R0                     5/5 RAN                        control
codex 0.166.0 M1 shell trusted-bypass - plain arm S R1                     5/5 RAN                        control | hook invoked 5/5
codex 0.166.0 M1 shell trusted-bypass - plain arm S R10b                   5/5 RAN                        FAILURE-OPEN | hook unobservable (file-level reply); ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R11                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R15                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R16                    2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R2                     5/5 RAN                        - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R3                     5/5 RAN                        VERDICT-DROPPED | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R4                     0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R5                     5/5 RAN                        FAILURE-OPEN | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R6                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R7                     0/5 RAN modal BLOCKED 5/5      - | hook invoked 5/5; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R8                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-bypass - plain arm S R9                     2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 5/5 R1 5/5 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R1                  2/2 RAN                        control | hook invoked 2/2
codex 0.166.0 M1 shell trusted-persisted - plain arm S R11                 2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R16                 2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R3                  2/2 RAN                        VERDICT-DROPPED | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R4                  0/2 RAN modal BLOCKED 2/2      - | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R5                  2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell trusted-persisted - plain arm S R9                  2/2 RAN                        FAILURE-OPEN | hook invoked 2/2; ctl R0 - R1 2/2 RAN
codex 0.166.0 M1 shell untrusted - plain arm S R1                          5/5 RAN                        control | hook invoked 0/5
codex 0.166.0 M1 shell untrusted - plain arm S R4                          5/5 RAN                        HOOK-NOT-INVOKED | weak attempt evidence; hook invoked 0/5; ctl R0 - R1 5/5 RAN

classes per harness: codex: FAILURE-OPEN x56, HOOK-NOT-INVOKED x14, VERDICT-DROPPED x21
prediction hits by basis: docs hit x117, source hit x16
kill criterion (>= 5 undocumented deviations replicating on >= 3 versions): not met over codex
  codex: 0 undocumented, 0 on every one of 17 version(s) run, 0 on 3+
