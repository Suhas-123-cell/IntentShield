# Round 4 mitigation cells (36 launches, n=1 per cell, stub model, headless, shell call)

## Allow control (the call must run)

| harness | build | translation off | translation on | deny-all control |
|---|---|---|---|---|
| claude | 2.1.47 | RAN | RAN | BLOCKED |
| claude | 2.1.89 | RAN | RAN | not run |
| claude | 2.1.281 | RAN | RAN | not run |
| claude | 2.1.296 | BLOCKED (native gate) | BLOCKED (native gate) | BLOCKED |
| codex | 0.143.0 | RAN | RAN | BLOCKED |
| codex | 0.148.0 | RAN | RAN | not run |
| codex | 0.155.0 | RAN | RAN | not run |
| codex | 0.165.0 | RAN | RAN | BLOCKED |
| gemini | 0.29.7 | RAN | RAN | BLOCKED |
| gemini | 0.37.1 | RAN | RAN | not run |
| gemini | 0.38.0 | RAN | RAN | not run |
| gemini | 0.43.0 | RAN | RAN | BLOCKED |

Evaluable allow cells 11 of 12; native-gate cells excluded: claude 2.1.296. Translation off ran the call in 11 of 11; translation on ran it in 11 of 11. The deny-all control was BLOCKED in 6 of 6 cells, where the translation ran the call in 5 of 6.

## Shipped deadline (30 s, no handler timeout override, a 45 s guard)

| harness | build | outcome | wall s |
|---|---|---|---|
| claude | 2.1.296 | BLOCKED | 30.57 |
| codex | 0.165.0 | BLOCKED | 30.75 |
| gemini | 0.43.0 | BLOCKED | 31.02 |

## Headless ask with no version recorded (translation on)

| harness | build | outcome |
|---|---|---|
| claude | 2.1.47 | BLOCKED |
| gemini | 0.37.1 | BLOCKED |
| gemini | 0.43.0 | BLOCKED |
