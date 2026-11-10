# Breakdown of the corrected held-out set (derived by `detect_compare.py breakdown`)

Primary rendering mix (each item once, round-robin over the shapes that fit): harmful {'claude': 75, 'codex': 42, 'gemini': 49}, benign {'gemini': 66, 'codex': 55, 'claude': 113}.

## Benign false-deny and false-ask, near-miss items apart from ordinary development items (claimed view)

| guard | near-miss n | near-miss deny | near-miss ask | ordinary n | ordinary deny | ordinary ask |
|---|---|---|---|---|---|---|
| cc-safe-setup | 20 | 2 | 0 | 54 | 0 | 0 |
| safety-net | 48 | 3 | 0 | 112 | 0 | 0 |
| railway-guard | 16 | 0 | 0 | 35 | 0 | 0 |
| block-no-verify | 32 | 0 | 0 | 73 | 0 | 0 |
| gemini-intrupt-hook | 20 | 20 | 0 | 46 | 46 | 0 |
| gemini-intrupt-hook[local-filter] | 20 | 7 | 0 | 46 | 9 | 0 |
| prevent-destructive | 16 | 6 | 0 | 35 | 0 | 0 |
| tob-codex-config | 16 | 5 | 0 | 39 | 0 | 0 |
| claude-codex-settings[force-push] | 16 | 0 | 0 | 35 | 1 | 0 |
| knox | 45 | 0 | 0 | 123 | 0 | 0 |
| intentshield | 65 | 0 | 1 | 169 | 0 | 0 |
| intentshield-default | 8 | 0 | 1 | 23 | 0 | 0 |
| intentshield-nostate | 65 | 0 | 0 | 169 | 0 | 0 |
| intentshield-always | 65 | 0 | 53 | 169 | 0 | 123 |
| intentshield-tainted | 45 | 0 | 28 | 123 | 0 | 40 |

## Decisions per harness shape (every rendering of each held-out item in the guard's scope; allow includes error)

| guard | harness | harmful n | allow | ask | deny | benign n | allow | ask | deny |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | claude | 148 | 122 | 0 | 26 | 195 | 192 | 0 | 3 |
| safety-net | claude | 130 | 31 | 4 | 95 | 160 | 157 | 0 | 3 |
| safety-net | codex | 130 | 31 | 0 | 99 | 160 | 157 | 0 | 3 |
| safety-net | gemini | 130 | 31 | 0 | 99 | 160 | 157 | 0 | 3 |
| railway-guard | claude | 130 | 130 | 0 | 0 | 160 | 160 | 0 | 0 |
| block-no-verify | claude | 130 | 119 | 0 | 11 | 160 | 160 | 0 | 0 |
| block-no-verify | gemini | 130 | 119 | 0 | 11 | 160 | 160 | 0 | 0 |
| gemini-intrupt-hook | gemini | 143 | 0 | 0 | 143 | 183 | 0 | 0 | 183 |
| gemini-intrupt-hook[local-filter] | gemini | 143 | 62 | 0 | 81 | 183 | 149 | 0 | 34 |
| prevent-destructive | claude | 130 | 98 | 0 | 32 | 160 | 142 | 0 | 18 |
| tob-codex-config | codex | 130 | 94 | 0 | 36 | 160 | 143 | 0 | 17 |
| claude-codex-settings[force-push] | claude | 130 | 118 | 0 | 12 | 160 | 157 | 0 | 3 |
| knox | claude | 166 | 93 | 0 | 73 | 234 | 233 | 0 | 1 |
| knox | codex | 130 | 67 | 0 | 63 | 160 | 159 | 0 | 1 |
| intentshield | claude | 166 | 137 | 29 | 0 | 234 | 233 | 1 | 0 |
| intentshield | codex | 130 | 111 | 19 | 0 | 160 | 160 | 0 | 0 |
| intentshield | gemini | 143 | 124 | 19 | 0 | 183 | 183 | 0 | 0 |
| intentshield-default | claude | 10 | 0 | 10 | 0 | 31 | 30 | 1 | 0 |
| intentshield-nostate | claude | 166 | 147 | 19 | 0 | 234 | 234 | 0 | 0 |
| intentshield-nostate | codex | 130 | 111 | 19 | 0 | 160 | 160 | 0 | 0 |
| intentshield-nostate | gemini | 143 | 124 | 19 | 0 | 183 | 183 | 0 | 0 |
| intentshield-always | claude | 166 | 3 | 163 | 0 | 234 | 58 | 176 | 0 |
| intentshield-always | codex | 130 | 2 | 128 | 0 | 160 | 28 | 132 | 0 |
| intentshield-always | gemini | 143 | 2 | 141 | 0 | 183 | 28 | 155 | 0 |
| intentshield-tainted | claude | 166 | 9 | 138 | 19 | 234 | 134 | 100 | 0 |
| intentshield-tainted | codex | 130 | 8 | 103 | 19 | 160 | 69 | 91 | 0 |
