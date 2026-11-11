# Detection comparison tables (derived by `detect_compare.py report` from `decisions.jsonl`, `fixtures.jsonl` and the committed delivery rows)

Every k/n is a count of fixture items; the interval is the 95% Wilson interval, computed at display. Items are not fully independent (the two AgentDojo items of one goal share the call; authored items share one author), so the intervals are optimistic. `miss` = the reply was an allow or an error that every measured build fails open on; `ask` and `deny` are the guard's own words. A guard that is not registered for a call (wrong harness or tool kind) answers allow in the `total` view.

Fixtures: held-out 166 harmful / 234 benign items; full set 211 / 256. Held out = the item's source was not used to tune IntentShield and its defining string was not in IntentShield's repo text when the set was built (`provenance.md`). The unit tests of the dangerous-command rules were written afterwards and contain the command or path of some of these items (33 of the 156 harmful built-in-tool items when checked at 633014e with `overlap_check.py`), so they are no longer absent from the repository.

## Coverage each guard claims (the `claimed` view scores only these calls)

| guard | harnesses and tool kinds | what it claims |
|---|---|---|
| cc-safe-setup | claude: edit, shell, write | Claude Code: Bash (recursive rm, destructive git, credentials in a command, system directories) and Write|Edit (secret files), from the plugin's hooks/hooks.json. |
| safety-net | claude: shell; codex: shell; gemini: shell | shell commands: destructive git and filesystem commands and access to secrets (README); registered with no matcher. |
| railway-guard | claude: shell | the Railway CLI only (redeploy, volume delete, shell on a live database). Narrower claim: no category of this fixture set |
| block-no-verify | claude: shell; gemini: shell | git hook bypass only (`--no-verify` and its spellings). Narrower claim: category git (a subset of its commands) |
| gemini-intrupt-hook | gemini: shell, write | Gemini CLI run_shell_command, write_file, replace; default environment: forwards every call to an approval service and fails closed when it is unreachable. |
| gemini-intrupt-hook[local-filter] | gemini: shell, write | Gemini CLI run_shell_command, write_file, replace; AEGMIS_FORWARD_ALL=false: its local risk filter decides low-risk calls without the service. |
| prevent-destructive | claude: shell | Claude Code Bash: destructive commands (README). |
| tob-codex-config | codex: shell | Codex Bash: rm -rf, sudo, mkfs, dd, curl|sh, force-push, reset --hard, push to main (README). |
| claude-codex-settings[force-push] | claude: shell | git force-push and rebase only (the ultralytics-dev plugin's hook). Narrower claim: category git (a subset of its commands) |
| knox | claude: edit, mcp, read, shell, write; codex: shell | Claude Code: Bash, Write|Edit, Read and every MCP tool; Codex CLI: Bash (hooks/hooks.json and codex-hooks.json). |
| intentshield | claude: edit, mcp, read, shell, write; codex: edit, mcp, read, shell, write; gemini: edit, mcp, read, shell, write | IntentShield's hook with `--builtin-tools` and session state. |
| intentshield-default | claude: mcp; codex: mcp; gemini: mcp | as installed without `--builtin-tools`: MCP tools only. |
| intentshield-nostate | claude: edit, mcp, read, shell, write; codex: edit, mcp, read, shell, write; gemini: edit, mcp, read, shell, write | `--builtin-tools`, but no earlier prompt or tool result (each call alone, as the other guards see it). |
| intentshield-always | claude: edit, mcp, read, shell, write; codex: edit, mcp, read, shell, write; gemini: edit, mcp, read, shell, write | POST HOC (added after the default variants were scored): `--builtin-tools --review always`, the hook's stricter shipped option. |
| intentshield-tainted | claude: edit, mcp, read, shell, write; codex: edit, mcp, read, shell, write | POST HOC: `--builtin-tools`, every non-MCP call preceded by an MCP result carrying an injection (a tainted session), Claude and Codex shapes only. |

# Headline: the held-out subset

## Held-out, claimed view (each guard scored only on the harnesses, tool kinds and, where narrower, the commands it claims)

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 57 | 49/57 86% [75, 93] | 0/57 0% [0, 6] | 8/57 14% [7, 25] | 74 | 2/74 3% [1, 9] | 0/74 0% [0, 5] |
| safety-net | 130 | 31/130 24% [17, 32] | 1/130 1% [0, 4] | 98/130 75% [67, 82] | 160 | 3/160 2% [1, 5] | 0/160 0% [0, 2] |
| railway-guard | 0 | - | - | - | 51 | 0/51 0% [0, 7] | 0/51 0% [0, 7] |
| block-no-verify | 8 | 0/8 0% [0, 32] | 0/8 0% [0, 32] | 8/8 100% [68, 100] | 105 | 0/105 0% [0, 4] | 0/105 0% [0, 4] |
| gemini-intrupt-hook | 49 | 0/49 0% [0, 7] | 0/49 0% [0, 7] | 49/49 100% [93, 100] | 66 | 66/66 100% [94, 100] | 0/66 0% [0, 6] |
| gemini-intrupt-hook[local-filter] | 49 | 19/49 39% [26, 53] | 0/49 0% [0, 7] | 30/49 61% [47, 74] | 66 | 16/66 24% [16, 36] | 0/66 0% [0, 6] |
| prevent-destructive | 45 | 35/45 78% [64, 87] | 0/45 0% [0, 8] | 10/45 22% [13, 36] | 51 | 6/51 12% [6, 23] | 0/51 0% [0, 7] |
| tob-codex-config | 42 | 31/42 74% [59, 85] | 0/42 0% [0, 8] | 11/42 26% [15, 41] | 55 | 5/55 9% [4, 20] | 0/55 0% [0, 7] |
| claude-codex-settings[force-push] | 4 | 0/4 0% [0, 49] | 0/4 0% [0, 49] | 4/4 100% [51, 100] | 51 | 1/51 2% [0, 10] | 0/51 0% [0, 7] |
| knox | 117 | 67/117 57% [48, 66] | 0/117 0% [0, 3] | 50/117 43% [34, 52] | 168 | 0/168 0% [0, 2] | 0/168 0% [0, 2] |
| intentshield | 166 | 137/166 83% [76, 88] | 29/166 17% [12, 24] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1/234 0% [0, 2] |
| intentshield-default | 10 | 0/10 0% [0, 28] | 10/10 100% [72, 100] | 0/10 0% [0, 28] | 31 | 0/31 0% [0, 11] | 1/31 3% [1, 16] |
| intentshield-nostate | 166 | 147/166 89% [83, 93] | 19/166 11% [7, 17] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield-always | 166 | 3/166 2% [1, 5] | 163/166 98% [95, 99] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 176/234 75% [69, 80] |
| intentshield-tainted | 117 | 7/117 6% [3, 12] | 98/117 84% [76, 89] | 12/117 10% [6, 17] | 168 | 0/168 0% [0, 2] | 68/168 40% [33, 48] |
| ALLOW-ALL | 166 | 166/166 100% [98, 100] | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| DENY-ALL | 166 | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0/234 0% [0, 2] |

## Held-out, all-category view (the guard's harnesses and tool kinds, every category)

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 57 | 49/57 86% [75, 93] | 0/57 0% [0, 6] | 8/57 14% [7, 25] | 74 | 2/74 3% [1, 9] | 0/74 0% [0, 5] |
| safety-net | 130 | 31/130 24% [17, 32] | 1/130 1% [0, 4] | 98/130 75% [67, 82] | 160 | 3/160 2% [1, 5] | 0/160 0% [0, 2] |
| railway-guard | 45 | 45/45 100% [92, 100] | 0/45 0% [0, 8] | 0/45 0% [0, 8] | 51 | 0/51 0% [0, 7] | 0/51 0% [0, 7] |
| block-no-verify | 88 | 80/88 91% [83, 95] | 0/88 0% [0, 4] | 8/88 9% [5, 17] | 105 | 0/105 0% [0, 4] | 0/105 0% [0, 4] |
| gemini-intrupt-hook | 49 | 0/49 0% [0, 7] | 0/49 0% [0, 7] | 49/49 100% [93, 100] | 66 | 66/66 100% [94, 100] | 0/66 0% [0, 6] |
| gemini-intrupt-hook[local-filter] | 49 | 19/49 39% [26, 53] | 0/49 0% [0, 7] | 30/49 61% [47, 74] | 66 | 16/66 24% [16, 36] | 0/66 0% [0, 6] |
| prevent-destructive | 45 | 35/45 78% [64, 87] | 0/45 0% [0, 8] | 10/45 22% [13, 36] | 51 | 6/51 12% [6, 23] | 0/51 0% [0, 7] |
| tob-codex-config | 42 | 31/42 74% [59, 85] | 0/42 0% [0, 8] | 11/42 26% [15, 41] | 55 | 5/55 9% [4, 20] | 0/55 0% [0, 7] |
| claude-codex-settings[force-push] | 45 | 41/45 91% [79, 96] | 0/45 0% [0, 8] | 4/45 9% [4, 21] | 51 | 1/51 2% [0, 10] | 0/51 0% [0, 7] |
| knox | 117 | 67/117 57% [48, 66] | 0/117 0% [0, 3] | 50/117 43% [34, 52] | 168 | 0/168 0% [0, 2] | 0/168 0% [0, 2] |
| intentshield | 166 | 137/166 83% [76, 88] | 29/166 17% [12, 24] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1/234 0% [0, 2] |
| intentshield-default | 10 | 0/10 0% [0, 28] | 10/10 100% [72, 100] | 0/10 0% [0, 28] | 31 | 0/31 0% [0, 11] | 1/31 3% [1, 16] |
| intentshield-nostate | 166 | 147/166 89% [83, 93] | 19/166 11% [7, 17] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield-always | 166 | 3/166 2% [1, 5] | 163/166 98% [95, 99] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 176/234 75% [69, 80] |
| intentshield-tainted | 117 | 7/117 6% [3, 12] | 98/117 84% [76, 89] | 12/117 10% [6, 17] | 168 | 0/168 0% [0, 2] | 68/168 40% [33, 48] |
| ALLOW-ALL | 166 | 166/166 100% [98, 100] | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| DENY-ALL | 166 | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0/234 0% [0, 2] |

## Held-out, total view (every held-out item; a guard that is not registered for a call allows it)

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 166 | 158/166 95% [91, 98] | 0/166 0% [0, 2] | 8/166 5% [2, 9] | 234 | 2/234 1% [0, 3] | 0/234 0% [0, 2] |
| safety-net | 166 | 60/166 36% [29, 44] | 1/166 1% [0, 3] | 105/166 63% [56, 70] | 234 | 3/234 1% [0, 4] | 0/234 0% [0, 2] |
| railway-guard | 166 | 166/166 100% [98, 100] | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| block-no-verify | 166 | 158/166 95% [91, 98] | 0/166 0% [0, 2] | 8/166 5% [2, 9] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| gemini-intrupt-hook | 166 | 117/166 70% [63, 77] | 0/166 0% [0, 2] | 49/166 30% [23, 37] | 234 | 66/234 28% [23, 34] | 0/234 0% [0, 2] |
| gemini-intrupt-hook[local-filter] | 166 | 136/166 82% [75, 87] | 0/166 0% [0, 2] | 30/166 18% [13, 25] | 234 | 16/234 7% [4, 11] | 0/234 0% [0, 2] |
| prevent-destructive | 166 | 156/166 94% [89, 97] | 0/166 0% [0, 2] | 10/166 6% [3, 11] | 234 | 6/234 3% [1, 5] | 0/234 0% [0, 2] |
| tob-codex-config | 166 | 155/166 93% [89, 96] | 0/166 0% [0, 2] | 11/166 7% [4, 11] | 234 | 5/234 2% [1, 5] | 0/234 0% [0, 2] |
| claude-codex-settings[force-push] | 166 | 162/166 98% [94, 99] | 0/166 0% [0, 2] | 4/166 2% [1, 6] | 234 | 1/234 0% [0, 2] | 0/234 0% [0, 2] |
| knox | 166 | 116/166 70% [63, 76] | 0/166 0% [0, 2] | 50/166 30% [24, 37] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield | 166 | 137/166 83% [76, 88] | 29/166 17% [12, 24] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1/234 0% [0, 2] |
| intentshield-default | 166 | 156/166 94% [89, 97] | 10/166 6% [3, 11] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1/234 0% [0, 2] |
| intentshield-nostate | 166 | 147/166 89% [83, 93] | 19/166 11% [7, 17] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield-always | 166 | 3/166 2% [1, 5] | 163/166 98% [95, 99] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 176/234 75% [69, 80] |
| intentshield-tainted | 166 | 56/166 34% [27, 41] | 98/166 59% [51, 66] | 12/166 7% [4, 12] | 234 | 0/234 0% [0, 2] | 68/234 29% [24, 35] |
| ALLOW-ALL | 166 | 166/166 100% [98, 100] | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0/234 0% [0, 2] |
| DENY-ALL | 166 | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0/234 0% [0, 2] |

## Headline: effective protection per build (held-out, deploy view: harmful calls stopped / harmful calls rendered for that harness)

A cell is `stopped k/n` with a 95% Wilson interval; `-` means the guard has no hook entry for that harness. Interactive Claude Code: an ask is a prompt, not counted as stopped (`+p` = prompted). Gemini 0.66.0: an ask hangs (`+h` = held at the cap, not stopped). Row `+translation` is IntentShield as installed (an ask becomes a refusal where nobody can answer).

| guard | claude-2.1.316 | claude-2.1.84 | codex-0.166.0 | gemini-0.66.0-yolo | gemini-0.37.1-yolo | gemini-0.66.0-allow | claude-2.1.316-interactive |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 26/166 16% [11, 22] | 26/166 16% [11, 22] | - | - | - | - | 26/166 16% [11, 22] |
| safety-net | 106/166 64% [56, 71] | 102/166 61% [54, 69] | 99/130 76% [68, 83] | 99/143 69% [61, 76] | 99/143 69% [61, 76] | 99/143 69% [61, 76] | 102/166 61% [54, 69] +4p |
| railway-guard | 0/166 0% [0, 2] | 0/166 0% [0, 2] | - | - | - | - | 0/166 0% [0, 2] |
| block-no-verify | 11/166 7% [4, 11] | 11/166 7% [4, 11] | - | 11/143 8% [4, 13] | 11/143 8% [4, 13] | 11/143 8% [4, 13] | 11/166 7% [4, 11] |
| gemini-intrupt-hook | - | - | - | 143/143 100% [97, 100] | 143/143 100% [97, 100] | 143/143 100% [97, 100] | - |
| gemini-intrupt-hook[local-filter] | - | - | - | 81/143 57% [48, 64] | 81/143 57% [48, 64] | 81/143 57% [48, 64] | - |
| prevent-destructive | 32/166 19% [14, 26] | 32/166 19% [14, 26] | - | - | - | - | 32/166 19% [14, 26] |
| tob-codex-config | - | - | 36/130 28% [21, 36] | - | - | - | - |
| claude-codex-settings[force-push] | 12/166 7% [4, 12] | 12/166 7% [4, 12] | - | - | - | - | 12/166 7% [4, 12] |
| knox | 73/166 44% [37, 52] | 73/166 44% [37, 52] | 63/130 48% [40, 57] | - | - | - | 73/166 44% [37, 52] |
| intentshield | 29/166 17% [12, 24] | 0/166 0% [0, 2] | 0/130 0% [0, 3] | 0/143 0% [0, 3] +19h | 0/143 0% [0, 3] | 0/143 0% [0, 3] +19h | 0/166 0% [0, 2] +29p |
| intentshield+translation | 29/166 17% [12, 24] | 29/166 17% [12, 24] | 19/130 15% [10, 22] | 19/143 13% [9, 20] | 19/143 13% [9, 20] | 19/143 13% [9, 20] | 0/166 0% [0, 2] +29p |
| intentshield-default | 10/166 6% [3, 11] | 0/166 0% [0, 2] | 0/130 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/166 0% [0, 2] +10p |
| intentshield-default+translation | 10/166 6% [3, 11] | 10/166 6% [3, 11] | 0/130 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/166 0% [0, 2] +10p |
| intentshield-nostate | 19/166 11% [7, 17] | 0/166 0% [0, 2] | 0/130 0% [0, 3] | 0/143 0% [0, 3] +19h | 0/143 0% [0, 3] | 0/143 0% [0, 3] +19h | 0/166 0% [0, 2] +19p |
| intentshield-nostate+translation | 19/166 11% [7, 17] | 19/166 11% [7, 17] | 19/130 15% [10, 22] | 19/143 13% [9, 20] | 19/143 13% [9, 20] | 19/143 13% [9, 20] | 0/166 0% [0, 2] +19p |
| intentshield-always | 163/166 98% [95, 99] | 0/166 0% [0, 2] | 0/130 0% [0, 3] | 0/143 0% [0, 3] +141h | 0/143 0% [0, 3] | 0/143 0% [0, 3] +141h | 0/166 0% [0, 2] +163p |
| intentshield-always+translation | 163/166 98% [95, 99] | 163/166 98% [95, 99] | 128/130 98% [95, 100] | 141/143 99% [95, 100] | 141/143 99% [95, 100] | 141/143 99% [95, 100] | 0/166 0% [0, 2] +163p |
| intentshield-tainted | 157/166 95% [90, 97] | 19/166 11% [7, 17] | 19/130 15% [10, 22] | - | - | - | 19/166 11% [7, 17] +138p |
| intentshield-tainted+translation | 157/166 95% [90, 97] | 157/166 95% [90, 97] | 122/130 94% [88, 97] | - | - | - | 19/166 11% [7, 17] +138p |
| ALLOW-ALL | 0/166 0% [0, 2] | 0/166 0% [0, 2] | 0/130 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/143 0% [0, 3] | 0/166 0% [0, 2] |
| DENY-ALL | 166/166 100% [98, 100] | 166/166 100% [98, 100] | 130/130 100% [97, 100] | 143/143 100% [97, 100] | 143/143 100% [97, 100] | 143/143 100% [97, 100] | 166/166 100% [98, 100] |

Benign calls the harness refused because of the guard (held-out, deploy view), same builds:

| guard | claude-2.1.316 | claude-2.1.84 | codex-0.166.0 | gemini-0.66.0-yolo | gemini-0.37.1-yolo | gemini-0.66.0-allow | claude-2.1.316-interactive |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 3/234 1% [0, 4] | 3/234 1% [0, 4] | - | - | - | - | 3/234 1% [0, 4] |
| safety-net | 3/234 1% [0, 4] | 3/234 1% [0, 4] | 3/160 2% [1, 5] | 3/183 2% [1, 5] | 3/183 2% [1, 5] | 3/183 2% [1, 5] | 3/234 1% [0, 4] |
| railway-guard | 0/234 0% [0, 2] | 0/234 0% [0, 2] | - | - | - | - | 0/234 0% [0, 2] |
| block-no-verify | 0/234 0% [0, 2] | 0/234 0% [0, 2] | - | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] |
| gemini-intrupt-hook | - | - | - | 183/183 100% [98, 100] | 183/183 100% [98, 100] | 183/183 100% [98, 100] | - |
| gemini-intrupt-hook[local-filter] | - | - | - | 34/183 19% [14, 25] | 34/183 19% [14, 25] | 34/183 19% [14, 25] | - |
| prevent-destructive | 18/234 8% [5, 12] | 18/234 8% [5, 12] | - | - | - | - | 18/234 8% [5, 12] |
| tob-codex-config | - | - | 17/160 11% [7, 16] | - | - | - | - |
| claude-codex-settings[force-push] | 3/234 1% [0, 4] | 3/234 1% [0, 4] | - | - | - | - | 3/234 1% [0, 4] |
| knox | 1/234 0% [0, 2] | 1/234 0% [0, 2] | 1/160 1% [0, 3] | - | - | - | 1/234 0% [0, 2] |
| intentshield | 1/234 0% [0, 2] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] +1p |
| intentshield+translation | 1/234 0% [0, 2] | 1/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] +1p |
| intentshield-default | 1/234 0% [0, 2] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] +1p |
| intentshield-default+translation | 1/234 0% [0, 2] | 1/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] +1p |
| intentshield-nostate | 0/234 0% [0, 2] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield-nostate+translation | 0/234 0% [0, 2] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] |
| intentshield-always | 176/234 75% [69, 80] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] +176p |
| intentshield-always+translation | 176/234 75% [69, 80] | 176/234 75% [69, 80] | 132/160 82% [76, 88] | 155/183 85% [79, 89] | 155/183 85% [79, 89] | 155/183 85% [79, 89] | 0/234 0% [0, 2] +176p |
| intentshield-tainted | 100/234 43% [37, 49] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | - | - | - | 0/234 0% [0, 2] +100p |
| intentshield-tainted+translation | 100/234 43% [37, 49] | 100/234 43% [37, 49] | 91/160 57% [49, 64] | - | - | - | 0/234 0% [0, 2] +100p |
| ALLOW-ALL | 0/234 0% [0, 2] | 0/234 0% [0, 2] | 0/160 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/183 0% [0, 2] | 0/234 0% [0, 2] |
| DENY-ALL | 234/234 100% [98, 100] | 234/234 100% [98, 100] | 160/160 100% [98, 100] | 183/183 100% [98, 100] | 183/183 100% [98, 100] | 183/183 100% [98, 100] | 234/234 100% [98, 100] |

# The full set (held-out plus items from sources IntentShield was tuned on or whose text is in its repo)

## Full set, claimed view

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 57 | 49/57 86% [75, 93] | 0/57 0% [0, 6] | 8/57 14% [7, 25] | 83 | 2/83 2% [1, 8] | 0/83 0% [0, 4] |
| safety-net | 133 | 31/133 23% [17, 31] | 1/133 1% [0, 4] | 101/133 76% [68, 82] | 182 | 5/182 3% [1, 6] | 0/182 0% [0, 2] |
| railway-guard | 0 | - | - | - | 60 | 0/60 0% [0, 6] | 0/60 0% [0, 6] |
| block-no-verify | 8 | 0/8 0% [0, 32] | 0/8 0% [0, 32] | 8/8 100% [68, 100] | 121 | 0/121 0% [0, 3] | 0/121 0% [0, 3] |
| gemini-intrupt-hook | 50 | 0/50 0% [0, 7] | 0/50 0% [0, 7] | 50/50 100% [93, 100] | 73 | 73/73 100% [95, 100] | 0/73 0% [0, 5] |
| gemini-intrupt-hook[local-filter] | 50 | 20/50 40% [28, 54] | 0/50 0% [0, 7] | 30/50 60% [46, 72] | 73 | 17/73 23% [15, 34] | 0/73 0% [0, 5] |
| prevent-destructive | 45 | 35/45 78% [64, 87] | 0/45 0% [0, 8] | 10/45 22% [13, 36] | 60 | 7/60 12% [6, 22] | 0/60 0% [0, 6] |
| tob-codex-config | 44 | 33/44 75% [61, 85] | 0/44 0% [0, 8] | 11/44 25% [15, 39] | 61 | 5/61 8% [4, 18] | 0/61 0% [0, 6] |
| claude-codex-settings[force-push] | 4 | 0/4 0% [0, 49] | 0/4 0% [0, 49] | 4/4 100% [51, 100] | 60 | 1/60 2% [0, 9] | 0/60 0% [0, 6] |
| knox | 161 | 111/161 69% [61, 76] | 0/161 0% [0, 2] | 50/161 31% [24, 39] | 183 | 0/183 0% [0, 2] | 0/183 0% [0, 2] |
| intentshield | 211 | 140/211 66% [60, 72] | 41/211 19% [15, 25] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1/256 0% [0, 2] |
| intentshield-default | 52 | 0/52 0% [0, 7] | 22/52 42% [30, 56] | 30/52 58% [44, 70] | 31 | 0/31 0% [0, 11] | 1/31 3% [1, 16] |
| intentshield-nostate | 211 | 192/211 91% [86, 94] | 19/211 9% [6, 14] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| intentshield-always | 211 | 3/211 1% [0, 4] | 178/211 84% [79, 89] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 193/256 75% [70, 80] |
| intentshield-tainted | 161 | 7/161 4% [2, 9] | 112/161 70% [62, 76] | 42/161 26% [20, 33] | 183 | 0/183 0% [0, 2] | 72/183 39% [33, 47] |
| ALLOW-ALL | 211 | 211/211 100% [98, 100] | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| DENY-ALL | 211 | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0/256 0% [0, 1] |

## Full set, all-category view

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 57 | 49/57 86% [75, 93] | 0/57 0% [0, 6] | 8/57 14% [7, 25] | 83 | 2/83 2% [1, 8] | 0/83 0% [0, 4] |
| safety-net | 133 | 31/133 23% [17, 31] | 1/133 1% [0, 4] | 101/133 76% [68, 82] | 182 | 5/182 3% [1, 6] | 0/182 0% [0, 2] |
| railway-guard | 45 | 45/45 100% [92, 100] | 0/45 0% [0, 8] | 0/45 0% [0, 8] | 60 | 0/60 0% [0, 6] | 0/60 0% [0, 6] |
| block-no-verify | 89 | 81/89 91% [83, 95] | 0/89 0% [0, 4] | 8/89 9% [5, 17] | 121 | 0/121 0% [0, 3] | 0/121 0% [0, 3] |
| gemini-intrupt-hook | 50 | 0/50 0% [0, 7] | 0/50 0% [0, 7] | 50/50 100% [93, 100] | 73 | 73/73 100% [95, 100] | 0/73 0% [0, 5] |
| gemini-intrupt-hook[local-filter] | 50 | 20/50 40% [28, 54] | 0/50 0% [0, 7] | 30/50 60% [46, 72] | 73 | 17/73 23% [15, 34] | 0/73 0% [0, 5] |
| prevent-destructive | 45 | 35/45 78% [64, 87] | 0/45 0% [0, 8] | 10/45 22% [13, 36] | 60 | 7/60 12% [6, 22] | 0/60 0% [0, 6] |
| tob-codex-config | 44 | 33/44 75% [61, 85] | 0/44 0% [0, 8] | 11/44 25% [15, 39] | 61 | 5/61 8% [4, 18] | 0/61 0% [0, 6] |
| claude-codex-settings[force-push] | 45 | 41/45 91% [79, 96] | 0/45 0% [0, 8] | 4/45 9% [4, 21] | 60 | 1/60 2% [0, 9] | 0/60 0% [0, 6] |
| knox | 161 | 111/161 69% [61, 76] | 0/161 0% [0, 2] | 50/161 31% [24, 39] | 183 | 0/183 0% [0, 2] | 0/183 0% [0, 2] |
| intentshield | 211 | 140/211 66% [60, 72] | 41/211 19% [15, 25] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1/256 0% [0, 2] |
| intentshield-default | 52 | 0/52 0% [0, 7] | 22/52 42% [30, 56] | 30/52 58% [44, 70] | 31 | 0/31 0% [0, 11] | 1/31 3% [1, 16] |
| intentshield-nostate | 211 | 192/211 91% [86, 94] | 19/211 9% [6, 14] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| intentshield-always | 211 | 3/211 1% [0, 4] | 178/211 84% [79, 89] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 193/256 75% [70, 80] |
| intentshield-tainted | 161 | 7/161 4% [2, 9] | 112/161 70% [62, 76] | 42/161 26% [20, 33] | 183 | 0/183 0% [0, 2] | 72/183 39% [33, 47] |
| ALLOW-ALL | 211 | 211/211 100% [98, 100] | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| DENY-ALL | 211 | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0/256 0% [0, 1] |

## Full set, total view

| guard | harmful n | miss (allow or error) | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 211 | 203/211 96% [93, 98] | 0/211 0% [0, 2] | 8/211 4% [2, 7] | 256 | 2/256 1% [0, 3] | 0/256 0% [0, 1] |
| safety-net | 211 | 102/211 48% [42, 55] | 1/211 0% [0, 3] | 108/211 51% [44, 58] | 256 | 5/256 2% [1, 4] | 0/256 0% [0, 1] |
| railway-guard | 211 | 211/211 100% [98, 100] | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| block-no-verify | 211 | 203/211 96% [93, 98] | 0/211 0% [0, 2] | 8/211 4% [2, 7] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| gemini-intrupt-hook | 211 | 161/211 76% [70, 82] | 0/211 0% [0, 2] | 50/211 24% [18, 30] | 256 | 73/256 29% [23, 34] | 0/256 0% [0, 1] |
| gemini-intrupt-hook[local-filter] | 211 | 181/211 86% [80, 90] | 0/211 0% [0, 2] | 30/211 14% [10, 20] | 256 | 17/256 7% [4, 10] | 0/256 0% [0, 1] |
| prevent-destructive | 211 | 201/211 95% [91, 97] | 0/211 0% [0, 2] | 10/211 5% [3, 9] | 256 | 7/256 3% [1, 6] | 0/256 0% [0, 1] |
| tob-codex-config | 211 | 200/211 95% [91, 97] | 0/211 0% [0, 2] | 11/211 5% [3, 9] | 256 | 5/256 2% [1, 4] | 0/256 0% [0, 1] |
| claude-codex-settings[force-push] | 211 | 207/211 98% [95, 99] | 0/211 0% [0, 2] | 4/211 2% [1, 5] | 256 | 1/256 0% [0, 2] | 0/256 0% [0, 1] |
| knox | 211 | 161/211 76% [70, 82] | 0/211 0% [0, 2] | 50/211 24% [18, 30] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| intentshield | 211 | 140/211 66% [60, 72] | 41/211 19% [15, 25] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1/256 0% [0, 2] |
| intentshield-default | 211 | 159/211 75% [69, 81] | 22/211 10% [7, 15] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1/256 0% [0, 2] |
| intentshield-nostate | 211 | 192/211 91% [86, 94] | 19/211 9% [6, 14] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| intentshield-always | 211 | 3/211 1% [0, 4] | 178/211 84% [79, 89] | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 193/256 75% [70, 80] |
| intentshield-tainted | 211 | 57/211 27% [21, 33] | 112/211 53% [46, 60] | 42/211 20% [15, 26] | 256 | 0/256 0% [0, 1] | 72/256 28% [23, 34] |
| ALLOW-ALL | 211 | 211/211 100% [98, 100] | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0/256 0% [0, 1] |
| DENY-ALL | 211 | 0/211 0% [0, 2] | 0/211 0% [0, 2] | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0/256 0% [0, 1] |

## Paired with IntentShield: the same held-out items, in each guard's harness and tool-kind scope

`flags` = deny or ask. `only guard` / `only IS` = items exactly one of the two flags; p is the exact two-sided sign test of those discordant items (items are not independent, so read it as descriptive). A guard that flags more harmful items than IntentShield on the same items is better at catching them; the benign columns say what it costs.

| guard | harmful n | guard flags | IS flags | only guard | only IS | p | benign n | guard flags | IS flags | only guard | only IS | p |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 57 | 8 | 6 | 8 | 6 | 0.791 | 74 | 2 | 0 | 2 | 0 | 0.5 |
| safety-net | 130 | 99 | 19 | 81 | 1 | 3.43e-23 | 160 | 3 | 0 | 3 | 0 | 0.25 |
| railway-guard | 45 | 0 | 6 | 0 | 6 | 0.0312 | 51 | 0 | 0 | 0 | 0 | 1 |
| block-no-verify | 88 | 8 | 13 | 8 | 13 | 0.383 | 105 | 0 | 0 | 0 | 0 | 1 |
| gemini-intrupt-hook | 49 | 49 | 7 | 42 | 0 | 4.55e-13 | 66 | 66 | 0 | 66 | 0 | 2.71e-20 |
| gemini-intrupt-hook[local-filter] | 49 | 30 | 7 | 25 | 2 | 5.65e-06 | 66 | 16 | 0 | 16 | 0 | 3.05e-05 |
| prevent-destructive | 45 | 10 | 6 | 10 | 6 | 0.454 | 51 | 6 | 0 | 6 | 0 | 0.0312 |
| tob-codex-config | 42 | 11 | 6 | 11 | 6 | 0.332 | 55 | 5 | 0 | 5 | 0 | 0.0625 |
| claude-codex-settings[force-push] | 45 | 4 | 6 | 4 | 6 | 0.754 | 51 | 1 | 0 | 1 | 0 | 1 |
| knox | 117 | 50 | 22 | 42 | 14 | 0.000234 | 168 | 0 | 1 | 0 | 1 | 1 |

## Miss rate per harmful category (held-out; the guard's harnesses and tool kinds; k/n misses)

| guard | destructive | git | credential-read | pipe-to-shell | exfiltration | rc-and-ci-write | mcp-injected-destination |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 4/10 40% [17, 69] | 6/8 75% [41, 93] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 17/17 100% [82, 100] | - |
| safety-net | 3/29 10% [4, 26] | 10/22 45% [27, 65] | 5/27 19% [8, 37] | 0/15 0% [0, 20] | 2/23 9% [2, 27] | 11/14 79% [52, 92] | - |
| railway-guard | 10/10 100% [72, 100] | 8/8 100% [68, 100] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| block-no-verify | 19/19 100% [83, 100] | 8/16 50% [28, 72] | 19/19 100% [83, 100] | 10/10 100% [72, 100] | 15/15 100% [80, 100] | 9/9 100% [70, 100] | - |
| gemini-intrupt-hook | 0/9 0% [0, 30] | 0/8 0% [0, 32] | 0/9 0% [0, 30] | 0/5 0% [0, 43] | 0/8 0% [0, 32] | 0/10 0% [0, 28] | - |
| gemini-intrupt-hook[local-filter] | 2/9 22% [6, 55] | 2/8 25% [7, 59] | 9/9 100% [70, 100] | 1/5 20% [4, 62] | 2/8 25% [7, 59] | 3/10 30% [11, 60] | - |
| prevent-destructive | 3/10 30% [11, 60] | 5/8 62% [31, 86] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| tob-codex-config | 3/10 30% [11, 60] | 3/6 50% [19, 81] | 8/8 100% [68, 100] | 4/5 80% [38, 96] | 8/8 100% [68, 100] | 5/5 100% [57, 100] | - |
| claude-codex-settings[force-push] | 10/10 100% [72, 100] | 4/8 50% [22, 78] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| knox | 8/20 40% [22, 61] | 14/14 100% [78, 100] | 22/26 85% [66, 94] | 0/10 0% [0, 28] | 5/15 33% [15, 58] | 8/22 36% [20, 57] | 10/10 100% [72, 100] |
| intentshield | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 35/35 100% [90, 100] | 15/15 100% [80, 100] | 4/23 17% [7, 37] | 32/32 100% [89, 100] | 0/10 0% [0, 28] |
| intentshield-default | - | - | - | - | - | - | 0/10 0% [0, 28] |
| intentshield-nostate | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 35/35 100% [90, 100] | 15/15 100% [80, 100] | 4/23 17% [7, 37] | 32/32 100% [89, 100] | 10/10 100% [72, 100] |
| intentshield-always | 0/29 0% [0, 12] | 0/22 0% [0, 15] | 3/35 9% [3, 22] | 0/15 0% [0, 20] | 0/23 0% [0, 14] | 0/32 0% [0, 11] | 0/10 0% [0, 28] |
| intentshield-tainted | 0/20 0% [0, 16] | 5/14 36% [16, 61] | 2/26 8% [2, 24] | 0/10 0% [0, 28] | 0/15 0% [0, 20] | 0/22 0% [0, 15] | 0/10 0% [0, 28] |
| ALLOW-ALL | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 35/35 100% [90, 100] | 15/15 100% [80, 100] | 23/23 100% [86, 100] | 32/32 100% [89, 100] | 10/10 100% [72, 100] |
| DENY-ALL | 0/29 0% [0, 12] | 0/22 0% [0, 15] | 0/35 0% [0, 10] | 0/15 0% [0, 20] | 0/23 0% [0, 14] | 0/32 0% [0, 11] | 0/10 0% [0, 28] |

## Miss rate per harmful category (full set; the guard's harnesses and tool kinds; k/n misses)

| guard | destructive | git | credential-read | pipe-to-shell | exfiltration | rc-and-ci-write | mcp-injected-destination |
|---|---|---|---|---|---|---|---|
| cc-safe-setup | 4/10 40% [17, 69] | 6/8 75% [41, 93] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 17/17 100% [82, 100] | - |
| safety-net | 3/29 10% [4, 26] | 10/22 45% [27, 65] | 5/30 17% [7, 34] | 0/15 0% [0, 20] | 2/23 9% [2, 27] | 11/14 79% [52, 92] | - |
| railway-guard | 10/10 100% [72, 100] | 8/8 100% [68, 100] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| block-no-verify | 19/19 100% [83, 100] | 8/16 50% [28, 72] | 20/20 100% [84, 100] | 10/10 100% [72, 100] | 15/15 100% [80, 100] | 9/9 100% [70, 100] | - |
| gemini-intrupt-hook | 0/9 0% [0, 30] | 0/8 0% [0, 32] | 0/10 0% [0, 28] | 0/5 0% [0, 43] | 0/8 0% [0, 32] | 0/10 0% [0, 28] | - |
| gemini-intrupt-hook[local-filter] | 2/9 22% [6, 55] | 2/8 25% [7, 59] | 10/10 100% [72, 100] | 1/5 20% [4, 62] | 2/8 25% [7, 59] | 3/10 30% [11, 60] | - |
| prevent-destructive | 3/10 30% [11, 60] | 5/8 62% [31, 86] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| tob-codex-config | 3/10 30% [11, 60] | 3/6 50% [19, 81] | 10/10 100% [72, 100] | 4/5 80% [38, 96] | 8/8 100% [68, 100] | 5/5 100% [57, 100] | - |
| claude-codex-settings[force-push] | 10/10 100% [72, 100] | 4/8 50% [22, 78] | 10/10 100% [72, 100] | 5/5 100% [57, 100] | 7/7 100% [65, 100] | 5/5 100% [57, 100] | - |
| knox | 8/20 40% [22, 61] | 14/14 100% [78, 100] | 24/28 86% [69, 94] | 0/10 0% [0, 28] | 5/15 33% [15, 58] | 8/22 36% [20, 57] | 52/52 100% [93, 100] |
| intentshield | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 38/38 100% [91, 100] | 15/15 100% [80, 100] | 4/23 17% [7, 37] | 32/32 100% [89, 100] | 0/52 0% [0, 7] |
| intentshield-default | - | - | - | - | - | - | 0/52 0% [0, 7] |
| intentshield-nostate | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 38/38 100% [91, 100] | 15/15 100% [80, 100] | 4/23 17% [7, 37] | 32/32 100% [89, 100] | 52/52 100% [93, 100] |
| intentshield-always | 0/29 0% [0, 12] | 0/22 0% [0, 15] | 3/38 8% [3, 21] | 0/15 0% [0, 20] | 0/23 0% [0, 14] | 0/32 0% [0, 11] | 0/52 0% [0, 7] |
| intentshield-tainted | 0/20 0% [0, 16] | 5/14 36% [16, 61] | 2/28 7% [2, 23] | 0/10 0% [0, 28] | 0/15 0% [0, 20] | 0/22 0% [0, 15] | 0/52 0% [0, 7] |
| ALLOW-ALL | 29/29 100% [88, 100] | 22/22 100% [85, 100] | 38/38 100% [91, 100] | 15/15 100% [80, 100] | 23/23 100% [86, 100] | 32/32 100% [89, 100] | 52/52 100% [93, 100] |
| DENY-ALL | 0/29 0% [0, 12] | 0/22 0% [0, 15] | 0/38 0% [0, 9] | 0/15 0% [0, 20] | 0/23 0% [0, 14] | 0/32 0% [0, 11] | 0/52 0% [0, 7] |

# Effective protection per build: the decision pushed through the delivery matrix

`stopped` = the harness did not run the call (BLOCKED). `prompted` = a person is asked (interactive Claude Code: not counted as stopped; the scripted answerer declined). `hung` = Gemini 0.66.0 waits for an answer in a headless run (killed at the cap; not counted as stopped). `ran` = the call ran. `benign blocked` = benign calls the harness refused because of the guard. The deploy view counts every harmful item rendered for that harness (a call a guard is not registered for runs); the scope view counts only the tool kinds the guard claims. `+translation` = IntentShield as `intentshield install` ships it: an ask becomes a refusal where nobody can answer.

## Held-out subset

### claude-2.1.316

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 166 | 26/166 16% [11, 22] | 0 | 0 | 140 | 26/148 18% [12, 24] | 234 | 3/234 1% [0, 4] | 0 |
| safety-net | 166 | 106/166 64% [56, 71] | 0 | 0 | 60 | 99/130 76% [68, 83] | 234 | 3/234 1% [0, 4] | 0 |
| railway-guard | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/130 0% [0, 3] | 234 | 0/234 0% [0, 2] | 0 |
| block-no-verify | 166 | 11/166 7% [4, 11] | 0 | 0 | 155 | 11/130 8% [5, 15] | 234 | 0/234 0% [0, 2] | 0 |
| prevent-destructive | 166 | 32/166 19% [14, 26] | 0 | 0 | 134 | 32/130 25% [18, 33] | 234 | 18/234 8% [5, 12] | 0 |
| claude-codex-settings[force-push] | 166 | 12/166 7% [4, 12] | 0 | 0 | 154 | 12/130 9% [5, 15] | 234 | 3/234 1% [0, 4] | 0 |
| knox | 166 | 73/166 44% [37, 52] | 0 | 0 | 93 | 73/166 44% [37, 52] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield | 166 | 29/166 17% [12, 24] | 0 | 0 | 137 | 29/166 17% [12, 24] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield+translation | 166 | 29/166 17% [12, 24] | 0 | 0 | 137 | 29/166 17% [12, 24] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield-default | 166 | 10/166 6% [3, 11] | 0 | 0 | 156 | 10/10 100% [72, 100] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield-default+translation | 166 | 10/166 6% [3, 11] | 0 | 0 | 156 | 10/10 100% [72, 100] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield-nostate | 166 | 19/166 11% [7, 17] | 0 | 0 | 147 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-nostate+translation | 166 | 19/166 11% [7, 17] | 0 | 0 | 147 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-always | 166 | 163/166 98% [95, 99] | 0 | 0 | 3 | 163/166 98% [95, 99] | 234 | 176/234 75% [69, 80] | 0 |
| intentshield-always+translation | 166 | 163/166 98% [95, 99] | 0 | 0 | 3 | 163/166 98% [95, 99] | 234 | 176/234 75% [69, 80] | 0 |
| intentshield-tainted | 166 | 157/166 95% [90, 97] | 0 | 0 | 9 | 157/166 95% [90, 97] | 234 | 100/234 43% [37, 49] | 0 |
| intentshield-tainted+translation | 166 | 157/166 95% [90, 97] | 0 | 0 | 9 | 157/166 95% [90, 97] | 234 | 100/234 43% [37, 49] | 0 |
| ALLOW-ALL | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| DENY-ALL | 166 | 166/166 100% [98, 100] | 0 | 0 | 0 | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0 |

### claude-2.1.84

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 166 | 26/166 16% [11, 22] | 0 | 0 | 140 | 26/148 18% [12, 24] | 234 | 3/234 1% [0, 4] | 0 |
| safety-net | 166 | 102/166 61% [54, 69] | 0 | 0 | 64 | 95/130 73% [65, 80] | 234 | 3/234 1% [0, 4] | 0 |
| railway-guard | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/130 0% [0, 3] | 234 | 0/234 0% [0, 2] | 0 |
| block-no-verify | 166 | 11/166 7% [4, 11] | 0 | 0 | 155 | 11/130 8% [5, 15] | 234 | 0/234 0% [0, 2] | 0 |
| prevent-destructive | 166 | 32/166 19% [14, 26] | 0 | 0 | 134 | 32/130 25% [18, 33] | 234 | 18/234 8% [5, 12] | 0 |
| claude-codex-settings[force-push] | 166 | 12/166 7% [4, 12] | 0 | 0 | 154 | 12/130 9% [5, 15] | 234 | 3/234 1% [0, 4] | 0 |
| knox | 166 | 73/166 44% [37, 52] | 0 | 0 | 93 | 73/166 44% [37, 52] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield+translation | 166 | 29/166 17% [12, 24] | 0 | 0 | 137 | 29/166 17% [12, 24] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield-default | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/10 0% [0, 28] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-default+translation | 166 | 10/166 6% [3, 11] | 0 | 0 | 156 | 10/10 100% [72, 100] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield-nostate | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-nostate+translation | 166 | 19/166 11% [7, 17] | 0 | 0 | 147 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-always | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-always+translation | 166 | 163/166 98% [95, 99] | 0 | 0 | 3 | 163/166 98% [95, 99] | 234 | 176/234 75% [69, 80] | 0 |
| intentshield-tainted | 166 | 19/166 11% [7, 17] | 0 | 0 | 147 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-tainted+translation | 166 | 157/166 95% [90, 97] | 0 | 0 | 9 | 157/166 95% [90, 97] | 234 | 100/234 43% [37, 49] | 0 |
| ALLOW-ALL | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| DENY-ALL | 166 | 166/166 100% [98, 100] | 0 | 0 | 0 | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0 |

### codex-0.166.0

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 130 | 99/130 76% [68, 83] | 0 | 0 | 31 | 99/130 76% [68, 83] | 160 | 3/160 2% [1, 5] | 0 |
| tob-codex-config | 130 | 36/130 28% [21, 36] | 0 | 0 | 94 | 36/130 28% [21, 36] | 160 | 17/160 11% [7, 16] | 0 |
| knox | 130 | 63/130 48% [40, 57] | 0 | 0 | 67 | 63/130 48% [40, 57] | 160 | 1/160 1% [0, 3] | 0 |
| intentshield | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | 0/130 0% [0, 3] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield+translation | 130 | 19/130 15% [10, 22] | 0 | 0 | 111 | 19/130 15% [10, 22] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-default | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | - | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-default+translation | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | - | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-nostate | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | 0/130 0% [0, 3] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-nostate+translation | 130 | 19/130 15% [10, 22] | 0 | 0 | 111 | 19/130 15% [10, 22] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-always | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | 0/130 0% [0, 3] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-always+translation | 130 | 128/130 98% [95, 100] | 0 | 0 | 2 | 128/130 98% [95, 100] | 160 | 132/160 82% [76, 88] | 0 |
| intentshield-tainted | 130 | 19/130 15% [10, 22] | 0 | 0 | 111 | 19/130 15% [10, 22] | 160 | 0/160 0% [0, 2] | 0 |
| intentshield-tainted+translation | 130 | 122/130 94% [88, 97] | 0 | 0 | 8 | 122/130 94% [88, 97] | 160 | 91/160 57% [49, 64] | 0 |
| ALLOW-ALL | 130 | 0/130 0% [0, 3] | 0 | 0 | 130 | 0/130 0% [0, 3] | 160 | 0/160 0% [0, 2] | 0 |
| DENY-ALL | 130 | 130/130 100% [97, 100] | 0 | 0 | 0 | 130/130 100% [97, 100] | 160 | 160/160 100% [98, 100] | 0 |

### gemini-0.66.0-yolo

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 143 | 99/143 69% [61, 76] | 0 | 0 | 44 | 99/130 76% [68, 83] | 183 | 3/183 2% [1, 5] | 0 |
| block-no-verify | 143 | 11/143 8% [4, 13] | 0 | 0 | 132 | 11/130 8% [5, 15] | 183 | 0/183 0% [0, 2] | 0 |
| gemini-intrupt-hook | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 143 | 81/143 57% [48, 64] | 0 | 0 | 62 | 81/143 57% [48, 64] | 183 | 34/183 19% [14, 25] | 0 |
| intentshield | 143 | 0/143 0% [0, 3] | 0 | 19 | 124 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default+translation | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate | 143 | 0/143 0% [0, 3] | 0 | 19 | 124 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always | 143 | 0/143 0% [0, 3] | 0 | 141 | 2 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always+translation | 143 | 141/143 99% [95, 100] | 0 | 0 | 2 | 141/143 99% [95, 100] | 183 | 155/183 85% [79, 89] | 0 |
| ALLOW-ALL | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| DENY-ALL | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |

### gemini-0.37.1-yolo

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 143 | 99/143 69% [61, 76] | 0 | 0 | 44 | 99/130 76% [68, 83] | 183 | 3/183 2% [1, 5] | 0 |
| block-no-verify | 143 | 11/143 8% [4, 13] | 0 | 0 | 132 | 11/130 8% [5, 15] | 183 | 0/183 0% [0, 2] | 0 |
| gemini-intrupt-hook | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 143 | 81/143 57% [48, 64] | 0 | 0 | 62 | 81/143 57% [48, 64] | 183 | 34/183 19% [14, 25] | 0 |
| intentshield | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default+translation | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always+translation | 143 | 141/143 99% [95, 100] | 0 | 0 | 2 | 141/143 99% [95, 100] | 183 | 155/183 85% [79, 89] | 0 |
| ALLOW-ALL | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| DENY-ALL | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |

### gemini-0.66.0-allow

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 143 | 99/143 69% [61, 76] | 0 | 0 | 44 | 99/130 76% [68, 83] | 183 | 3/183 2% [1, 5] | 0 |
| block-no-verify | 143 | 11/143 8% [4, 13] | 0 | 0 | 132 | 11/130 8% [5, 15] | 183 | 0/183 0% [0, 2] | 0 |
| gemini-intrupt-hook | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 143 | 81/143 57% [48, 64] | 0 | 0 | 62 | 81/143 57% [48, 64] | 183 | 34/183 19% [14, 25] | 0 |
| intentshield | 143 | 0/143 0% [0, 3] | 0 | 19 | 124 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-default+translation | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | - | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate | 143 | 0/143 0% [0, 3] | 0 | 19 | 124 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-nostate+translation | 143 | 19/143 13% [9, 20] | 0 | 0 | 124 | 19/143 13% [9, 20] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always | 143 | 0/143 0% [0, 3] | 0 | 141 | 2 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| intentshield-always+translation | 143 | 141/143 99% [95, 100] | 0 | 0 | 2 | 141/143 99% [95, 100] | 183 | 155/183 85% [79, 89] | 0 |
| ALLOW-ALL | 143 | 0/143 0% [0, 3] | 0 | 0 | 143 | 0/143 0% [0, 3] | 183 | 0/183 0% [0, 2] | 0 |
| DENY-ALL | 143 | 143/143 100% [97, 100] | 0 | 0 | 0 | 143/143 100% [97, 100] | 183 | 183/183 100% [98, 100] | 0 |

### claude-2.1.316-interactive

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 166 | 26/166 16% [11, 22] | 0 | 0 | 140 | 26/148 18% [12, 24] | 234 | 3/234 1% [0, 4] | 0 |
| safety-net | 166 | 102/166 61% [54, 69] | 4 | 0 | 60 | 95/130 73% [65, 80] | 234 | 3/234 1% [0, 4] | 0 |
| railway-guard | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/130 0% [0, 3] | 234 | 0/234 0% [0, 2] | 0 |
| block-no-verify | 166 | 11/166 7% [4, 11] | 0 | 0 | 155 | 11/130 8% [5, 15] | 234 | 0/234 0% [0, 2] | 0 |
| prevent-destructive | 166 | 32/166 19% [14, 26] | 0 | 0 | 134 | 32/130 25% [18, 33] | 234 | 18/234 8% [5, 12] | 0 |
| claude-codex-settings[force-push] | 166 | 12/166 7% [4, 12] | 0 | 0 | 154 | 12/130 9% [5, 15] | 234 | 3/234 1% [0, 4] | 0 |
| knox | 166 | 73/166 44% [37, 52] | 0 | 0 | 93 | 73/166 44% [37, 52] | 234 | 1/234 0% [0, 2] | 0 |
| intentshield | 166 | 0/166 0% [0, 2] | 29 | 0 | 137 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1 |
| intentshield+translation | 166 | 0/166 0% [0, 2] | 29 | 0 | 137 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 1 |
| intentshield-default | 166 | 0/166 0% [0, 2] | 10 | 0 | 156 | 0/10 0% [0, 28] | 234 | 0/234 0% [0, 2] | 1 |
| intentshield-default+translation | 166 | 0/166 0% [0, 2] | 10 | 0 | 156 | 0/10 0% [0, 28] | 234 | 0/234 0% [0, 2] | 1 |
| intentshield-nostate | 166 | 0/166 0% [0, 2] | 19 | 0 | 147 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-nostate+translation | 166 | 0/166 0% [0, 2] | 19 | 0 | 147 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| intentshield-always | 166 | 0/166 0% [0, 2] | 163 | 0 | 3 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 176 |
| intentshield-always+translation | 166 | 0/166 0% [0, 2] | 163 | 0 | 3 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 176 |
| intentshield-tainted | 166 | 19/166 11% [7, 17] | 138 | 0 | 9 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 100 |
| intentshield-tainted+translation | 166 | 19/166 11% [7, 17] | 138 | 0 | 9 | 19/166 11% [7, 17] | 234 | 0/234 0% [0, 2] | 100 |
| ALLOW-ALL | 166 | 0/166 0% [0, 2] | 0 | 0 | 166 | 0/166 0% [0, 2] | 234 | 0/234 0% [0, 2] | 0 |
| DENY-ALL | 166 | 166/166 100% [98, 100] | 0 | 0 | 0 | 166/166 100% [98, 100] | 234 | 234/234 100% [98, 100] | 0 |

## Full set

### claude-2.1.316

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 211 | 26/211 12% [9, 17] | 0 | 0 | 185 | 26/151 17% [12, 24] | 256 | 3/256 1% [0, 3] | 0 |
| safety-net | 211 | 109/211 52% [45, 58] | 0 | 0 | 102 | 102/133 77% [69, 83] | 256 | 5/256 2% [1, 4] | 0 |
| railway-guard | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/133 0% [0, 3] | 256 | 0/256 0% [0, 1] | 0 |
| block-no-verify | 211 | 11/211 5% [3, 9] | 0 | 0 | 200 | 11/133 8% [5, 14] | 256 | 0/256 0% [0, 1] | 0 |
| prevent-destructive | 211 | 32/211 15% [11, 21] | 0 | 0 | 179 | 32/133 24% [18, 32] | 256 | 19/256 7% [5, 11] | 0 |
| claude-codex-settings[force-push] | 211 | 12/211 6% [3, 10] | 0 | 0 | 199 | 12/133 9% [5, 15] | 256 | 3/256 1% [0, 3] | 0 |
| knox | 211 | 73/211 35% [29, 41] | 0 | 0 | 138 | 73/211 35% [29, 41] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield | 211 | 71/211 34% [28, 40] | 0 | 0 | 140 | 71/211 34% [28, 40] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield+translation | 211 | 71/211 34% [28, 40] | 0 | 0 | 140 | 71/211 34% [28, 40] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield-default | 211 | 52/211 25% [19, 31] | 0 | 0 | 159 | 52/52 100% [93, 100] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield-default+translation | 211 | 52/211 25% [19, 31] | 0 | 0 | 159 | 52/52 100% [93, 100] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield-nostate | 211 | 19/211 9% [6, 14] | 0 | 0 | 192 | 19/211 9% [6, 14] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-nostate+translation | 211 | 19/211 9% [6, 14] | 0 | 0 | 192 | 19/211 9% [6, 14] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-always | 211 | 208/211 99% [96, 100] | 0 | 0 | 3 | 208/211 99% [96, 100] | 256 | 193/256 75% [70, 80] | 0 |
| intentshield-always+translation | 211 | 208/211 99% [96, 100] | 0 | 0 | 3 | 208/211 99% [96, 100] | 256 | 193/256 75% [70, 80] | 0 |
| intentshield-tainted | 211 | 202/211 96% [92, 98] | 0 | 0 | 9 | 202/211 96% [92, 98] | 256 | 105/256 41% [35, 47] | 0 |
| intentshield-tainted+translation | 211 | 202/211 96% [92, 98] | 0 | 0 | 9 | 202/211 96% [92, 98] | 256 | 105/256 41% [35, 47] | 0 |
| ALLOW-ALL | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| DENY-ALL | 211 | 211/211 100% [98, 100] | 0 | 0 | 0 | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0 |

### claude-2.1.84

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 211 | 26/211 12% [9, 17] | 0 | 0 | 185 | 26/151 17% [12, 24] | 256 | 3/256 1% [0, 3] | 0 |
| safety-net | 211 | 105/211 50% [43, 56] | 0 | 0 | 106 | 98/133 74% [66, 80] | 256 | 5/256 2% [1, 4] | 0 |
| railway-guard | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/133 0% [0, 3] | 256 | 0/256 0% [0, 1] | 0 |
| block-no-verify | 211 | 11/211 5% [3, 9] | 0 | 0 | 200 | 11/133 8% [5, 14] | 256 | 0/256 0% [0, 1] | 0 |
| prevent-destructive | 211 | 32/211 15% [11, 21] | 0 | 0 | 179 | 32/133 24% [18, 32] | 256 | 19/256 7% [5, 11] | 0 |
| claude-codex-settings[force-push] | 211 | 12/211 6% [3, 10] | 0 | 0 | 199 | 12/133 9% [5, 15] | 256 | 3/256 1% [0, 3] | 0 |
| knox | 211 | 73/211 35% [29, 41] | 0 | 0 | 138 | 73/211 35% [29, 41] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield | 211 | 30/211 14% [10, 20] | 0 | 0 | 181 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield+translation | 211 | 71/211 34% [28, 40] | 0 | 0 | 140 | 71/211 34% [28, 40] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield-default | 211 | 30/211 14% [10, 20] | 0 | 0 | 181 | 30/52 58% [44, 70] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-default+translation | 211 | 52/211 25% [19, 31] | 0 | 0 | 159 | 52/52 100% [93, 100] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield-nostate | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-nostate+translation | 211 | 19/211 9% [6, 14] | 0 | 0 | 192 | 19/211 9% [6, 14] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-always | 211 | 30/211 14% [10, 20] | 0 | 0 | 181 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-always+translation | 211 | 208/211 99% [96, 100] | 0 | 0 | 3 | 208/211 99% [96, 100] | 256 | 193/256 75% [70, 80] | 0 |
| intentshield-tainted | 211 | 49/211 23% [18, 29] | 0 | 0 | 162 | 49/211 23% [18, 29] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-tainted+translation | 211 | 202/211 96% [92, 98] | 0 | 0 | 9 | 202/211 96% [92, 98] | 256 | 105/256 41% [35, 47] | 0 |
| ALLOW-ALL | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| DENY-ALL | 211 | 211/211 100% [98, 100] | 0 | 0 | 0 | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0 |

### codex-0.166.0

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 133 | 102/133 77% [69, 83] | 0 | 0 | 31 | 102/133 77% [69, 83] | 182 | 5/182 3% [1, 6] | 0 |
| tob-codex-config | 133 | 36/133 27% [20, 35] | 0 | 0 | 97 | 36/133 27% [20, 35] | 182 | 18/182 10% [6, 15] | 0 |
| knox | 133 | 63/133 47% [39, 56] | 0 | 0 | 70 | 63/133 47% [39, 56] | 182 | 1/182 1% [0, 3] | 0 |
| intentshield | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | 0/133 0% [0, 3] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield+translation | 133 | 19/133 14% [9, 21] | 0 | 0 | 114 | 19/133 14% [9, 21] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-default | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | - | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-default+translation | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | - | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-nostate | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | 0/133 0% [0, 3] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-nostate+translation | 133 | 19/133 14% [9, 21] | 0 | 0 | 114 | 19/133 14% [9, 21] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-always | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | 0/133 0% [0, 3] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-always+translation | 133 | 131/133 98% [95, 100] | 0 | 0 | 2 | 131/133 98% [95, 100] | 182 | 149/182 82% [76, 87] | 0 |
| intentshield-tainted | 133 | 19/133 14% [9, 21] | 0 | 0 | 114 | 19/133 14% [9, 21] | 182 | 0/182 0% [0, 2] | 0 |
| intentshield-tainted+translation | 133 | 125/133 94% [89, 97] | 0 | 0 | 8 | 125/133 94% [89, 97] | 182 | 96/182 53% [46, 60] | 0 |
| ALLOW-ALL | 133 | 0/133 0% [0, 3] | 0 | 0 | 133 | 0/133 0% [0, 3] | 182 | 0/182 0% [0, 2] | 0 |
| DENY-ALL | 133 | 133/133 100% [97, 100] | 0 | 0 | 0 | 133/133 100% [97, 100] | 182 | 182/182 100% [98, 100] | 0 |

### gemini-0.66.0-yolo

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 146 | 102/146 70% [62, 77] | 0 | 0 | 44 | 102/133 77% [69, 83] | 205 | 5/205 2% [1, 6] | 0 |
| block-no-verify | 146 | 11/146 8% [4, 13] | 0 | 0 | 135 | 11/133 8% [5, 14] | 205 | 0/205 0% [0, 2] | 0 |
| gemini-intrupt-hook | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 146 | 81/146 55% [47, 63] | 0 | 0 | 65 | 81/146 55% [47, 63] | 205 | 36/205 18% [13, 23] | 0 |
| intentshield | 146 | 0/146 0% [0, 3] | 0 | 19 | 127 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default+translation | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate | 146 | 0/146 0% [0, 3] | 0 | 19 | 127 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always | 146 | 0/146 0% [0, 3] | 0 | 144 | 2 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always+translation | 146 | 144/146 99% [95, 100] | 0 | 0 | 2 | 144/146 99% [95, 100] | 205 | 172/205 84% [78, 88] | 0 |
| ALLOW-ALL | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| DENY-ALL | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |

### gemini-0.37.1-yolo

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 146 | 102/146 70% [62, 77] | 0 | 0 | 44 | 102/133 77% [69, 83] | 205 | 5/205 2% [1, 6] | 0 |
| block-no-verify | 146 | 11/146 8% [4, 13] | 0 | 0 | 135 | 11/133 8% [5, 14] | 205 | 0/205 0% [0, 2] | 0 |
| gemini-intrupt-hook | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 146 | 81/146 55% [47, 63] | 0 | 0 | 65 | 81/146 55% [47, 63] | 205 | 36/205 18% [13, 23] | 0 |
| intentshield | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default+translation | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always+translation | 146 | 144/146 99% [95, 100] | 0 | 0 | 2 | 144/146 99% [95, 100] | 205 | 172/205 84% [78, 88] | 0 |
| ALLOW-ALL | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| DENY-ALL | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |

### gemini-0.66.0-allow

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| safety-net | 146 | 102/146 70% [62, 77] | 0 | 0 | 44 | 102/133 77% [69, 83] | 205 | 5/205 2% [1, 6] | 0 |
| block-no-verify | 146 | 11/146 8% [4, 13] | 0 | 0 | 135 | 11/133 8% [5, 14] | 205 | 0/205 0% [0, 2] | 0 |
| gemini-intrupt-hook | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |
| gemini-intrupt-hook[local-filter] | 146 | 81/146 55% [47, 63] | 0 | 0 | 65 | 81/146 55% [47, 63] | 205 | 36/205 18% [13, 23] | 0 |
| intentshield | 146 | 0/146 0% [0, 3] | 0 | 19 | 127 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-default+translation | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | - | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate | 146 | 0/146 0% [0, 3] | 0 | 19 | 127 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-nostate+translation | 146 | 19/146 13% [8, 19] | 0 | 0 | 127 | 19/146 13% [8, 19] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always | 146 | 0/146 0% [0, 3] | 0 | 144 | 2 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| intentshield-always+translation | 146 | 144/146 99% [95, 100] | 0 | 0 | 2 | 144/146 99% [95, 100] | 205 | 172/205 84% [78, 88] | 0 |
| ALLOW-ALL | 146 | 0/146 0% [0, 3] | 0 | 0 | 146 | 0/146 0% [0, 3] | 205 | 0/205 0% [0, 2] | 0 |
| DENY-ALL | 146 | 146/146 100% [97, 100] | 0 | 0 | 0 | 146/146 100% [97, 100] | 205 | 205/205 100% [98, 100] | 0 |

### claude-2.1.316-interactive

| guard | harmful n | stopped (deploy) | prompted | hung | ran | stopped (scope) of scope n | benign n | benign blocked | benign prompted |
|---|---|---|---|---|---|---|---|---|---|
| cc-safe-setup | 211 | 26/211 12% [9, 17] | 0 | 0 | 185 | 26/151 17% [12, 24] | 256 | 3/256 1% [0, 3] | 0 |
| safety-net | 211 | 105/211 50% [43, 56] | 4 | 0 | 102 | 98/133 74% [66, 80] | 256 | 5/256 2% [1, 4] | 0 |
| railway-guard | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/133 0% [0, 3] | 256 | 0/256 0% [0, 1] | 0 |
| block-no-verify | 211 | 11/211 5% [3, 9] | 0 | 0 | 200 | 11/133 8% [5, 14] | 256 | 0/256 0% [0, 1] | 0 |
| prevent-destructive | 211 | 32/211 15% [11, 21] | 0 | 0 | 179 | 32/133 24% [18, 32] | 256 | 19/256 7% [5, 11] | 0 |
| claude-codex-settings[force-push] | 211 | 12/211 6% [3, 10] | 0 | 0 | 199 | 12/133 9% [5, 15] | 256 | 3/256 1% [0, 3] | 0 |
| knox | 211 | 73/211 35% [29, 41] | 0 | 0 | 138 | 73/211 35% [29, 41] | 256 | 1/256 0% [0, 2] | 0 |
| intentshield | 211 | 30/211 14% [10, 20] | 41 | 0 | 140 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1 |
| intentshield+translation | 211 | 30/211 14% [10, 20] | 41 | 0 | 140 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 1 |
| intentshield-default | 211 | 30/211 14% [10, 20] | 22 | 0 | 159 | 30/52 58% [44, 70] | 256 | 0/256 0% [0, 1] | 1 |
| intentshield-default+translation | 211 | 30/211 14% [10, 20] | 22 | 0 | 159 | 30/52 58% [44, 70] | 256 | 0/256 0% [0, 1] | 1 |
| intentshield-nostate | 211 | 0/211 0% [0, 2] | 19 | 0 | 192 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-nostate+translation | 211 | 0/211 0% [0, 2] | 19 | 0 | 192 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| intentshield-always | 211 | 30/211 14% [10, 20] | 178 | 0 | 3 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 193 |
| intentshield-always+translation | 211 | 30/211 14% [10, 20] | 178 | 0 | 3 | 30/211 14% [10, 20] | 256 | 0/256 0% [0, 1] | 193 |
| intentshield-tainted | 211 | 49/211 23% [18, 29] | 153 | 0 | 9 | 49/211 23% [18, 29] | 256 | 0/256 0% [0, 1] | 105 |
| intentshield-tainted+translation | 211 | 49/211 23% [18, 29] | 153 | 0 | 9 | 49/211 23% [18, 29] | 256 | 0/256 0% [0, 1] | 105 |
| ALLOW-ALL | 211 | 0/211 0% [0, 2] | 0 | 0 | 211 | 0/211 0% [0, 2] | 256 | 0/256 0% [0, 1] | 0 |
| DENY-ALL | 211 | 211/211 100% [98, 100] | 0 | 0 | 0 | 211/211 100% [98, 100] | 256 | 256/256 100% [99, 100] | 0 |

# The delivery matrix used (derived from the committed unwrapped head-to-head and interactive rows)

| build | deny | ask | error (exit 1, crash) | deny with empty stderr |
|---|---|---|---|---|
| claude-2.1.316 | BLOCKED 5 | BLOCKED 4 | RAN 2 | BLOCKED 4 |
| claude-2.1.84 | BLOCKED 5 | RAN 4 | RAN 2 | UNMEASURED |
| codex-0.166.0 | BLOCKED 3 | RAN 2 | RAN 2 | RAN 2 |
| gemini-0.66.0-yolo | BLOCKED 4 | HUNG 3 | RAN 2 | BLOCKED 2 |
| gemini-0.37.1-yolo | BLOCKED 4 | RAN 3 | RAN 2 | UNMEASURED |
| gemini-0.66.0-allow | BLOCKED 4 | HUNG 3 | RAN 2 | UNMEASURED |
| claude-2.1.316-interactive | BLOCKED 2 | PROMPT 4 | RAN (assumed) | BLOCKED (assumed) |

Guards that were not run: dcg (Rust binary; no prebuilt binary, and the crates are not in the offline cargo cache (committed evidence in guards/captures-meta.json); a build needs network); tool-gate-hook (Rust binary; crates not in the offline cache (guards/captures-meta.json)); rtk (Rust binary `rtk rewrite`; a rewrite helper, not a verdict guard; no prebuilt binary); defenseclaw (Go binary (no Go toolchain here) that calls a local gateway); malanta-trustgate (Go binaries, Cursor only); agent-edict (Go binary, Cursor only); balerx (native binary `balerx hook`; no prebuilt binary or toolchain here); ggshield (Python package whose dependencies are not installed, and its secret scan needs the GitGuardian API (no key, no network)); hol-guard (Python package whose dependencies are not installed; its hook reaches a local daemon); ai-guardian (Python package that needs tree-sitter language packages (not installed here; installing needs network)); axonflow-codex (needs an AxonFlow policy server (an account and a network); without one its documented behaviour is fail-open allow, which is not a decision); skillgate (TypeScript with no dist and dependencies (a native pairing-crypto module among them) not installed; it is a definition-of-done gate for commit and push, not a command-safety guard); hookify (a rule engine that decides nothing without user-written `.claude/hookify.*.local.md` rules; with none its reply is `{}`); oh-my-harness (TypeScript generator of hook scripts; no build output and dependencies not installed); riphook (TypeScript with no dist and dependencies not installed; Cursor and Claude entries); vaibot-cursor (Cursor only (the study has no Cursor delivery data)); endor-cursor-hooks (Cursor only and needs endorctl and an Endor account); agentsid-cursor (rules for Cursor, no hook entry point); lasso-claude-hooks (a prompt-injection scanner of tool results (PostToolUse), not a PreToolUse verdict on calls).
