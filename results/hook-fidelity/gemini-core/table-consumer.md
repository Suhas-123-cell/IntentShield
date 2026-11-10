## Consumer side: the Scheduler, the policy engine and the tools

| scenario | `0.36.0` | `0.37.1` | `0.38.2 .. 0.67.0-preview.0` |
|---|---|---|---|
| direct|shell|default | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: prompt:exec |
| direct|mcp|default|trust=false | no-forced: prompt:mcp; ask_user: prompt:mcp | no-forced: prompt:mcp; ask_user: prompt:mcp | no-forced: prompt:mcp; ask_user: prompt:mcp |
| direct|mcp|default|trust=true | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt |
| direct|mcp|default|trust=false|session-allowlist | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt |
| direct|mcp|default|trust=true|folderTrust-on|folder-untrusted | no-forced: prompt:mcp; ask_user: prompt:mcp | no-forced: prompt:mcp; ask_user: prompt:mcp | no-forced: prompt:mcp; ask_user: prompt:mcp |
| direct|shell|yolo | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: prompt:exec |
| direct|mcp|yolo|trust=false | no-forced: no-prompt; ask_user: prompt:mcp | no-forced: no-prompt; ask_user: prompt:mcp | no-forced: no-prompt; ask_user: prompt:mcp |
| direct|mcp|yolo|trust=true | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt |
| direct|mcp|yolo|trust=false|session-allowlist | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt | no-forced: no-prompt; ask_user: no-prompt |
| direct|mcp|yolo|trust=true|folderTrust-on|folder-untrusted | no-forced: no-prompt; ask_user: prompt:mcp | no-forced: no-prompt; ask_user: prompt:mcp | no-forced: no-prompt; ask_user: prompt:mcp |
| shell|default|interactive|hook=none | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| shell|default|interactive|hook=allow | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| shell|default|interactive|hook=ask | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| shell|default|interactive|hook=deny | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| shell|default|headless|hook=none | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| shell|default|headless|hook=allow | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| shell|default|headless|hook=ask | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| shell|default|headless|hook=deny | ERROR:hook-deny | ERROR:tool-not-offered | ERROR:tool-not-offered |
| shell|yolo|interactive|hook=none | RAN | RAN | RAN |
| shell|yolo|interactive|hook=allow | RAN | RAN | RAN |
| shell|yolo|interactive|hook=ask | RAN | RAN | PROMPT-WAIT |
| shell|yolo|interactive|hook=deny | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| shell|yolo|headless|hook=none | RAN | RAN | RAN |
| shell|yolo|headless|hook=allow | RAN | RAN | RAN |
| shell|yolo|headless|hook=ask | RAN | RAN | PROMPT-WAIT |
| shell|yolo|headless|hook=deny | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|default|interactive|hook=none|trust=false | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|default|interactive|hook=none|trust=true | RAN | RAN | RAN |
| mcp|default|interactive|hook=allow|trust=false | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|default|interactive|hook=allow|trust=true | RAN | RAN | RAN |
| mcp|default|interactive|hook=ask|trust=false | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|default|interactive|hook=ask|trust=true | RAN | RAN | RAN |
| mcp|default|interactive|hook=deny|trust=false | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|default|interactive|hook=deny|trust=true | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|default|headless|hook=none|trust=false | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| mcp|default|headless|hook=none|trust=true | RAN | RAN | RAN |
| mcp|default|headless|hook=allow|trust=false | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| mcp|default|headless|hook=allow|trust=true | RAN | RAN | RAN |
| mcp|default|headless|hook=ask|trust=false | ERROR:noninteractive-ask | ERROR:tool-not-offered | ERROR:tool-not-offered |
| mcp|default|headless|hook=ask|trust=true | RAN | RAN | RAN |
| mcp|default|headless|hook=deny|trust=false | ERROR:hook-deny | ERROR:tool-not-offered | ERROR:tool-not-offered |
| mcp|default|headless|hook=deny|trust=true | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|yolo|interactive|hook=none|trust=false | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=none|trust=true | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=allow|trust=false | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=allow|trust=true | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=ask|trust=false | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|yolo|interactive|hook=ask|trust=true | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=deny|trust=false | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|yolo|interactive|hook=deny|trust=true | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|yolo|headless|hook=none|trust=false | RAN | RAN | RAN |
| mcp|yolo|headless|hook=none|trust=true | RAN | RAN | RAN |
| mcp|yolo|headless|hook=allow|trust=false | RAN | RAN | RAN |
| mcp|yolo|headless|hook=allow|trust=true | RAN | RAN | RAN |
| mcp|yolo|headless|hook=ask|trust=false | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|yolo|headless|hook=ask|trust=true | RAN | RAN | RAN |
| mcp|yolo|headless|hook=deny|trust=false | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|yolo|headless|hook=deny|trust=true | ERROR:hook-deny | ERROR:hook-deny | ERROR:hook-deny |
| mcp|default|headless|hook=ask|mcp.allowed | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|default|interactive|hook=ask|mcp.allowed | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|yolo|headless|hook=ask|trust=true|folderTrust-on|folder-untrusted | RAN | RAN | RAN |
| mcp|yolo|headless|hook=ask|trust=true|folderTrust-on|folder-trusted | RAN | RAN | RAN |
| mcp|yolo|interactive|hook=ask|trust=false|session-allowlist | RAN | RAN | RAN |
| mcp|default|interactive|hook=ask|trust=false|session-allowlist | RAN | RAN | RAN |
| shell|yolo|interactive|hook=ask|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | PROMPT-WAIT |
| shell|yolo|headless|hook=ask|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | PROMPT-WAIT |
| shell|default|headless|hook=ask|tools.exclude | ERROR:tool-not-offered | ERROR:tool-not-offered | ERROR:tool-not-offered |
| shell|yolo|headless|hook=none|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | ERROR:policy-deny |
| shell|yolo|headless|hook=allow|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | ERROR:policy-deny |
| mcp|yolo|headless|hook=ask|policy-deny-rule | PROMPT-WAIT | PROMPT-WAIT | PROMPT-WAIT |
| mcp|yolo|headless|hook=none|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | ERROR:policy-deny |
| mcp|yolo|headless|hook=allow|policy-deny-rule | ERROR:policy-deny | ERROR:policy-deny | ERROR:policy-deny |

Version groups: [0.36.0] = 0.36.0; [0.37.1] = 0.37.1; [0.38.2 .. 0.67.0-preview.0] = 0.38.2, 0.40.1, 0.45.3, 0.50.0, 0.55.1, 0.60.0, 0.66.0, 0.67.0-nightly.20261031.g6814e00d6, 0.67.0-preview.0

RAN = the marker was written. PROMPT-WAIT = the call reached awaiting_approval and nothing answered within the bounded wait (a TUI user would see a prompt; the CLI end-to-end runs show what a headless run does). ERROR:* = the scheduler ended the call with that error (tool-not-offered: the registry did not hold the tool). `direct|...` rows call the invocation's own shouldConfirmExecute with and without forcedDecision 'ask_user'. Boundaries are between the SAMPLED releases named.
