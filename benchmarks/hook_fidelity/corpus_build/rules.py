# Prediction rules derived ONLY from wf1/vendor-semantics.md (docs + Codex/Gemini source). Nothing here was run.
RULES = {
 # Claude Code (closed source; docs only)
 "CC-FAILOPEN": ("claude", "Empty stdout, malformed JSON, exit 1/3/126/127/other non-zero (except 2), missing or non-executable script, crash and timeout are all non-blocking: the tool call proceeds. `onFailure: block` (v2.1.295+) makes a failure act like exit 2; it is off by default.", "DOC (hooks page)"),
 "CC-EXIT2": ("claude", "Exit 2 blocks the call with stderr as the reason, before permission rules are evaluated.", "DOC"),
 "CC-ASK-HEADLESS": ("claude", "`ask` under `claude -p` (no human) is not documented. Closest text: calls needing approval are denied unless approved by a rule, hook, canUseTool or --permission-prompt-tool. Inferred deny, not established.", "UNVERIFIED (inferred)"),
 "CC-ASK-BYPASS": ("claude", "`ask` under bypassPermissions / auto / dontAsk is not documented (bypass skips prompts except actions no mode auto-approves; the list names explicit ask rules, not hook asks). Public issue reports disagree by version.", "UNVERIFIED"),
 "CC-ALLOW-SCOPE": ("claude", "Hook `allow` skips the prompt but deny/ask rules still apply, plus exceptions (network-path reads, requiresUserInteraction MCP tools, AskUserQuestion, critical-path rm, explicit ask rules).", "DOC"),
 "CC-P-TRUST": ("claude", "`-p` / SDK never shows the workspace-trust dialog and treats the folder as trusted, so repo hooks run in a never-trusted folder.", "DOC"),
 "CC-MCP-RES": ("claude", "ReadMcpResourceTool and ListMcpResourcesTool are built-in tools with built-in names; an `mcp__` matcher or `^mcp__` self-filter does not match them. No doc says so outright.", "DOC for ingredients; conclusion is an inference"),
 "CC-LEGACY-DECISION": ("claude", "A top-level legacy `{decision: block}` on PreToolUse is not covered by the collected docs; two public issues say wrong-shape output is silently ignored.", "UNVERIFIED"),
 # Codex CLI (docs + source)
 "CX-BLOCK-OK": ("codex", "Blocking works for (a) PreToolUse JSON deny / decision:block with a non-empty reason and (b) exit 2 with non-empty stderr.", "DOC + SRC (pre_tool_use.rs:248-255, 277-283)"),
 "CX-ASK": ("codex", "PreToolUse `ask` is parsed but unsupported: the hook run is marked Failed and the tool call CONTINUES.", "DOC + SRC (output_parser.rs:458-460)"),
 "CX-ALLOW": ("codex", "`allow` without `updatedInput` is unsupported: hook Failed, call continues (same net effect as allow, plus an error).", "SRC (output_parser.rs:453-457)"),
 "CX-DENY-EMPTY": ("codex", "`deny` with an empty reason is invalid: hook Failed, call continues.", "SRC (output_parser.rs:461-470)"),
 "CX-EXIT2-EMPTY": ("codex", "Exit 2 with EMPTY stderr: hook Failed (\"did not write a blocking reason\"), call continues.", "SRC only (pre_tool_use.rs:277-283)"),
 "CX-EXIT-OTHER": ("codex", "Exit 1, 126, 127, any other non-zero code, spawn error or no status code: hook Failed, call continues.", "SRC; docs say only that a failure can fail the hook without blocking"),
 "CX-TIMEOUT": ("codex", "Timeout (default 600 s): hook Failed, call continues.", "DOC (default) + SRC (command_runner.rs:333-377)"),
 "CX-UNSUPPORTED-FIELDS": ("codex", "`continue:false`, `stopReason`, `suppressOutput` are unsupported: hook Failed, call continues.", "DOC + SRC"),
 "CX-MALFORMED": ("codex", "Output that looks like JSON but does not parse: hook Failed, call continues.", "SRC (pre_tool_use.rs:260-266)"),
 "CX-TRUST": ("codex", "Non-managed hooks must be reviewed/trusted; untrusted hooks are not registered (skipped). The startup warning found in source is TUI-only; a headless warning is UNVERIFIED.", "DOC + SRC (discovery.rs:917-927)"),
 "CX-COVERAGE": ("codex", "PreToolUse covers Bash, apply_patch and MCP calls only; hosted tools (WebSearch) and some specialised paths do not use it. Docs: a useful guardrail, not a complete enforcement boundary. A public report says no hook fires for unified_exec/command_execution on some Desktop builds (not verified here).", "DOC"),
 # Cursor (closed source; docs + forum)
 "CU-ASK-MCP": ("cursor", "`ask` for beforeMCPExecution is in the schema but reported not enforced when the MCP tool is allowlisted/approved: it ran 3/3 in an earlier live Cursor CLI run (not part of this task), matching IDE forum reports and one guard's source reading of the Cursor 3.24.18 executor.", "FORUM + earlier measurement elsewhere; docs silent"),
 "CU-ASK-PRETOOLUSE": ("cursor", "`ask` on preToolUse is accepted by the schema but not enforced.", "DOC"),
 "CU-ASK-SHELL": ("cursor", "`ask` on beforeShellExecution was held in the earlier CLI run even when allowlisted; one Nov 2025 IDE forum report says an allowlisted shell ask auto-runs.", "DOC (schema only) + FORUM; earlier measurement elsewhere"),
 "CU-FAILCLOSED": ("cursor", "Crash, timeout, non-zero exit other than 2, and empty output fail OPEN unless the hook sets `failClosed: true`. Invalid JSON or a schema mismatch on a permission hook blocks regardless of failClosed.", "DOC"),
 "CU-MISSING": ("cursor", "Missing hook script / missing interpreter / exit 126 is not documented. Guess: it is the same as a non-zero exit (fails open without failClosed).", "UNVERIFIED"),
 "CU-ALLOW": ("cursor", "A hook `allow` does not override Cursor's own approval/allowlist (forum, IDE).", "FORUM"),
 "CU-IMPORT": ("cursor", "Claude-plugin hooks imported by Cursor are reported to run with failClosed:false, and bash/jq hooks that print nothing on allow count as hook failures.", "UNVERIFIED (blog/forum)"),
 # Gemini CLI (docs + source)
 "GM-DENY-OK": ("gemini", "`decision: deny|block` on stdout (exit 0) blocks in every approval mode including yolo.", "DOC + SRC (scheduler.ts:654-665)"),
 "GM-ASK": ("gemini", "BeforeTool `ask` is undocumented. 0.66.0 headless yolo: no non-interactive branch, waits indefinitely. 0.37.1 shell tool drops the forced ask (runs). MCP tool on a trusted server or allowlisted: ask silently approved (source prediction, never run).", "SRC; DOC absent"),
 "GM-EXIT2-EMPTY": ("gemini", "Exit 2 with NO stdout and NO stderr: no output, so the call is ALLOWED (docs say exit 2 blocks). Exit 2 with JSON stdout: the JSON decides.", "SRC contradicts docs"),
 "GM-EXIT-TEXT": ("gemini", "Exit 126/127/3+ with text on stderr or stdout becomes a DENY (stderr is the reason); with empty output the call is allowed. Docs say \"Other: warning, continue\".", "SRC contradicts docs; not run"),
 "GM-TIMEOUT": ("gemini", "Timeout (default 60 s) or spawn error: success:false, no output, call ALLOWED.", "DOC (default) + SRC (hookRunner.ts:369-399, 434-448)"),
 "GM-PLAINTEXT": ("gemini", "Plain-text stdout with exit 0 becomes allow plus a systemMessage; malformed JSON is treated as plain text (exit 1 allows with a warning).", "DOC + SRC"),
}
