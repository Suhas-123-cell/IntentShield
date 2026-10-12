# Channel coverage: what a hook-scoped MCP guard sees, and what a proxy sees

Experiment run 2026-10-12 with `benchmarks/coverage/run.py` (probe server plus a passive
logging hook, four benign prompts, headless Claude Code and Gemini CLI). Raw logs in
`artifacts/coverage/<harness>-<mode>/` (gitignored).

**Status of the data.** The stored artifacts came from the first version of the instrumentation,
which had five problems (listed under "Instrumentation fixes"). Every cell below was re-scored
by hand from the stored `hooks.jsonl`, `probe.jsonl` and answer files, not read from the stored
`summary.json`, whose "hook events carrying it" lists mix input delivery with the model's own
output. **A re-run with the fixed instrumentation is pending**; until it exists, treat the table
as a careful reading of one contaminated run, not a clean measurement.

**Scope.** n = 1 run per cell, one model per harness (Claude Haiku; Gemini 3.1 Flash-Lite as the
main model), benign markers, nothing blocks: this measures visibility only. The Gemini "tools"
prompt in both modes also started a `gemini-3-flash-preview` sub-agent (`codebase_investigator`),
so some Gemini hook events come from that sub-agent. No real attack was run.

## The question

Third-party MCP guards commonly install as a **harness hook** scoped to MCP tool calls (a
`mcp__.*` matcher in Claude Code, the tool hooks in Gemini CLI); no vendor product was tested
here. The other placement is a **transparent proxy** in front of the server. MCP carries
attacker-controllable text on five channels: tool descriptions, tool results, resource contents,
prompt contents, and server-initiated sampling/elicitation. Which of them reach each placement?

## Method

A benign probe server puts one unique marker in each channel and logs every protocol request with
the client's declared capabilities. A passive hook, registered on every relevant event with a
`*` matcher on tool events, logs which event carried each marker and under which tool name. For
each marker we record whether it reached the model's context, and then separate two things the
first version mixed:

- **delivered by**: events that hand the marker to the model. These are tool-result events
  (`PostToolUse`, `AfterTool`) for the probe's MCP tools or the harness's MCP resource tools,
  prompt events (`UserPromptSubmit`, `UserPromptExpansion`, `BeforeAgent`), and the first
  model-request event (`BeforeModel`, `BeforeToolSelection`) when no echo came earlier.
- **echoed in**: events carrying the model's own output or arguments (`Stop`, `AfterModel`,
  `AfterAgent`, `PreToolUse`, `BeforeTool`), output of non-probe tools, and replays of an earlier
  echo. The prompts tell the model to quote every `ISC-` token it can see, so a marker in an echo
  event only shows that the model saw it somewhere.

## Result

Cells use only what the stored logs show. "Delivered" means a hook event handed the marker to
the model; "echo only" means the model had it (it quoted it) but no hook event delivered it.

| MCP channel | Claude Code hooks | Gemini CLI hooks | Transparent proxy |
|---|---|---|---|
| Tool result | delivered: `PostToolUse` under `mcp__probe__lookup` (an `mcp__` matcher sees it) | delivered: `AfterTool` under `mcp_probe_lookup` | every `tools/call` passes through it; in the "tools" prompt only the first lookup reached the upstream (see the rug-pull note) |
| Tool description | echo only: reached the model, no hook event delivered it (`Stop` is the model's echo) | not observed: `ISC-DESC-41` appears in no hook or chat log in the direct run, and no hook carried it in the proxy run, where the model did quote it | the proxy fetches every `tools/list` itself and passes benign descriptions through (the model quoted `ISC-DESC-41` under both proxy runs); gating poisoned descriptions is measured by the MCPTox replay, not here |
| Resource content | delivered: `PostToolUse` under the built-in `ReadMcpResourceTool`; a `*` matcher sees it, an `mcp__.*` matcher would miss it by name (inferred, not run) | not reached: the model never requested a resource (`resources/read` 0) | not exposed: the proxy implements tools only, so the feature is lost, not mediated; `resources/read` 1 to 0 on Claude, 0 to 0 on Gemini |
| Prompt content | echo only: reached the model, no pre-action event carried it (`UserPromptExpansion` fired once with no marker; `Stop` is the model's echo) | delivered pre-model by `BeforeAgent`, `BeforeModel` and `BeforeToolSelection`; not by `BeforeTool` | not exposed: `prompts/get` 1 to 0 on both harnesses |
| Changed description (rug-pull) | not observed: Claude listed tools once per session, so the changed description never reached the model | reached the model (quoted `ISC-DESC2-45`); no hook event delivered it, only the `AfterAgent` echo | the changed tool was hidden and later calls were refused, for the rest of that session (below); direct Gemini is the only run where the changed description reached the model |
| Elicitation | not exercised | not exercised | not exercised |
| Sampling | not tested | not tested | not tested |

**Rug-pull row, under the proxy.** The probe changed the lookup tool's description after its
first call and sent `tools/list_changed`. The proxy fails closed on any change after connect
(`_refresh_catalog` adds the tool to a drifted set that is never cleared, `mcp_proxy.py:469`).
In the Claude run the second and third lookups failed with "Tool lookup is not available through
IntentShield" (two `PostToolUseFailure` events); in the Gemini run the second lookup never
reached the upstream (the probe logged one `tools/call`). A new session starts a new proxy
process and the lookup worked again (Gemini proxy, "resources" prompt). So this is the proxy
behaving as designed. It also means the first-version probe used one tool for both the result
and the rug-pull, so the proxy rows for the result channel are one call deep.

**Elicitation.** In three of four runs the probe's SDK raised `NoBackChannelError` before sending
anything (Claude direct, Claude proxy, Gemini proxy); Claude direct had declared the elicitation
capability. The fourth run (Gemini direct) got "Method not found" (-32601). No elicitation
request ever reached a client, so this row is "not exercised", not "not observed". Sampling was
never attempted. A local stdio client declaring both capabilities did receive both requests from
the updated probe, so the probe itself works; why Claude Code's transport reports no back-channel
is not established.

Requests that reached the probe server. Under the proxy these are the proxy's own upstream
requests, so its `tools/list` counts are its fan-out (it re-lists on its own), not requests the
harness made:

| | resources/read | prompts/get | tools/list | tools/call |
|---|---|---|---|---|
| Claude, direct | 1 | 1 | 4 | 4 |
| Claude, proxy | 0 | 0 | 14 (proxy) | 2 |
| Gemini, direct | 0 | 1 | 8 | 4 |
| Gemini, proxy | 0 | 0 | 15 (proxy) | 3 |

## What the data supports

- A hook scoped to MCP tool names saw the tool-result channel on both harnesses.
- No hook event in either harness delivered a tool description to the model, in either mode.
  The stored logs show it in every cell; it is consistent with hook inputs that carry tool
  calls and results rather than the tool list, though that was not checked against the schemas.
  It is the one gap observed in both harnesses.
- Resource content reached a `*`-matched hook on Claude under a built-in tool name that an
  `mcp__` matcher would not match. Prompt content reached Gemini's model-request hooks but not
  its tool hook, and reached no Claude pre-action hook.
- The proxy sees `tools/list` and `tools/call`. It does not expose resources or prompts at all,
  which removes those features from the client instead of mediating them.
- Not supported by this data: that any channel is "bypassed" in the sense of an attack succeeding
  (no attack was run), or anything about elicitation and sampling.

## Instrumentation fixes (applied after this run; re-run pending)

1. Hook events are classified as input delivery or model echo and reported separately
   (`delivered_by`, `echoed_in`). A tool event counts as delivery only for the probe's MCP tools
   or the harness's MCP resource tools, and the tool name is recorded.
2. Each prompt gets its own project directory (and, on Gemini, its own `HOME`). In the stored
   Gemini proxy run the model wrote `info.txt` containing the markers in the "tools" prompt and
   later sessions read it, which inflated its description and result rows.
3. MCP tool names match `mcp__` and `mcp_` (Gemini names its MCP tools `mcp_probe_lookup`),
   or the server field.
4. The description and result channels use a stable `lookup`; the changing description moved to a
   separate `lookup_v`, scored on its own with a fifth "rugpull" prompt.
5. The summary records how elicitation and a benign sampling request ended, by failure kind
   (`server_initiated`), and labels the request counts as upstream requests.

## Limitations

Two harnesses, one model each, one run per cell, benign markers, no Codex or Cursor. Whether a
hook could act on a marker before the model sees it was not tested; this study only records which
event carried it. Real injections on each channel, an adaptive attacker and the review cost of a
proxy are not covered here. See [contribution.md](contribution.md) §5 and §7 for what this does
and does not support as a research claim, and for the two routes forward.
