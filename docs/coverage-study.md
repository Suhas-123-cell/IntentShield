# Channel coverage: what a hook-scoped MCP guard sees, and what a proxy sees

Experiment run 2026-10-12. Reproduce with `benchmarks/coverage/run.py` (probe server plus a
passive logging hook, four benign prompts, headless Claude Code and Gemini CLI). Raw
summaries in `artifacts/coverage/<harness>-<mode>/summary.json`.

## The question

A third-party guard for MCP is installed one of two ways: as a **harness hook** scoped to MCP
tool calls (the shipping pattern: `mcp__.*` matcher in Claude Code, `BeforeTool` in Gemini
CLI; used by Pillar, Numbat, CrowdStrike, HOL Guard and others), or as a **transparent proxy**
in front of the server. MCP carries attacker-controllable text on five channels: tool
descriptions, tool results, resource contents, prompt contents, and server-initiated
sampling/elicitation. Which channels does each placement actually observe? Complete mediation
(Saltzer & Schroeder 1975) requires that every such channel pass through the guard.

## Method

A benign probe server puts one unique marker in each channel and logs every protocol request
with the client's declared capabilities. A passive hook, registered on every relevant event,
logs which event carried each marker and under which tool name. Nothing blocks; this measures
visibility only. For each marker we record: did it reach the model's context; which hook
events carried it; would a hook **scoped to MCP tool names** have seen it; and which requests
reached the server (under the proxy, the ones it mediated).

## Result

Per-channel visibility to a guard, by placement (observed = seen in time to block; post-turn =
reaches the model but only after the turn or under a non-MCP tool name; closed = channel not
exposed):

| MCP channel | Claude hook (`mcp__.*`) | Gemini hook (`BeforeTool`) | Transparent proxy |
|---|---|---|---|
| Tool result | observed (PostToolUse) | observed (AfterTool) | observed (every `tools/call`) |
| Tool description | post-turn (`Stop` only) | post-turn (model hooks only) | observed (every `tools/list`) |
| Resource content | post-turn (built-in tool name, not `mcp__`) | not reached | closed (`resources/read` 1→0) |
| Prompt content | post-turn (`Stop` only) | post-turn (model hooks only) | closed (`prompts/get` 1→0) |
| Elicitation | not observed | not observed | not forwarded |

Server-side request counts (how the proxy closes the resource/prompt channels):

| | resources/read | prompts/get | tools/list | tools/call |
|---|---|---|---|---|
| Claude, direct | 1 | 1 | 4 | 4 |
| Claude, proxy | **0** | **0** | 14 (all via proxy) | 2 |
| Gemini, direct | 0 | 1 | 8 | 4 |
| Gemini, proxy | **0** | **0** | 15 (all via proxy) | 3 |

## Finding

A hook scoped to MCP tool calls — the way every shipping MCP guard registers — mediates only
the **tool-call and tool-result** channels. The **tool description, resource content and
prompt content** reach the model but never reach that hook in time to block it: in Claude Code
they surface only in the post-turn `Stop` event (after the call has run) or, for a resource,
under a built-in tool name (`ReadMcpResourceTool`) a `mcp__.*` matcher does not match; in
Gemini CLI they surface only on model-level hooks, not the tool hook. So a hook-scoped guard
does **not** satisfy complete mediation: three of five channels bypass it.

A transparent proxy does satisfy it. It mediates every `tools/list`, so it gates descriptions
before the model sees them, and it closes the resource and prompt channels outright — under
the proxy `resources/read` and `prompts/get` fall to zero on both harnesses, because the proxy
exposes only tools. This is the structural reason IntentShield pairs hooks with a proxy rather
than shipping hooks alone.

## Why this is a contribution

Prior work is adjacent but distinct. HarnessSecurity-Bench (2610.07639) measures harnesses'
own built-in settings, not third-party guards, and notes alternative execution paths without a
per-channel guard-visibility matrix. Fail-open studies and vendor docs cover what happens when
a hook crashes, not which channels never reach it. COPEX (2610.04378) and "Implicit Trust"
(2609.18217) attack the channels but isolate the model and do not evaluate guard placement.
None measure, per MCP channel and across harnesses, what a hook-scoped guard observes versus a
proxy. That matrix, plus the "proxy closes the resource/prompt channels" result, is new.

## Limitations

Two harnesses, one model each (Haiku, Gemini 3.1 Flash-Lite), benign markers rather than live
attacks, and SDK-version elicitation errors meant the elicitation channel never reached the
model in either harness, so its row is "not observed" rather than "confirmed blind". A full
paper needs: the same matrix under real injections on each channel (the threat model COPEX and
2609.18217 supply); Codex and Cursor; an adaptive attacker; and the utility/review cost of
closing the channels, which `benchmarks/msb.py` already measures for the tool-call channel.

## Paper framing

Title: *Complete Mediation for MCP: Why Hook-Scoped Guards Miss the Description, Resource and
Prompt Channels.* Sections: threat model (five channels) → coverage matrix (this result) →
per-channel attack demonstrating the gap → proxy as the fix → cost (MSB utility and review
load) → limitations. Target: a security workshop (AISec, SaTML, the Agents-in-the-Wild
workshop that published COPEX) or arXiv first. The MSB (0.0% executed harm) and MCPTox replay
numbers become the cost-of-mediation evidence, not the headline.
