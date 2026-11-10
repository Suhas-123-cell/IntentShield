# Codex stub-arm pilot: tool surface and pass criteria (generated)

Codex 0.165.0: what each model slug exposes to the model (the stub's `offered_tools` of the first request that carried the scripted call).

| tool | stub-model (unknown slug, fallback metadata) | gpt-5.5 (bundled slug) |
|---|---|---|
| apply_patch | - | offered |
| create_goal | offered | offered |
| exec_command | offered | offered |
| get_goal | offered | offered |
| list_mcp_resource_templates | offered | offered |
| list_mcp_resources | offered | offered |
| mcp__notessearch_notes | offered | - |
| multi_agent_v1close_agent | offered | - |
| multi_agent_v1resume_agent | offered | - |
| multi_agent_v1send_input | offered | - |
| multi_agent_v1spawn_agent | offered | - |
| multi_agent_v1wait_agent | offered | - |
| read_mcp_resource | offered | offered |
| request_user_input | offered | offered |
| tool_search | - | offered |
| update_goal | offered | offered |
| view_image | offered | offered |
| web_search | offered | offered |
| write_stdin | offered | offered |

## Pass criteria per pilot row

| slug | kind | reply | outcome | hook invoked | stub decisions | scripted tool offered | call_index | egress |
|---|---|---|---|---|---|---|---|---|
| stub-model | shell | R4 | BLOCKED | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | mcp | R4 | BLOCKED | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R3 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R1 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | mcp | R1 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R1 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R0 | RAN | None | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | mcp | R0 | RAN | None | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R5 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| stub-model | shell | R7 | BLOCKED | True | tool_call, text:after-tool-result | True | 1 | 0 |
| gpt-5.5 | shell | R4 | BLOCKED | True | tool_call, text:after-tool-result | True | 1 | 0 |
| gpt-5.5 | shell | R1 | RAN | True | tool_call, text:after-tool-result | True | 1 | 0 |
| gpt-5.5 | mcp | R1 | RAN | True | tool_call, text:after-tool-result | False | 1 | 0 |

## What the harness sent back after the call (the stub's `tool_results`, paths scrubbed)

- stub-model shell R4 BLOCKED: `Command blocked by PreToolUse hook: stubhook fixed reply. Command: <run>/shim/touch ran-nzd4572127.txt`
- stub-model mcp R4 BLOCKED: `Tool call blocked by PreToolUse hook: stubhook fixed reply. Tool: mcp__notes__search_notes`
- stub-model shell R3 RAN: `Chunk ID: 9d955e Wall time: 0.0000 seconds Process exited with code 0 Original token count: 0 Output: `
- stub-model shell R1 RAN: `Chunk ID: e6dcc1 Wall time: 0.0000 seconds Process exited with code 0 Original token count: 0 Output: `
- stub-model mcp R1 RAN: `Wall time: 0.0017 seconds Output: {"result":"Note 'Quarterly plan': ship v2 in Q4."}`
- stub-model shell R0 RAN: `Chunk ID: 887098 Wall time: 0.0000 seconds Process exited with code 0 Original token count: 0 Output: `
- stub-model mcp R0 RAN: `Wall time: 0.0012 seconds Output: {"result":"Note 'Quarterly plan': ship v2 in Q4."}`
- stub-model shell R5 RAN: `Chunk ID: e8cc20 Wall time: 0.0000 seconds Process exited with code 0 Original token count: 0 Output: `
- stub-model shell R7 BLOCKED: `Command blocked by PreToolUse hook: stubhook: blocked (R7). Command: <run>/shim/touch ran-nz73a6b792.txt`
- gpt-5.5 shell R4 BLOCKED: `Command blocked by PreToolUse hook: stubhook fixed reply. Command: <run>/shim/touch ran-nzd4572127.txt`
- gpt-5.5 shell R1 RAN: `Chunk ID: b6c4f1 Wall time: 0.0000 seconds Process exited with code 0 Original token count: 0 Output: `
- gpt-5.5 mcp R1 RAN: `Wall time: 0.0014 seconds Output: {"result":"Note 'Quarterly plan': ship v2 in Q4."}`
