# Coverage re-run: which MCP surfaces reach a hook, per harness build (no model)

Every cell is k/n with a Wilson 95% interval in brackets (percent, computed here from k and n). n counts valid launches of one stub-model run; the stub model is deterministic, so n=3 shows run-to-run stability of the harness, not sampling variance of a model. See [hook-fidelity-coverage-rerun.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-coverage-rerun.md) for the method and limits.

## claude 2.0.41

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | tools |
| server_instructions | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | system |
| changed_description | 1 | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | none |
| tool_result | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | PostToolUse | messages[user:tool_result] |
| resource_read | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | PostToolUse | messages[user:tool_result] |
| prompt_content | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | messages[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 1/1 [21,100]; resource_read: 1/1 [21,100].

## claude 2.1.69

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | system |
| changed_description | 3 | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | messages[user:tool_result] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | messages[user:tool_result] |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## claude 2.1.139

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |
| changed_description | 3 | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## claude 2.1.246

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |
| changed_description | 3 | 0/3 [0,56] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## claude 2.1.316

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |
| changed_description | 3 | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolBatch, PostToolUse | messages[user:tool_result] |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | messages[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## codex 0.131.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| changed_description | 3 | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | input[function_call_output:function_call_output] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 0/3 [0,56].

## codex 0.134.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 0 | not run | | | | | | | |
| server_instructions | 0 | not run | | | | | | | |
| changed_description | 0 | not run | | | | | | | |
| tool_result | 0 | not run | | | | | | | |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: resource_read: 0/3 [0,56].

## codex 0.136.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 0 | not run | | | | | | | |
| server_instructions | 0 | not run | | | | | | | |
| changed_description | 0 | not run | | | | | | | |
| tool_result | 0 | not run | | | | | | | |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: resource_read: 3/3 [44,100].

## codex 0.140.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 0 | not run | | | | | | | |
| server_instructions | 0 | not run | | | | | | | |
| changed_description | 0 | not run | | | | | | | |
| tool_result | 0 | not run | | | | | | | |
| resource_read | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | PostToolUse | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: resource_read: 1/1 [21,100].

## codex 0.149.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 0 | not run | | | | | | | |
| server_instructions | 0 | not run | | | | | | | |
| changed_description | 0 | not run | | | | | | | |
| tool_result | 0 | not run | | | | | | | |
| resource_read | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | PostToolUse | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: resource_read: 1/1 [21,100].

## codex 0.166.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| changed_description | 3 | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | input[function_call_output:function_call_output] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | PostToolUse | input[function_call_output:function_call_output] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## gemini 0.37.1

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | systemInstruction |
| changed_description | 3 | 0/3 [0,56] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 0 | not run | | | | | | | |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | AfterAgent, AfterModel, BeforeAgent, BeforeModel, BeforeToolSelection | contents[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100].

## gemini 0.37.2

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | tools |
| server_instructions | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | systemInstruction |
| changed_description | 1 | 0/1 [0,79] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | none |
| tool_result | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 0 | not run | | | | | | | |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 1/1 [21,100].

## gemini 0.39.1

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | systemInstruction |
| changed_description | 3 | 0/3 [0,56] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 0 | not run | | | | | | | |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100].

## gemini 0.41.2

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | AfterModel, BeforeModel, BeforeToolSelection | contents[user:text] |
| changed_description | 3 | 0/3 [0,56] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 2 | 2/2 [34,100] | 2/2 [34,100] | 0/2 [0,66] | 2/2 [34,100] | 2/2 [34,100] | 2/2 [34,100] | AfterTool | contents[user:functionResponse] |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 2/2 [34,100].

## gemini 0.50.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | tools |
| server_instructions | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | AfterModel, BeforeModel, BeforeToolSelection | contents[user:text] |
| changed_description | 1 | 0/1 [0,79] | 1/1 [21,100] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | 0/1 [0,79] | none | none |
| tool_result | 1 | 1/1 [21,100] | 1/1 [21,100] | 0/1 [0,79] | 1/1 [21,100] | 1/1 [21,100] | 1/1 [21,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 0 | not run | | | | | | | |
| prompt_content | 0 | not run | | | | | | | |

Scripted call reached a PreToolUse-class hook event: tool_result: 1/1 [21,100].

## gemini 0.66.0

| surface | n | model got it (stub log) | server was asked | tool-gate hook (Pre/BeforeTool, PermissionRequest) | result hook | any hook | any hook before the model | hook events that carried it | where in the model request |
|---|---|---|---|---|---|---|---|---|---|
| tool_description | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | tools |
| server_instructions | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | AfterModel, BeforeModel, BeforeToolSelection | contents[user:text] |
| changed_description | 3 | 0/3 [0,56] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | 0/3 [0,56] | none | none |
| tool_result | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | AfterTool | contents[user:functionResponse] |
| resource_read | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | 3/3 [44,100] | AfterTool | contents[user:functionResponse] |
| prompt_content | 3 | 3/3 [44,100] | 3/3 [44,100] | 0/3 [0,56] | 0/3 [0,56] | 3/3 [44,100] | 3/3 [44,100] | AfterAgent, AfterModel, BeforeAgent, BeforeModel, BeforeToolSelection | contents[user:text] |

Scripted call reached a PreToolUse-class hook event: tool_result: 3/3 [44,100]; resource_read: 3/3 [44,100].

## Longitudinal: first and last sampled build where a hook carried each surface

| harness | surface | builds sampled (old to new) | hook-visible per build | first / last build where any hook carried it |
|---|---|---|---|---|
| claude | changed_description | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: no hook; 2.1.69: no hook; 2.1.139: no hook; 2.1.246: no hook; 2.1.316: no hook | never hook-visible in any sampled build |
| claude | prompt_content | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: no hook; 2.1.69: no hook; 2.1.139: no hook; 2.1.246: no hook; 2.1.316: no hook | never hook-visible in any sampled build |
| claude | resource_read | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: result hook; 2.1.69: result hook; 2.1.139: result hook; 2.1.246: result hook; 2.1.316: result hook | all sampled builds (2.0.41 .. 2.1.316); no change |
| claude | server_instructions | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: no hook; 2.1.69: no hook; 2.1.139: no hook; 2.1.246: no hook; 2.1.316: no hook | never hook-visible in any sampled build |
| claude | tool_description | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: no hook; 2.1.69: no hook; 2.1.139: no hook; 2.1.246: no hook; 2.1.316: no hook | never hook-visible in any sampled build |
| claude | tool_result | 2.0.41, 2.1.69, 2.1.139, 2.1.246, 2.1.316 | 2.0.41: result hook; 2.1.69: result hook; 2.1.139: result hook; 2.1.246: result hook; 2.1.316: result hook | all sampled builds (2.0.41 .. 2.1.316); no change |
| codex | changed_description | 0.131.0, 0.166.0 | 0.131.0: no hook; 0.166.0: no hook | never hook-visible in any sampled build |
| codex | resource_read | 0.131.0, 0.134.0, 0.136.0, 0.140.0, 0.149.0, 0.166.0 | 0.131.0: no hook; 0.134.0: no hook; 0.136.0: result hook; 0.140.0: result hook; 0.149.0: result hook; 0.166.0: result hook | first 0.136.0, last 0.166.0; class changed between builds |
| codex | server_instructions | 0.131.0, 0.166.0 | 0.131.0: no hook; 0.166.0: no hook | never hook-visible in any sampled build |
| codex | tool_description | 0.131.0, 0.166.0 | 0.131.0: no hook; 0.166.0: no hook | never hook-visible in any sampled build |
| codex | tool_result | 0.131.0, 0.166.0 | 0.131.0: result hook; 0.166.0: result hook | all sampled builds (0.131.0 .. 0.166.0); no change |
| gemini | changed_description | 0.37.1, 0.37.2, 0.39.1, 0.41.2, 0.50.0, 0.66.0 | 0.37.1: no hook; 0.37.2: no hook; 0.39.1: no hook; 0.41.2: no hook; 0.50.0: no hook; 0.66.0: no hook | never hook-visible in any sampled build |
| gemini | prompt_content | 0.37.1, 0.66.0 | 0.37.1: model-request/agent events only; 0.66.0: model-request/agent events only | all sampled builds (0.37.1 .. 0.66.0); no change |
| gemini | resource_read | 0.41.2, 0.66.0 | 0.41.2: result hook; 0.66.0: result hook | all sampled builds (0.41.2 .. 0.66.0); no change |
| gemini | server_instructions | 0.37.1, 0.37.2, 0.39.1, 0.41.2, 0.50.0, 0.66.0 | 0.37.1: no hook; 0.37.2: no hook; 0.39.1: no hook; 0.41.2: model-request/agent events only; 0.50.0: model-request/agent events only; 0.66.0: model-request/agent events only | first 0.41.2, last 0.66.0; class changed between builds |
| gemini | tool_description | 0.37.1, 0.37.2, 0.39.1, 0.41.2, 0.50.0, 0.66.0 | 0.37.1: no hook; 0.37.2: no hook; 0.39.1: no hook; 0.41.2: no hook; 0.50.0: no hook; 0.66.0: no hook | never hook-visible in any sampled build |
| gemini | tool_result | 0.37.1, 0.37.2, 0.39.1, 0.41.2, 0.50.0, 0.66.0 | 0.37.1: result hook; 0.37.2: result hook; 0.39.1: result hook; 0.41.2: result hook; 0.50.0: result hook; 0.66.0: result hook | all sampled builds (0.37.1 .. 0.66.0); no change |

## Launches where the harness did not offer the scripted tool up front

These are not in any n above. The harness did not list the tool the stub was scripted to call among the tools the model was offered in its first request (tool search or a resource tool the build lacks), so the cell is read from the logs instead: what the model was sent, whether the call was dispatched anyway (a tool result reached the model), and which hook events saw it.

| build | launch | launches | tool declaration (DESC) in the model request | instructions (INSTR) in the model request | scripted call dispatched anyway (RESULT reached the model) | result hook saw it | resources/list asked | resources/read asked | tools offered in the first request |
|---|---|---|---|---|---|---|---|---|---|
| claude 2.1.316 (toolsearch-default) | tools | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 12 tools; probe or resource tools among them: none |
| codex 0.166.0 (bundled-slug-gpt-5.5) | tools | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 13 tools; probe or resource tools among them: list_mcp_resource_templates, list_mcp_resources, read_mcp_resource |
| gemini 0.37.1 | resource | 3 | 3/3 | 3/3 | 0/3 | 0/3 | 3/3 | 0/3 | 18 tools; probe or resource tools among them: mcp_probe_lookup, mcp_probe_lookup_v |
| gemini 0.39.1 | resource | 1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 0/1 | 18 tools; probe or resource tools among them: mcp_probe_lookup, mcp_probe_lookup_v |

## Launch ledger

Launches recorded in this directory's ledger: 94 (rows: 94). Preliminary and debug launches that are not rows here are listed in `launches.json`.
