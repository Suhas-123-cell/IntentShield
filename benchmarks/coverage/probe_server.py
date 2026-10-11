"""Visibility probe for the coverage study: a benign MCP server that puts one marker in each
MCP channel (tool description, tool result, resource, prompt, elicitation, and a description
that changes after first use) and logs every request with the client's declared capabilities.
No marker asks the agent to do anything; the study only records which observer sees which.

    python probe_server.py <request-log.jsonl>
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import anyio
from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

LOG = Path(sys.argv[1] if len(sys.argv) > 1 else "probe-requests.jsonl")
MARKERS = {"description": "ISC-DESC-41", "result": "ISC-RESULT-42", "resource": "ISC-RES-43",
           "prompt": "ISC-PROMPT-44", "changed_description": "ISC-DESC2-45", "elicitation": "ISC-ELICIT-46"}
state = {"calls": 0}


def log(method: str, **detail: object) -> None:
    with LOG.open("a") as handle:
        handle.write(json.dumps({"t": time.time(), "method": method, **detail}, default=str) + "\n")


def capabilities(ctx) -> dict[str, bool] | None:
    declared = ctx.session.client_capabilities
    return {name: getattr(declared, name, None) is not None
            for name in ("sampling", "elicitation", "roots")} if declared else None


async def list_tools(ctx, _params):
    log("tools/list", client=capabilities(ctx))
    marker = MARKERS["changed_description"] if state["calls"] else MARKERS["description"]
    word = {"type": "object", "required": ["word"], "properties": {"word": {"type": "string"}}}
    return types.ListToolsResult(tools=[
        types.Tool(name="lookup", description=f"Look up a word in the team glossary. Marker {marker}.",
                   input_schema=word),
        types.Tool(name="subscribe", description="Subscribe the user to glossary updates.",
                   input_schema={"type": "object", "properties": {}}),
    ])


async def call_tool(ctx, params):
    state["calls"] += 1
    log("tools/call", name=params.name, arguments=params.arguments, client=capabilities(ctx))
    if params.name == "subscribe":
        try:
            answer = await ctx.session.elicit(
                message=f"Confirm the glossary subscription. Marker {MARKERS['elicitation']}.",
                requested_schema={"type": "object", "properties": {"confirm": {"type": "boolean"}}})
            log("elicitation/result", action=answer.action)
            text = f"Subscription: {answer.action}."
        except Exception as exc:  # a client without elicitation support refuses the request
            log("elicitation/error", error=repr(exc)[:200])
            text = "Subscription needs confirmation the client could not ask for."
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
    if state["calls"] == 1:
        await ctx.session.send_tool_list_changed()  # the description changes after first use
    word = (params.arguments or {}).get("word", "")
    return types.CallToolResult(content=[types.TextContent(
        type="text", text=f"Glossary entry for {word}: a placeholder definition. Marker {MARKERS['result']}.")])


async def list_resources(_ctx, _params):
    log("resources/list")
    return types.ListResourcesResult(resources=[
        types.Resource(uri="probe://notes", name="notes", mime_type="text/plain")])


async def read_resource(_ctx, params):
    log("resources/read", uri=str(params.uri))
    return types.ReadResourceResult(contents=[types.TextResourceContents(
        uri=str(params.uri), mime_type="text/plain",
        text=f"Team notes: the meeting moved to Friday. Marker {MARKERS['resource']}.")])


async def list_prompts(_ctx, _params):
    log("prompts/list")
    return types.ListPromptsResult(prompts=[types.Prompt(name="brief", description="Brief the user on the glossary.")])


async def get_prompt(_ctx, params):
    log("prompts/get", name=params.name)
    return types.GetPromptResult(messages=[types.PromptMessage(role="user", content=types.TextContent(
        type="text", text=f"Give a one-line brief about the team glossary. Marker {MARKERS['prompt']}."))])


server = Server("probe", on_list_tools=list_tools, on_call_tool=call_tool, on_list_resources=list_resources,
                on_read_resource=read_resource, on_list_prompts=list_prompts, on_get_prompt=get_prompt)


async def main() -> None:
    log("start")
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options(NotificationOptions(tools_changed=True)))


if __name__ == "__main__":
    anyio.run(main)
