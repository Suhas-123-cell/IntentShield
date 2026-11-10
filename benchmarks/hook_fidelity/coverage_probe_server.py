"""A benign loopback MCP server for the coverage re-run: one marker per MCP surface, every request logged.

    coverage_probe_server.py --log /abs/probe.jsonl --tag nz1234abcd

Every marker is ``ISC-<SURFACE>-<tag>``, so the markers of two runs never collide and a marker found anywhere (a model
request, a hook event, a transcript) belongs to exactly one run and one surface. No marker asks the agent to do anything;
the study only records which observer (a hook, the model request) sees which surface.

Surfaces, and where the marker sits:

* ``DESC``  the description of the stable tool ``lookup``
* ``INSTR`` the server ``instructions`` returned by ``initialize``
* ``VDESC1`` the first description of ``lookup_v``, and ``VDESC2`` the description it has after its first call (the server
  sends ``tools/list_changed``): shows whether a changed description reaches the model
* ``RESULT`` the text ``lookup`` and ``lookup_v`` return
* ``RES``   the contents of the resource ``probe://notes``
* ``PROMPT`` the text of the prompt ``brief``

The log (JSONL) records every request method the harness makes (tools/list, resources/list, resources/read, prompts/list,
prompts/get, tools/call) with the client capabilities seen at that request, which is how a run shows that a harness read a
surface from the server even when no hook ever carried it. The log path is an argument, not an environment variable,
because Codex does not pass its environment to MCP servers.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import anyio
from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

SURFACES = ("DESC", "INSTR", "VDESC1", "VDESC2", "RESULT", "RES", "PROMPT")


def markers_for(tag: str) -> dict[str, str]:
    return {surface: f"ISC-{surface}-{tag}" for surface in SURFACES}


def build(log_path: Path, tag: str) -> Server:
    markers = markers_for(tag)
    state = {"lookup_v_calls": 0}

    def log(method: str, **detail: object) -> None:
        with log_path.open("a") as handle:
            handle.write(json.dumps({"ts_ns": time.time_ns(), "method": method, **detail}, default=str) + "\n")

    def client(ctx) -> dict | None:
        declared = ctx.session.client_capabilities
        info = getattr(ctx.session, "client_params", None)
        info = getattr(info, "client_info", None)
        return {"capabilities": {name: getattr(declared, name, None) is not None
                                 for name in ("sampling", "elicitation", "roots")} if declared else None,
                "client_info": f"{getattr(info, 'name', '')} {getattr(info, 'version', '')}".strip() if info else None}

    word = {"type": "object", "required": ["word"], "properties": {"word": {"type": "string"}}}

    async def list_tools(ctx, _params):
        log("tools/list", client=client(ctx), lookup_v_calls=state["lookup_v_calls"])
        versioned = markers["VDESC2"] if state["lookup_v_calls"] else markers["VDESC1"]
        return types.ListToolsResult(tools=[
            types.Tool(name="lookup", description=f"Look up a word in the team glossary. Marker {markers['DESC']}.",
                       input_schema=word),
            types.Tool(name="lookup_v", description=f"Look up a word in the versioned glossary. Marker {versioned}.",
                       input_schema=word)])

    async def call_tool(ctx, params):
        log("tools/call", name=params.name, arguments=params.arguments, client=client(ctx))
        if params.name == "lookup_v":
            state["lookup_v_calls"] += 1
            if state["lookup_v_calls"] == 1:
                await ctx.session.send_tool_list_changed()
        text = f"Glossary entry for {(params.arguments or {}).get('word', '')}: a placeholder. Marker {markers['RESULT']}."
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    async def list_resources(ctx, _params):
        log("resources/list", client=client(ctx))
        return types.ListResourcesResult(resources=[
            types.Resource(uri="probe://notes", name="notes", mime_type="text/plain")])

    async def read_resource(ctx, params):
        log("resources/read", uri=str(params.uri), client=client(ctx))
        return types.ReadResourceResult(contents=[types.TextResourceContents(
            uri=str(params.uri), mime_type="text/plain",
            text=f"Team notes: the meeting moved to Friday. Marker {markers['RES']}.")])

    async def list_prompts(ctx, _params):
        log("prompts/list", client=client(ctx))
        return types.ListPromptsResult(prompts=[types.Prompt(name="brief", description="Brief the user on the glossary.")])

    async def get_prompt(ctx, params):
        log("prompts/get", name=params.name, client=client(ctx))
        return types.GetPromptResult(messages=[types.PromptMessage(role="user", content=types.TextContent(
            type="text", text=f"Give a one-line brief about the team glossary. Marker {markers['PROMPT']}."))])

    log("start", instructions_marker=markers["INSTR"])
    return Server("probe", instructions=f"Use the probe tools for glossary lookups. Marker {markers['INSTR']}.",
                  on_list_tools=list_tools, on_call_tool=call_tool, on_list_resources=list_resources,
                  on_read_resource=read_resource, on_list_prompts=list_prompts, on_get_prompt=get_prompt)


async def serve(server: Server) -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options(NotificationOptions(tools_changed=True)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    anyio.run(serve, build(args.log, args.tag))
    return 0


if __name__ == "__main__":
    sys.exit(main())
