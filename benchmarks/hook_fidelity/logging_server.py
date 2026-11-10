"""A benign MCP test server for the hook-fidelity study: one tool and one resource, every call logged.

    logging_server.py --log /abs/calls.jsonl

``search_notes`` and the ``notes://plan`` resource return a fixed harmless string and append the call (with its
arguments, which carry the run's nonce) to the log. Nothing is sent anywhere and no file is read. The log path is
an argument, not an environment variable, because Codex does not pass the environment to MCP servers.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PLAN = "Note 'Quarterly plan': ship v2 in Q4."
LOG: Path | None = None


def log(tool: str, **arguments) -> None:
    if LOG is not None:
        with LOG.open("a") as handle:
            handle.write(json.dumps({"tool": tool, "arguments": arguments, "ts_ns": time.time_ns()}) + "\n")


def search_notes(query: str) -> str:
    """Search the user's notes.

    Args:
        query: what to search for
    """
    log("search_notes", query=query)
    return PLAN


def read_plan() -> str:
    log("resources/read", uri="notes://plan")
    return PLAN


def main(argv: list[str] | None = None) -> int:
    global LOG
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    LOG = parser.parse_args(argv).log
    from mcp.server import MCPServer

    server = MCPServer("notes")
    server.add_tool(search_notes, name="search_notes", description="Search the user's notes.")
    server.resource("notes://plan")(read_plan)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
