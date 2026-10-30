"""The ``intentshield`` command.

    intentshield                       # the local dashboard and API on 127.0.0.1:8000
    intentshield serve [--port N]
    intentshield install <harness>     # register the hooks in Claude Code, Codex CLI, Cursor or Gemini CLI
    intentshield uninstall <harness>
    intentshield wrap <mcp json>       # put the transparent proxy in front of the servers a client launches
    intentshield unwrap <mcp json>
    intentshield scan [config ...]     # find the MCP servers your agents use and check them offline
    intentshield doctor                # check the hooks and proxies are installed and actually run

The guard itself is ``intentshield-hook`` (hooks) and ``intentshield-mcp`` (gateway and transparent
proxy); this command installs and runs them.
"""
from __future__ import annotations

import argparse
import sys

from . import __version__, doctor, install, scan


def serve(port: int = 8000) -> None:
    import uvicorn

    from .logs import configure_logging

    configure_logging()
    # No proxy headers: every local client would be a trusted proxy and could pick its own
    # address in X-Forwarded-For, dodging the rate limit.
    uvicorn.run("intentshield.api:create_app", factory=True, host="127.0.0.1", port=port, reload=False,
                proxy_headers=False)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(prog="intentshield", description=__doc__.strip(),
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"intentshield {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the local dashboard and API (the default)").add_argument(
        "--port", type=int, default=8000, help="TCP port on 127.0.0.1 (default 8000)")
    install.add_subcommands(sub)
    scan.add_subcommand(sub)
    doctor.add_subcommand(sub)
    args = parser.parse_args(argv or ["serve"])
    if args.command == "serve":
        serve(args.port)
        return
    runner = {"scan": scan.run, "doctor": doctor.run}.get(args.command, install.run)
    sys.exit(runner(args))


if __name__ == "__main__":
    main()
