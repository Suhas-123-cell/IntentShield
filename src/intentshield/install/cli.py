"""The ``install``, ``uninstall``, ``wrap`` and ``unwrap`` subcommands of the ``intentshield`` command."""
from __future__ import annotations

import argparse
import errno
import sys
import textwrap
import tomllib
from pathlib import Path
from typing import Any

from .hooks import HARNESSES
from .records import ChangedMeanwhile
from .settings import install, uninstall
from .wrapping import unwrap, wrap


class _KeepAddresses(argparse.HelpFormatter):
    """Help text wrapped so that an address stays on one line: the default breaks it at its hyphens, and it cannot be copied."""

    def _split_lines(self, text: str, width: int) -> list[str]:
        return textwrap.wrap(self._whitespace_matcher.sub(" ", text).strip(), width, break_on_hyphens=False,
                             break_long_words=False)


def add_subcommands(sub: Any) -> None:
    for verb in ("install", "uninstall"):
        p = sub.add_parser(verb, help=f"{verb} the IntentShield hooks in an agent harness", formatter_class=_KeepAddresses)
        p.add_argument("harness", choices=HARNESSES, help="the agent harness whose settings file to edit")
        p.add_argument("--scope", choices=("user", "project"), default="user",
                       help="user: the harness's home settings; project: its settings in the current directory")
        p.add_argument("--dry-run", action="store_true", help="print the file instead of writing it")
        if verb == "install":
            p.add_argument("--review", choices=("tainted", "always", "never"), default=None,
                           help="pass --review to the hook (Codex and Gemini CLI cannot ask, so 'always' denies)")
            p.add_argument("--judge", nargs="?", const="groq", default=None, metavar="PROVIDER[:MODEL]",
                           help="turn on the LLM judge: groq (default, free tier, asks for GROQ_API_KEY once), "
                                "gemini, deepseek, ollama (local), or your own key with openai:<model>, "
                                "openrouter:<model> or custom:<model> (with --judge-url)")
            p.add_argument("--api-key", default=None,
                           help="the judge's API key, instead of being asked (replaces a stored one)")
            p.add_argument("--judge-url", default=None, metavar="URL",
                           help="with --judge custom:<model>: your OpenAI-compatible chat completions endpoint")
            p.add_argument("--builtin-tools", action="store_true",
                           help="also guard the harness's own shell, file and web tools (Bash, PowerShell, Monitor, "
                                "WebFetch, Read, Write...) with the built-in text rules: opt-in and best effort, not a "
                                "sandbox (rules: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/rules.md). "
                                "Install again without it to turn them off")
            p.add_argument("--gemini-ask", action="store_true",
                           help="Gemini CLI 0.66 or later, interactive sessions only: ask instead of refusing. "
                                "Headless runs (gemini -p) then hang on an ask; check with `intentshield doctor`")
            p.add_argument("--no-translate", action="store_true",
                           help="send the guard's verdicts as they are, with no deadline and no fail-closed launcher "
                                "(the hook as it was before the verdict translation)")
            p.add_argument("--allow-ephemeral", action="store_true",
                           help="record the hook's path even when it lies in the cache of uvx, pipx run or npx, which is "
                                "cleaned (install refuses that by default)")
            p.add_argument("--judge-outputs", action="store_true",
                           help="the judge also reads each tool result the rules pass (catches plain-language "
                                "injections; one request per result, about 1 s locally, 4 s on Gemini)")
    for verb in ("wrap", "unwrap"):
        p = sub.add_parser(verb, help=f"{verb} stdio MCP servers of a client's MCP file "
                                      f"{'in' if verb == 'wrap' else 'from'} the transparent proxy")
        p.add_argument("config", type=Path,
                       help="e.g. .mcp.json or ~/.claude.json (Claude Code), .cursor/mcp.json, ~/.gemini/settings.json, "
                            "~/.codex/config.toml (Codex CLI), .vscode/mcp.json (VS Code)")
        p.add_argument("--server", action="append", dest="servers", metavar="NAME",
                       help="only this server (repeatable)")
        p.add_argument("--dry-run", action="store_true", help="print the files instead of writing them")
        if verb == "wrap":
            p.add_argument("--out-dir", type=Path, default=None,
                           help="where generated proxy configs and databases go (default ~/.intentshield/proxies)")
            p.add_argument("--allow-ephemeral", action="store_true",
                           help="record the proxy's path even when it lies in the cache of uvx, pipx run or npx, which is "
                                "cleaned (wrap refuses that by default)")


_NO_ACCESS = (errno.EACCES, errno.EPERM, errno.EROFS)


def _explain(exc: Exception) -> str:
    """An error as a line for the user. A place that is refused (a read-only home, a file of another user) is named, with what to
    do about it, instead of the bare ``[Errno 13] Permission denied``."""
    if isinstance(exc, OSError) and not isinstance(exc, ChangedMeanwhile) and exc.errno in _NO_ACCESS and exc.filename:
        return (f"cannot use {exc.filename} ({exc.strerror}). IntentShield edits the settings or MCP file and keeps its own "
                "records in ~/.intentshield, so both must be readable and writable by you: fix the permissions (or the read-only "
                "mount), then run the command again")
    if isinstance(exc, OSError) and exc.errno in (errno.EISDIR, errno.ENOTDIR, errno.EEXIST) and exc.filename:
        return (f"{exc.filename} is not a file IntentShield can edit ({exc.strerror}); move it aside or fix the path, "
                "then run the command again")
    return str(exc)


def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "install":
            if args.judge_outputs and not args.judge:
                raise ValueError("--judge-outputs needs --judge")
            install(args.harness, args.scope, args.review, dry_run=args.dry_run, judge=args.judge,
                    api_key=args.api_key, judge_url=args.judge_url, judge_outputs=args.judge_outputs,
                    builtin_tools=args.builtin_tools, gemini_ask=args.gemini_ask,
                    translate=not args.no_translate, allow_ephemeral=args.allow_ephemeral)
        elif args.command == "uninstall":
            uninstall(args.harness, args.scope, dry_run=args.dry_run)
        elif args.command == "wrap":
            done = wrap(args.config, args.servers, args.out_dir, dry_run=args.dry_run, allow_ephemeral=args.allow_ephemeral)
            if done.skipped:  # a script that expects every server wrapped must not read this as a success
                print("intentshield wrap: at least one server was skipped (see above), so it is not behind the proxy",
                      file=sys.stderr)
                return 1
        elif args.command == "unwrap":
            unwrap(args.config, args.servers, dry_run=args.dry_run)
        else:
            return 2
    except (OSError, ValueError, KeyError, IndexError, tomllib.TOMLDecodeError) as exc:
        print(f"intentshield {args.command}: {_explain(exc)}", file=sys.stderr)
        return 1
    return 0
