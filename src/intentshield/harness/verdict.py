"""The verdict of a check, the kinds of the built-in tools, how an ask is answered by each harness and how a tool name is read."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .guard import HarnessGuard


_READ = frozenset({
    "get", "list", "search", "read", "find", "fetch", "query", "retrieve", "show", "view", "describe",
    "lookup", "browse", "count", "check", "inspect", "summarize", "info", "status", "tree", "directory",
})
_WRITE = frozenset({
    "add", "append", "approve", "archive", "assign", "book", "cancel", "change", "close", "commit",
    "create", "delete", "deploy", "edit", "email", "execute", "forward", "insert", "install", "invite",
    "kill", "mark", "merge", "modify", "move", "pay", "post", "publish", "push", "put", "remove",
    "rename", "replace", "reply", "restart", "run", "save", "schedule", "send", "set", "share", "start",
    "transfer", "update", "upload", "write",
    "clear", "destroy", "drop", "grant", "overwrite", "purge", "reset", "revoke", "truncate", "wipe",
    # Verbs that ride along with a read ("get_and_exec", "search_and_download", "status_stop"): one write verb
    # makes the tool a write, whatever else its name says.
    "apply", "attach", "authorize", "call", "clone", "comment", "connect", "detach", "disable", "dispatch",
    "download", "enable", "exec", "fork", "import", "invoke", "launch", "lock", "login", "logout", "mount",
    "notify", "pull", "register", "reject", "revert", "rollback", "stop", "submit", "subscribe", "sync",
    "toggle", "trigger", "unlock", "unsubscribe",
})


def is_mutation(tool: str) -> bool:
    """A tool name with a write verb, or with no read verb, may change state. Only the tool
    part of "server:tool" counts: a read verb in the server name must not hide a write."""
    tool = tool.partition(":")[2] or tool
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", tool).lower()
    if re.search(r"check[\W_]*(?:in|out)(?![a-z])", text):  # "check" reads, "check_in" books
        return True
    # "pull request" is a noun: "get_pull_request" reads, "pull_repo" writes.
    words = set(re.findall(r"[a-z0-9]+", re.sub(r"pull[\W_]+requests?", " ", text)))
    return bool(words & _WRITE) or not words & _READ


@dataclass
class Verdict:
    decision: str = "allow"                  # allow | deny | ask
    reason: str = ""
    arguments: dict[str, Any] | None = None  # rewritten arguments, when the harness can apply them
    user_reason: str = ""                    # the fuller reason, only where the user alone reads it
    context: str = ""                        # a note for the model
    findings: list[str] = field(default_factory=list)


def _kind_of(tool: str) -> str:
    """shell, write, read, fetch... for a built-in tool (``builtin:Bash``), "mcp" for an MCP tool (``server:tool``)."""
    return _BUILTIN.get(tool[8:], ("mcp",))[0] if tool.startswith("builtin:") else "mcp"


def _mode_note(guard: "HarnessGuard", harness: str, why: str, asked: bool) -> str:
    """The detector's reading (mode and which ancestry source decided), appended to the reason of every reply that came from an
    ask, so a run's evidence shows what the translation saw. Empty without a translation (and for Cursor, which has none). When an
    ask was passed on because the mode could not be read, ``why`` names the choice."""
    sem = guard.translation
    if sem is None or harness == "cursor":
        return ""
    return " " + sem.mode_note() + (f" {why}." if asked and why else "")


def _ask_as(guard: "HarnessGuard", harness: str, kind: str) -> tuple[str, str]:
    """("ask" or "deny", why) for a verdict of ask. With a translation (the default of the hook) the measured behaviour of the
    harness build and mode decides; without one, the mapping the hook had before: Codex CLI and Cursor's MCP tools refuse,
    Gemini CLI refuses unless --gemini-ask, Claude Code and Cursor's shell ask."""
    sem = guard.translation
    if sem is not None and harness != "cursor":  # Cursor has no measurement in the study (the free plan ran out)
        return sem.ask_reply(kind, guard.gemini_ask)
    if harness == "codex" or (harness == "cursor" and kind == "mcp"):
        return "deny", ""
    if harness == "gemini":
        return ("ask", "") if guard.gemini_ask else ("deny", "")
    return "ask", ""


# Codex CLI and Gemini CLI cannot ask the user, so an ask is a refusal, which agents retry unless told not to.
NO_RETRY = (" Do not retry this call or a variant of it: tell the user what you wanted to do and why, so they "
            "can decide.")
STOP_AFTER = 3  # refusals since the user's last prompt after which the Gemini hook ends the agent's turn
# Built-in tools guarded with --builtin-tools (Claude Code, Codex CLI and Gemini CLI names): their kind and
# the argument naming their target. Codex's shell tool has had several names.
_BUILTIN = {
    "Bash": ("shell", "command"), "shell": ("shell", "command"), "local_shell": ("shell", "command"),
    "exec_command": ("shell", "cmd"), "run_shell_command": ("shell", "command"),
    # Claude Code's other tools that run a shell command: PowerShell, and Monitor (a script whose output lines are events)
    "PowerShell": ("shell", "command"), "Monitor": ("shell", "command"),
    "WebFetch": ("fetch", "url"), "web_fetch": ("fetch", "prompt"),
    "WebSearch": ("search", "query"), "google_web_search": ("search", "query"),
    "Read": ("read", "file_path"), "read_file": ("read", "file_path"), "read_many_files": ("read", "include"),
    "Write": ("write", "file_path"), "write_file": ("write", "file_path"), "Edit": ("write", "file_path"),
    "MultiEdit": ("write", "file_path"), "replace": ("write", "file_path"), "NotebookEdit": ("write", "notebook_path"),
    "apply_patch": ("patch", "input"),  # Codex CLI's edit tool: the argument is a patch naming its files
    # Search tools that print what is in the files under ``path``. Their path is optional (the working directory). The tools that
    # only list names (Glob, LS, Gemini's list_directory and glob) are not guarded: they return no file content.
    "Grep": ("read", "path"), "search_file_content": ("read", "dir_path"), "grep_search": ("read", "dir_path"),
}


def _server_of(tool: str) -> str:
    """The server a tool's results are held to in the threat memory: "srv" of the hooks' "mcp__srv__tool" and of
    the proxy's "srv:tool". By the whole name, a server could give each result a new tool name and so a new
    quota of learned values."""
    if tool.startswith("mcp__") and "__" in tool[5:]:
        return tool[5:].partition("__")[0]
    return tool.partition(":")[0]
