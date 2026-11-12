"""The built-in tools (``--builtin-tools``) and the MCP tools whose arguments name a command, a path or text to write."""
from __future__ import annotations

import shlex
import sys
from typing import TYPE_CHECKING, Any

from intentshield import dangerous, shell

from .sensitive import _PATCH_FILE, _PERSISTENT, _RESULT_META
from .verdict import _BUILTIN, Verdict

if TYPE_CHECKING:
    from .guard import HarnessGuard


_OPTIONAL_TARGET = frozenset({"Grep", "search_file_content", "grep_search"})
_PATH_FIELDS = ("absolute_path", "path", "dir_path", "paths", "file_path")


def _builtin_value(kind: str, field_name: str, arguments: dict[str, Any]) -> Any:
    """What a built-in tool call names as its target, as the harness sent it (None when the call has none)."""
    value = arguments.get(field_name)
    if value is None and kind == "shell":
        value = arguments.get("command") if field_name != "command" else arguments.get("cmd")
    if value is None and kind in ("read", "write"):
        value = next((arguments[k] for k in _PATH_FIELDS if arguments.get(k)), None)
    if value is None and set(arguments) == {"value"}:
        value = arguments["value"]  # tool_input that was a bare string, not an object
    return value


def _builtin_target(kind: str, field_name: str, arguments: dict[str, Any]) -> str:
    value = _builtin_value(kind, field_name, arguments)
    if isinstance(value, list):  # an argv (Codex: ["bash", "-lc", "..."]), or several paths
        if kind == "shell" and len(value) == 1:   # one word that holds a whole command line is that command line
            text = str(value[0])
        else:
            text = shlex.join(str(v) for v in value) if kind == "shell" else " ".join(str(v) for v in value)
    else:
        text = "" if value is None else str(value)
    return text.replace("\x00", "")  # bash ignores a NUL in a script, so the text is read without it


def _shape_problem(tool: str, arguments: dict[str, Any]) -> str:
    """Why the call of a built-in tool cannot be read, or "": the field that names what it runs, reads or writes is missing
    or is not a string (or a list, for an argv or several paths). A call that cannot be read must not pass as one with
    nothing in it."""
    kind, field_name = _BUILTIN[tool]
    if kind == "search":
        return ""
    if kind == "patch":
        values = [arguments.get(k) for k in (field_name, "command", "patch", "diff")]
        return "" if any(isinstance(v, (str, list)) and v for v in values) else "it carries no patch text"
    value = _builtin_value(kind, field_name, arguments)
    if value is None:
        return "" if tool in _OPTIONAL_TARGET else f"it has no {field_name!r} value"
    if kind == "shell" and isinstance(value, list):   # an argv of words: not empty, nothing but text, and not the whole input
        if not value or not all(isinstance(word, str) for word in value):
            return f"its {field_name!r} value is a list that is not made of words"
        if set(arguments) == {"value"}:
            return "its tool input is a list, not an object"
    return "" if isinstance(value, (str, list)) else f"its {field_name!r} value is not text"


def _builtin_content(arguments: dict[str, Any]) -> list[Any]:
    """What a write puts in the file: never the text it replaces."""
    content = [arguments[k] for k in ("content", "new_string", "new_source") if arguments.get(k) is not None]
    edits = arguments.get("edits")
    return content + ([e.get("new_string") for e in edits if isinstance(e, dict)] if isinstance(edits, list) else [])


def _builtin_result(response: Any) -> Any:
    """The part of a built-in tool's result the model reads: Bash's stdout and stderr, WebFetch's text, the content
    of a read file, search results. Its own metadata (the URL fetched, the path read) is not page content."""
    if not isinstance(response, dict):
        return response
    file = response.get("file")
    if isinstance(file, dict) and "content" in file:
        return file["content"]
    kept = {k: v for k, v in response.items() if k not in _RESULT_META and v not in ("", None, [], {})}
    return kept or response


def _builtin_source(kind: str, target: str) -> str:
    """Whom threat memory holds responsible for a built-in result: the site fetched, the file read, the exact
    command run. Never the tool as a whole, or one attack page would make every later read suspect."""
    if kind == "fetch":
        hosts = sorted(shell.network_values(target))
        return f"web:{shell.host(hosts[0])}" if hosts else "web"
    return f"{kind}:{target[:200]}"


def _builtin_local(kind: str, target: str) -> bool:
    """A result from the user's own machine: a file read, or a command that reached nothing remote. Web pages,
    search results, and what curl or gh brought back are someone else's text."""
    return kind == "read" or (kind == "shell" and not shell.parse(target).remote)


def _patch_verdict(guard: HarnessGuard, session: str, label: str, patch: str) -> Verdict:
    """The verdict on a patch: every file it names is a write of what the patch adds."""
    added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
    paths = [(a or b).strip() for a, b in _PATCH_FILE.findall(patch)] or [""]
    # One database read per file would make a huge patch slow: the path rules are plain patterns, so only the
    # files they fire on, and one of the rest (for what the patch adds), go to the guard.
    special = [p for p in dict.fromkeys(paths) if _PERSISTENT.search(p.replace("\\", "/")) or shell.SECRET.search(p)
               or dangerous.path_risk(p)]
    verdicts = [guard.file(session, label, path, added, write=True) for path in special[:8] + paths[:1]]
    for path in special[8:]:  # past the eight the guard reads one by one, the rules still read each file
        hit = dangerous.assess_file(path, added, write=True, cwd=guard.cwd, homes=guard.homes)
        if hit:
            verdicts.append(Verdict(hit.decision, f"IntentShield: {hit.reason}"))
    return next((v for v in sorted(verdicts, key=lambda v: v.decision != "deny") if v.decision != "allow"), verdicts[0])


def _builtin_call(guard: HarnessGuard, session: str, tool: str, arguments: dict[str, Any]) -> Verdict | None:
    """The verdict on a built-in tool call, or None when it is not one the guard reads before it runs."""
    kind, field_name = _BUILTIN[tool]
    if problem := _shape_problem(tool, arguments):
        reason = (f"IntentShield could not read this {tool} call ({problem}), so it is refused rather than let through "
                  "unchecked; update IntentShield or the harness.")
        print(reason, file=sys.stderr)
        return Verdict("deny", reason)
    target = _builtin_target(kind, field_name, arguments)
    label = f"builtin:{tool}"
    if kind == "shell":
        verdict = guard.shell(session, label, target)
        if verdict.decision != "deny" and "apply_patch" in target and _PATCH_FILE.search(target):
            # apply_patch run from the shell tool (a here-document, or the patch as its argument): the files it names are writes
            patched = _patch_verdict(guard, session, label, target)
            if patched.decision == "deny" or patched.decision == "ask" and verdict.decision == "allow":
                return patched
        return verdict
    if kind == "fetch":
        return guard.fetch(session, label, target)
    if kind in ("read", "write"):
        return guard.file(session, label, target, _builtin_content(arguments), write=kind == "write")
    if kind == "patch":  # every file it names is a write, of what the patch adds
        values = [arguments.get(k) for k in (field_name, "command", "patch", "diff")]
        # Codex may pass the command as a list: ["apply_patch", "*** Begin Patch ..."]
        pieces = [x for v in values for x in (v if isinstance(v, list) else [v]) if isinstance(x, str)]
        return _patch_verdict(guard, session, label, "\n".join(str(x) for x in pieces))
    return None
