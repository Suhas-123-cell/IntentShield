"""IntentShield as a hook in agent harnesses that call MCP tools.

Harnesses (Claude Code, Codex CLI, Cursor, Gemini CLI) run a command at fixed points:
when the user submits a prompt, before a tool call and after it. Those hooks see what
the model cannot forge: the user's real prompt and every MCP call and result. This
package keeps per-session state across hook processes and applies the call and output
layers there; tool descriptions are guarded by the transparent proxy
(``intentshield-mcp --transparent``), which hooks never see.

    intentshield-hook claude|codex|cursor|gemini      # reads the event on stdin

It imports only the standard library and ``mcp_inspect`` so each hook starts fast.
"""
from __future__ import annotations

import threading
import time

from intentshield import credentials, translation

from .builtin import _patch_verdict
from .cli import _LOOSENING_ENV, MAX_DEADLINE, _arm_deadline, _env_seconds, loosening_env, main
from .env import ENV_FILE, load_env_file
from .events import handle
from .guard import _READ_LIMIT, _READ_STRINGS, JUDGE_PAUSE, RESULT_SCAN_CHARS, HarnessGuard
from .store import FLAGGED_TTL, SESSION_TTL, SessionStore
from .text import INTENT_HEAD, INTENT_LIMIT, _no_surrogates
from .verdict import _BUILTIN, NO_RETRY, STOP_AFTER, Verdict, _ask_as, is_mutation

# A global that a test replaces lives in the module whose code reads it: ``ENV_FILE`` in ``env``, ``RESULT_SCAN_CHARS`` and
# ``scan_output`` in ``guard``, ``handle``, ``HarnessGuard`` and ``_arm_deadline`` in ``cli`` (``main`` reads them there).
# Replacing the copy named here changes nothing.

__all__ = [
    "ENV_FILE",
    "FLAGGED_TTL",
    "HarnessGuard",
    "INTENT_HEAD",
    "INTENT_LIMIT",
    "JUDGE_PAUSE",
    "MAX_DEADLINE",
    "NO_RETRY",
    "RESULT_SCAN_CHARS",
    "SESSION_TTL",
    "STOP_AFTER",
    "SessionStore",
    "Verdict",
    "credentials",
    "handle",
    "is_mutation",
    "load_env_file",
    "loosening_env",
    "main",
    "threading",
    "time",
    "translation",
    "_BUILTIN",
    "_LOOSENING_ENV",
    "_READ_LIMIT",
    "_READ_STRINGS",
    "_arm_deadline",
    "_ask_as",
    "_env_seconds",
    "_no_surrogates",
    "_patch_verdict",
]
