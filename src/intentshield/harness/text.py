"""Text the hook stores, shows or reads: escaped for display, scrubbed of credentials, and cut to the length a session keeps."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from intentshield import credentials, translation


def _no_surrogates(value: Any) -> Any:
    """The event with lone surrogates replaced: JSON may carry one (half of a cut emoji), and SQLite and
    UTF-8 encoding refuse it, which lost the prompt or failed the hook."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode() if not value.isascii() else value
    if isinstance(value, list):
        return [_no_surrogates(v) for v in value]
    if isinstance(value, dict):
        return {_no_surrogates(k): _no_surrogates(v) for k, v in value.items()}
    return value


def _show(value: str, limit: int = 80) -> str:
    """A tool-derived value as it may appear in a reason the user or the agent reads: control and
    other non-printable characters escaped and the length capped, so an output cannot drive the
    terminal or flood the message."""
    shown = "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in value)
    return shown if len(shown) <= limit else shown[: limit - 1] + "…"


# The intent a session keeps, in characters: every hook of the session reads and scans all of it, at about 0.3 s
# per MB, so a long session of large pastes slowed each call. Past the limit the prompts in the middle go, oldest
# first: the first ``INTENT_HEAD`` characters (the task the session began with) and the rest of the limit, the
# newest, stay. About 80 pasted prompts of 2.6 KB, or thousands of typed ones, fit.
INTENT_LIMIT = 200_000
INTENT_HEAD = 20_000


def _private_dir(directory: Path) -> None:
    """Creates ``directory``, and keeps ``~/.intentshield`` (prompts, API keys, tool catalogs) readable by its owner only."""
    translation.private_dir(directory)


def _credential_mark(token: str) -> str:
    """What the stored prompt keeps in place of a credential the user pasted: a short hash, enough to tell later that the user
    gave this very value (``_given``) and no more than that."""
    return "[credential:" + hashlib.sha256(b"intentshield-credential\0" + token.encode()).hexdigest()[:20] + "]"


def _scrub_credentials(text: str) -> str:
    """``text`` with every credential in it (``credentials.find``) replaced by its mark, so that ``hooks.db`` does not keep an
    API key or token the user typed into a prompt."""
    for token in sorted(credentials.find(text), key=len, reverse=True):
        text = text.replace(token, _credential_mark(token))
    return text


def _given(token: str, intent: str) -> bool:
    """Whether the user's prompts gave this credential: as its mark, or as typed (a session stored before the scrub)."""
    return token in intent or _credential_mark(token) in intent


def _window(intent: str) -> str:
    return intent if len(intent) <= INTENT_LIMIT else \
        f"{intent[:INTENT_HEAD]}\n{intent[INTENT_HEAD - INTENT_LIMIT:]}"
