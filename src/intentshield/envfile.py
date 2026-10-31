"""Loading ``.env`` files without letting a repository's file choose what runs or who may approve."""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from typing import Any, Callable

from dotenv import dotenv_values, find_dotenv

# A ``.env`` found by searching (the working directory, a parent of the package) may be a cloned repository's.
# Its API keys and model names load as before. What names code to start, where data is sent or kept, a model or
# pack to load, how a process finds its certificates or proxy, or the credential that guards approvals comes from
# the environment or from ``~/.intentshield/.env``, as ``scan`` treats a repository's MCP config
# (``--connect-project``).
TRUSTED_ONLY = frozenset({
    "INTENTSHIELD_PROXY_CONFIG", "INTENTSHIELD_CONTROL_TOKEN", "INTENTSHIELD_AGENT_TOKEN", "INTENTSHIELD_JUDGE_URL",
    "OLLAMA_HOST", "INTENTSHIELD_INTENT_MODEL_DIR", "INTENTSHIELD_THREAT_PACKS", "INTENTSHIELD_PACK_PINS",
    "INTENTSHIELD_PACK_HMAC_KEY", "INTENTSHIELD_PACK_HMAC_KEY_FILE", "INTENTSHIELD_PACK_ED25519_KEYS",
    "INTENTSHIELD_DB", "INTENTSHIELD_THREAT_DB", "INTENTSHIELD_THREAT_MEMORY", "INTENTSHIELD_RATE_LIMIT_PER_MIN",
})
# By prefix: every other INTENTSHIELD_ setting that is not a key or a plain option, and the variables through which
# a process picks up a proxy, a CA bundle, a loader or an interpreter option (compared in upper case).
_TRUSTED_PREFIXES = ("INTENTSHIELD_PACK_", "INTENTSHIELD_THREAT_", "INTENTSHIELD_HOOK_", "NODE_", "PYTHON", "LD_",
                     "DYLD_", "SSL_", "XDG_")
_TRUSTED_PROCESS = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "PATH", "HOME", "USERPROFILE", "SHELL", "TMPDIR", "TEMP", "TMP", "GIT_SSH_COMMAND", "BROWSER", "EDITOR",
})


def trusted_only(name: str, extra: frozenset[str] = frozenset()) -> bool:
    upper = name.upper()
    return (name in TRUSTED_ONLY or name in extra or upper in _TRUSTED_PROCESS or upper.startswith(_TRUSTED_PREFIXES)
            or upper.endswith("_PROXY"))


def load_environment(load: Callable[..., Any], *, usecwd: bool = False,
                     extra: frozenset[str] = frozenset()) -> list[str]:
    """Load ``~/.intentshield/.env`` whole, then the nearest ``.env`` (the working directory's with ``usecwd``)
    minus the trusted-only names (``extra``: more, such as a custom token variable), never overriding what is
    exported. ``load`` is dotenv's ``load_dotenv``. The names left out are returned and named on stderr, with the
    file."""
    trusted = Path.home() / ".intentshield" / ".env"
    if trusted.is_file():
        load(trusted)
    found = find_dotenv(usecwd=usecwd)
    if not found or Path(found).resolve() == trusted.resolve():
        return []
    values = {k: v for k, v in dotenv_values(found).items() if v is not None}
    refused = sorted(k for k, v in values.items() if trusted_only(k, extra) and v.strip() and k not in os.environ)
    if refused:
        print(f"intentshield: ignored {', '.join(refused)} from {found}: a .env found by searching cannot set "
              f"these; export them or put them in {trusted}", file=sys.stderr)
    stream = io.StringIO("".join(f"{k}={_quoted(v)}\n" for k, v in values.items() if not trusted_only(k, extra)))
    load(stream=stream)
    return refused


def _quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def require_tokens(refused: list[str], names: tuple[str, ...]) -> None:
    """A token that only a repository's ``.env`` held was ignored: starting without it would leave what it guards
    open, so stop and say where to put it."""
    missing = [name for name in names if name in refused and not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError(f"{', '.join(missing)} was set only in a .env found by searching, which cannot set it: "
                         f"export it or put it in {Path.home() / '.intentshield' / '.env'}")
