"""The API key and endpoint of a hosted judge, kept in ``~/.intentshield/.env``."""
from __future__ import annotations

import getpass
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from .records import _private_dir

_KEY_FOR = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
            "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY", "custom": "INTENTSHIELD_JUDGE_API_KEY"}


def ensure_judge_key(judge: str, home: Path | None = None, api_key: str | None = None,
                     ask: Callable[[str], str] = getpass.getpass, judge_url: str | None = None,
                     dry_run: bool = False) -> Path | None:
    """The key a hosted judge needs, stored in ``~/.intentshield/.env`` (0600) where every hook
    process reads it. A key that is only exported in this shell is stored too, since a harness started
    elsewhere would not have it. Asks on the terminal when it is neither given nor set. A custom
    judge's endpoint (``judge_url``) is stored beside it. Returns the file written, or None when
    nothing was needed. With ``dry_run`` the arguments are checked exactly as for a real install (a custom judge's
    endpoint, ``--judge-url`` on another judge) but nothing is stored, asked for or printed."""
    provider = judge.partition(":")[0]
    env = _KEY_FOR.get(provider)
    if env is None:  # ollama: local, no key
        return None
    if provider == "custom":
        from intentshield.judge import JUDGE_URL_ENV, checked_judge_url
        if judge_url:
            checked = checked_judge_url(judge_url)
            if not dry_run:
                _store_env(home, JUDGE_URL_ENV, checked)
        elif not _read_env(home).get(JUDGE_URL_ENV):
            if not os.getenv(JUDGE_URL_ENV):
                raise ValueError("--judge custom needs --judge-url <OpenAI-compatible chat completions URL>")
            # Exported in this shell only: stored, and checked now, like the key (a hook does not see this shell).
            checked = checked_judge_url(os.environ[JUDGE_URL_ENV])
            if not dry_run:
                stored_url = _store_env(home, JUDGE_URL_ENV, checked)
                print(f"{JUDGE_URL_ENV} is set in this shell only; storing it in {stored_url}, which every hook reads")
    elif judge_url:
        raise ValueError("--judge-url is for --judge custom only")
    stored = _read_env(home)
    if not api_key and stored.get(env):
        return None
    if dry_run:  # what a real install would fail on without a terminal to ask at
        if not api_key and not os.getenv(env) and not sys.stdin.isatty() and ask is getpass.getpass:
            raise ValueError(f"{env} is not set; pass --api-key or export it before `install --judge {provider}`")
        return None
    path = _env_path(home)
    if not api_key and os.getenv(env):
        # Exported in this shell. A hook runs as a child of the harness, and one started from the Dock or an IDE
        # does not inherit this shell's variables, so the key is stored where every hook reads it.
        api_key = os.environ[env]
        print(f"{env} is set in this shell only; storing it in {path}, which every hook reads "
              "(a harness started from the Dock or an IDE does not see this shell's variables)")
    if not api_key:
        if ask is getpass.getpass and not sys.stdin.isatty():
            raise ValueError(f"{env} is not set; pass --api-key or export it before `install --judge {provider}`")
        api_key = ask(f"{env} for the {provider} judge (stored in {path}, never printed): ").strip()
        if not api_key:
            raise ValueError(f"no {env} given")
    return _store_env(home, env, api_key)


def _env_path(home: Path | None) -> Path:
    path = (home or Path.home()) / ".intentshield" / ".env"
    if path.is_symlink():  # the key would land wherever the link points
        raise ValueError(f"{path} is a symbolic link; replace it with a regular file before storing a key")
    return path


def _read_env(home: Path | None) -> dict[str, str]:
    path = _env_path(home)
    stored = {}
    for line in (path.read_text(encoding="utf-8").splitlines() if path.exists() else []):
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            stored[key] = value
    return stored


def _store_env(home: Path | None, env: str, value: str) -> Path:
    """Sets one KEY=value line in ``~/.intentshield/.env`` (0600), every other line as it was."""
    if "\n" in value or "\r" in value:
        raise ValueError(f"{env} must be one line")
    path = _env_path(home)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    stored = _read_env(home)
    # Every other line (comments, other keys) stays as it was; only this key's line changes.
    entry = f"{env}={value}"
    replaced = [entry if line.strip().partition("=")[0] == env else line for line in lines]
    lines = replaced if env in stored else [*lines, entry]
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".env.")  # created 0600: the key is never readable by others
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    print(f"stored {env} in {path}")
    return path
