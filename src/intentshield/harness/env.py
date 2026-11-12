"""The API keys ``intentshield install --judge`` stored, read into the environment."""
from __future__ import annotations

import os
from pathlib import Path

ENV_FILE = Path.home() / ".intentshield" / ".env"  # API keys `intentshield install --judge` stored


def load_env_file(path: Path | None = None) -> None:
    """KEY=VALUE lines into the environment, for keys not already set. No dotenv dependency:
    the hook imports only the standard library. ``ENV_FILE`` is read at call time so a test
    or an operator can point it elsewhere."""
    try:
        lines = (path or ENV_FILE).read_text(errors="replace").splitlines()
    except OSError:
        return
    for line in lines:
        key, sep, value = line.strip().removeprefix("export ").partition("=")
        key = key.strip()
        if sep and key and not key.startswith("#") and key not in os.environ:
            os.environ[key] = value.strip().strip("'\"")
