"""Entry points that print one line, not a traceback, when a package this command needs is not installed.

``pip install --no-deps intentshield-mcp`` leaves only the standard library: the hooks, ``install``, ``uninstall``, ``doctor``
and ``scan --no-connect`` run on it. The other commands (the proxy, ``wrap``, the dashboard, ``scan`` with a connection, the
verifier) need the packages the normal install brings."""
from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from typing import Any

# The packages intentshield-mcp depends on (import name -> name on PyPI). Only these are explained: any other missing module is a
# different problem and keeps its traceback.
_DEPENDENCIES = {"fastapi": "fastapi", "uvicorn": "uvicorn", "mcp": "mcp", "pydantic": "pydantic", "jsonschema": "jsonschema",
                 "dotenv": "python-dotenv", "anyio": "anyio", "starlette": "starlette", "httpx2": "httpx2"}


def missing_package(exc: BaseException) -> str | None:
    """The PyPI name of the dependency that ``exc`` (a ModuleNotFoundError) says is missing, else None."""
    if not isinstance(exc, ModuleNotFoundError):
        return None
    return _DEPENDENCIES.get((exc.name or "").partition(".")[0])


def explain(package: str) -> str:
    return (f"intentshield: this command needs the package '{package}', which is not installed (a --no-deps install has only the "
            "hooks, install, uninstall, doctor, demo, wrap-hook and scan --no-connect). "
            "Install everything with: pip install intentshield-mcp")


def guarded(run: Callable[[], Any]) -> Any:
    """``run()``, or a one-line message on stderr and exit status 2 when it needs a package that is not installed."""
    try:
        return run()
    except ModuleNotFoundError as exc:
        package = missing_package(exc)
        if package is None:
            raise
        print(explain(package), file=sys.stderr)
        raise SystemExit(2) from None


def _entry(module: str, function: str = "main") -> Callable[[], Any]:
    def run() -> Any:
        return guarded(lambda: getattr(importlib.import_module(f"intentshield.{module}"), function)())

    run.__name__ = f"{module}_{function}"
    return run


mcp = _entry("mcp_server")
demo_mcp = _entry("demo_mcp_server")
mcp_verify = _entry("mcp_verify")
evaluation = _entry("evaluation")
threats = _entry("threat_memory")
