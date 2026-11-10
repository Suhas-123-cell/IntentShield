"""The Codex ``trusted-persisted`` hook state: the trust record a person creates through ``/hooks``, written without a TUI.

Codex skips a non-managed hook until it is trusted: ``[hooks.state."<key>"] trusted_hash = "<hash>"`` in config.toml, where the
key and the hash are computed by Codex itself (key ``<config.toml>:pre_tool_use:<group>:<handler>``, hash ``sha256:...`` over
the normalised hook definition). Re-implementing the hash would be a guess, so the recipe asks the vendor's own loader: the
app-server ``hooks/list`` request (JSON-RPC lines over stdio, present from 0.128.0) returns each discovered hook with its
``key``, ``currentHash``, ``enabled`` and ``trustStatus``. The recipe then appends one ``[hooks.state]`` table per hook to the
run's own config.toml and the exec run is started WITHOUT ``--dangerously-bypass-hook-trust``. The app-server is started with
the run's isolated environment (and whatever egress proxy the run uses); it needs no model and no key.

Not run here, no launches: this module only builds the request lines and the TOML; ``run.py`` starts the app-server.
"""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import time
from pathlib import Path

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "hook-fidelity", "version": "0"}}}
INITIALIZED = {"jsonrpc": "2.0", "method": "initialized"}


def hooks_list_request(cwd: Path) -> dict:
    return {"jsonrpc": "2.0", "id": 2, "method": "hooks/list", "params": {"cwds": [str(cwd)]}}


def trust_toml(entries: list[dict]) -> str:
    """One ``[hooks.state."<key>"]`` table per discovered non-managed hook (the vendor's key and current hash, verbatim)."""
    out = ""
    for entry in entries:
        if entry.get("isManaged"):
            continue
        out += f"\n[hooks.state.{json.dumps(entry['key'])}]\ntrusted_hash = {json.dumps(entry['currentHash'])}\n"
    return out


def entries_of(response: dict | None) -> list[dict]:
    """The hook entries of a hooks/list response (every cwd), or [] for a missing or malformed one."""
    try:
        return [h for item in response["result"]["data"] for h in item["hooks"]]
    except (KeyError, TypeError):
        return []


def list_hooks(binary: list[str], env: dict[str, str], cwd: Path, timeout: float = 30.0) -> list[dict]:
    """Start ``<binary> app-server`` in ``cwd`` with ``env``, do the handshake, ask for hooks/list, kill the process group."""
    proc = subprocess.Popen([*binary, "app-server"], cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, start_new_session=True)

    def send(message: dict) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    def receive(want: int) -> dict | None:
        assert proc.stdout is not None
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ready, _, _ = select.select([proc.stdout], [], [], 0.5)
            if not ready:
                continue
            line = proc.stdout.readline()
            if not line:
                return None
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == want:
                return message
        return None

    try:
        send(INIT)
        if receive(1) is None:
            return []
        send(INITIALIZED)
        send(hooks_list_request(cwd))
        return entries_of(receive(2))
    except (OSError, ValueError):
        return []
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
