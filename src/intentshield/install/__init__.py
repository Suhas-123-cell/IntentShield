"""Install IntentShield into an agent harness, or wrap MCP servers in the transparent proxy.

    intentshield install claude|codex|cursor|gemini [--scope user|project]
    intentshield uninstall claude|codex|cursor|gemini [--scope user|project]
    intentshield wrap <mcp config JSON> [--server NAME ...]
    intentshield unwrap <mcp config JSON> [--server NAME ...]

``install`` merges the hook entries (the same ones as ``configs/harness/``) into the harness's own
settings file, naming the ``intentshield-hook`` executable that sits next to this interpreter, so
the harness finds it without PATH changes. ``wrap`` rewrites every stdio server in an
``mcpServers`` file (Claude Code ``.mcp.json``, Cursor ``mcp.json``, Gemini CLI ``settings.json``,
or any client that uses that layout) to launch ``intentshield-mcp --transparent`` in front of it,
with one generated proxy config per server. Both are idempotent and reversible. Only the standard
library is imported, so the commands start fast.

The package is split along its seams: ``hooks`` (the hook entries and the command each runs), ``judgekey`` (the judge's key),
``textedit`` (JSON with comments, TOML), ``records`` (the atomic write, backups, the record of installs), ``settings``
(``install`` and ``uninstall``), ``wrapping`` (``wrap`` and ``unwrap``) and ``cli``. Every name of the former ``install.py``
is still importable from here.
"""
from __future__ import annotations

import shutil  # noqa: F401  (tests patch install.shutil and install.sys)
import sys
import types

from intentshield import translation  # noqa: F401

from . import hooks, records
from .cli import (
    add_subcommands,
    run,
)
from .hooks import (
    _BUILTIN_CALLS,
    _BUILTIN_RESULTS,
    _EPHEMERAL,
    _HOOK,
    _JUDGE_SPEC,
    _MCP_MATCHER,
    _NEEDS_MODEL,
    _PROXY,
    HARNESSES,
    _hook_flags,
    _our_commands,
    _ours,
    _refuse_ephemeral,
    _say_what_was_replaced,
    _without_ours,
    codex_toml,
    ephemeral_location,
    executable,
    hook_command,
    hook_entries,
    merge_hooks,
    remove_hooks,
    settings_path,
)
from .judgekey import (
    _KEY_FOR,
    _env_path,
    _read_env,
    _store_env,
    ensure_judge_key,
)
from .records import (
    _COMMENTED,
    _SEEN,
    ChangedMeanwhile,
    _backup_holds_servers,
    _backup_path,
    _client_data,
    _exact_text,
    _has_comments,
    _installs_path,
    _is_toml,
    _json_text,
    _keep_original,
    _NotJSON,
    _parse,
    _private_dir,
    _read_client,
    _read_json,
    _record_install,
    _remember_servers,
    _undone_text,
    _undone_toml,
    _without_empty_hooks,
    _write,
    installed_at,
)
from .settings import (
    NEXT_STEP,
    _holds_our_hooks,
    _uninstall_file,
    client_config_files,
    codex_hooks_switched_off,
    install,
    legacy_project_settings,
    uninstall,
)
from .textedit import (
    _TOML_ANY_HEADER,
    _TOML_BEGIN,
    _TOML_END,
    _TOML_HEADER,
    _drop_trailing_commas,
    _strip_toml_block,
    _toml_path,
    _toml_set,
    _toml_value_end,
    strip_json_comments,
)
from .wrapping import (
    _INTERPOLATION,
    _SERVER_ID,
    SUPPORTED,
    Wrapped,
    _backed_up_server,
    _entry_problem,
    _in_repository,
    _inside,
    _interpolated,
    _is_wrapped,
    _label,
    _no_servers,
    _plan_wrap,
    _require_file,
    _say_wrapped,
    _server_groups,
    proxy_config,
    server_stem,
    unwrap,
    wrap,
)

__all__ = [
    "ChangedMeanwhile",
    "HARNESSES",
    "NEXT_STEP",
    "SUPPORTED",
    "Wrapped",
    "_BUILTIN_CALLS",
    "_BUILTIN_RESULTS",
    "_COMMENTED",
    "_EPHEMERAL",
    "_HOOK",
    "_INTERPOLATION",
    "_JUDGE_SPEC",
    "_KEY_FOR",
    "_MCP_MATCHER",
    "_NEEDS_MODEL",
    "_NotJSON",
    "_PROXY",
    "_SEEN",
    "_SERVER_ID",
    "_TOML_ANY_HEADER",
    "_TOML_BEGIN",
    "_TOML_END",
    "_TOML_HEADER",
    "_backed_up_server",
    "_backup_holds_servers",
    "_backup_path",
    "_client_data",
    "_drop_trailing_commas",
    "_entry_problem",
    "_env_path",
    "_exact_text",
    "_has_comments",
    "_holds_our_hooks",
    "_hook_flags",
    "_in_repository",
    "_inside",
    "_installs_path",
    "_interpolated",
    "_is_toml",
    "_is_wrapped",
    "_json_text",
    "_keep_original",
    "_label",
    "_no_servers",
    "_our_commands",
    "_ours",
    "_parse",
    "_plan_wrap",
    "_private_dir",
    "_read_client",
    "_read_env",
    "_read_json",
    "_record_install",
    "_refuse_ephemeral",
    "_remember_servers",
    "_require_file",
    "_say_what_was_replaced",
    "_say_wrapped",
    "_server_groups",
    "_store_env",
    "_strip_toml_block",
    "_toml_path",
    "_toml_set",
    "_toml_value_end",
    "_undone_text",
    "_undone_toml",
    "_uninstall_file",
    "_without_empty_hooks",
    "_without_ours",
    "_write",
    "add_subcommands",
    "client_config_files",
    "codex_hooks_switched_off",
    "codex_toml",
    "ensure_judge_key",
    "ephemeral_location",
    "executable",
    "hook_command",
    "hook_entries",
    "install",
    "installed_at",
    "legacy_project_settings",
    "merge_hooks",
    "proxy_config",
    "remove_hooks",
    "run",
    "server_stem",
    "settings_path",
    "strip_json_comments",
    "uninstall",
    "unwrap",
    "wrap",
]


class _Package(types.ModuleType):
    """``intentshield.install`` as one module, whose settable names are also set where the code that uses them lives: a name
    patched here (``install._write``, ``install._json_text``, ``install.executable``) reaches the install and wrap code."""

    def __setattr__(self, name: str, value: object) -> None:
        owner = _PATCHABLE.get(name)
        if owner is not None:
            setattr(owner, name, value)
        super().__setattr__(name, value)


# The functions the other modules call as ``records._write(...)`` and ``hooks.executable(...)``, so that one assignment is enough.
_PATCHABLE = {"_write": records, "_json_text": records, "executable": hooks}
sys.modules[__name__].__class__ = _Package
