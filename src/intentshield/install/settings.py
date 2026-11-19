"""``install`` and ``uninstall``: the hooks in a harness's settings file."""
from __future__ import annotations

import getpass
import json
import re
import time
import tomllib
from collections.abc import Callable
from pathlib import Path

from intentshield import translation

# ``records._write``, ``records._json_text`` and ``hooks.executable`` are called through their modules, not imported by name, so a
# name patched on the ``intentshield.install`` package (see its ``__init__``) is the one used here.
from . import hooks, records
from .hooks import (
    _HOOK,
    _our_commands,
    _refuse_ephemeral,
    _say_what_was_replaced,
    codex_toml,
    hook_command,
    hook_entries,
    merge_hooks,
    relocated_config_advice,
    relocated_config_dir,
    remove_hooks,
    settings_path,
)
from .judgekey import ensure_judge_key
from .records import (
    _BY_HAND_UNINSTALL,
    _backup_holds_servers,
    _backup_path,
    _exact_text,
    _keep_original,
    _read_json,
    _record_install,
    _undone_text,
    _undone_toml,
)
from .textedit import _TOML_BEGIN, _TOML_END, _strip_toml_block


def install(harness: str, scope: str = "user", review: str | None = None, hook: str | None = None,
            dry_run: bool = False, home: Path | None = None, cwd: Path | None = None,
            judge: str | None = None, api_key: str | None = None,
            ask: Callable[[str], str] = getpass.getpass,
            judge_outputs: bool = False, builtin_tools: bool = False, gemini_ask: bool = False,
            judge_url: str | None = None, translate: bool = True, allow_ephemeral: bool = False) -> Path:
    """Register the hooks in the harness's settings file. Returns the file touched. With ``translate`` (the default) the hooks
    that check a call carry the hook's own deadline and the fail-closed launcher (translation.py), and the harness's version
    is recorded for the hook."""
    path = settings_path(harness, scope, home, cwd)
    legacy = legacy_project_settings(harness, cwd) if scope == "project" else None
    if legacy is not None and _holds_our_hooks(legacy):
        # Both files are read by Claude Code, so a hook left in the shared one would run next to the new one.
        _uninstall_file(harness, legacy, dry_run, home)
    hook = hook or hooks.executable(_HOOK)
    _refuse_ephemeral(hook, "hook command", dry_run, allow_ephemeral)
    command = hook_command(harness, hook, review, judge, judge_outputs, builtin_tools, gemini_ask,
                           deadline=translation.DEFAULT_DEADLINE_S if translate else None)
    if judge:  # after the spec is checked, so a refused --judge stores nothing; a dry run checks the same, stores nothing
        ensure_judge_key(judge, home, api_key, ask, judge_url, dry_run=dry_run)
    elif judge_url:
        raise ValueError("--judge-url is for --judge custom only")
    if harness == "codex":
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        try:
            tomllib.loads(text)  # refuse to append to a file Codex could not read either
        except tomllib.TOMLDecodeError as exc:
            if dry_run:  # the error below points at this output, so it must not end with nothing printed
                print(f"--- would add to {path} (not written: the file does not parse, so merge this block by hand)\n"
                      f"{codex_toml(command, builtin_tools, translate)}", end="")
            raise ValueError(f"{path} is not valid TOML ({exc}); Codex CLI cannot read it either. Fix it, then run `intentshield "
                             "install codex` again (`--dry-run` prints the block it adds)") from None
        stripped, had_block = _strip_toml_block(text)  # replace an earlier block instead of stacking a second
        new = (stripped.rstrip("\n") + "\n\n" if stripped.strip() else "") + codex_toml(command, builtin_tools, translate)
        tomllib.loads(new)
        if new == text:
            print(f"already installed: {path}")
            return path
        if had_block:
            block = text[text.find(_TOML_BEGIN):text.find(_TOML_END)]
            _say_what_was_replaced([json.loads(c) for c in re.findall(r'^command = (".*")\s*$', block, re.M)], command,
                                   harness, scope, dry_run)
        _keep_original(path, home, dry_run)
        records._write(path, new, dry_run)
        if not dry_run:
            _record_install(path, home, time.time())
    else:
        existed = path.exists()
        try:
            current = _read_json(path, records._BY_HAND_DRY_RUN if dry_run else records._BY_HAND_HOOKS)
            previous = _our_commands(current)
            settings, changed = merge_hooks(current, hook_entries(harness, command, builtin_tools, translate))
        except ValueError as exc:
            if isinstance(exc, json.JSONDecodeError):
                if dry_run:  # the error below points at this output, so it must not end with nothing printed
                    print(f"--- would add to {path} (not written: the file does not parse, so merge these entries by hand)\n"
                          + records._json_text({"hooks": hook_entries(harness, command, builtin_tools, translate)}), end="")
                raise records._NotJSON(str(exc).replace("install <harness>", f"install {harness}"), exc) from None
            if str(path) in str(exc):
                raise
            raise ValueError(f"{path}: {exc}") from None
        if not changed:
            print(f"already installed: {path}")
            return path
        if previous:
            _say_what_was_replaced(previous, command, harness, scope, dry_run)
        if harness == "cursor" and not existed:  # a file Cursor wrote already has it; uninstall restores theirs
            settings.setdefault("version", 1)
        _keep_original(path, home, dry_run)
        records._write(path, records._json_text(settings), dry_run)
        if not dry_run:
            _record_install(path, home, time.time())
    print(f"{'would install' if dry_run else 'installed'} {harness} hooks in {path}")
    if scope == "user" and (moved := relocated_config_dir(harness, home)):
        print("warning: " + relocated_config_advice(harness, *moved, path))
    if translate and not dry_run:
        _record_version(harness, home, gemini_ask)
    if harness == "codex" and (switched_off := codex_hooks_switched_off(path)):
        print(f"warning: {path} has `{switched_off} = false` under [features], which can switch Codex's hooks off, so these "
              "hooks may not run. Remove that line or set it to true.")
    if harness == "codex":
        # Measured 2026-10-29 with Codex CLI 0.165: hooks nobody has trusted are skipped, and the
        # session runs unguarded with no warning from Codex.
        print("Codex runs a new hook only after you trust it: start `codex` once and approve the IntentShield "
              "hooks when it asks. Until then Codex is NOT guarded by them.")
    if scope == "project" and not dry_run:
        print(f"note: {path} now holds absolute paths of this machine (the hook command): do not commit it, and do not share it "
              "with a team that has the tools elsewhere.")
    if not builtin_tools:
        print("This guards MCP calls only, not the shell or the file tools. To guard those too: "
              f"intentshield install {harness} --builtin-tools")
    if not dry_run:
        print(f"Next: {NEXT_STEP.format(harness=harness)} Until the harness has run a hook, `doctor` says \"no hook has run "
              "yet\" as a warning: that is expected right after an install.")
    return path


def _record_version(harness: str, home: Path | None, gemini_ask: bool) -> None:
    """Reads the harness's version (it can take up to 20 s) and says what was found. Only Claude Code, and Gemini CLI with
    --gemini-ask, send an ask as a prompt by the version; for the others it changes no verdict."""
    program = translation._PROCESS.get(harness, harness)  # Cursor's command line program is `cursor-agent`
    print(f"reading the version of {harness} (`{program} --version`, up to 20 s) ...", flush=True)
    seen = translation.probe_and_record(harness, home)
    if seen:
        print(f"{harness} version {'.'.join(map(str, seen))} found and recorded, so the hook answers in the way that "
              "version expects (`intentshield doctor` shows what is measured)")
        return
    it = "it" if program == harness else f"`{program}`"
    why = f"{it} is not on PATH, or its --version printed no number or did not answer within 20 s"
    if harness == "claude" or (harness == "gemini" and gemini_ask):
        print(f"IntentShield could not read the version of {harness} ({why}), so a call that would normally "
              f"ask you is blocked instead, which is the safe side. Put {it} on PATH and run `intentshield doctor` to "
              "record the version.")
    else:
        print(f"IntentShield could not read the version of {harness} ({why}). The hook's verdicts for {harness} do not "
              f"depend on it, so nothing changes; `intentshield doctor` records it once {it} is on PATH.")


def codex_hooks_switched_off(path: Path) -> str:
    """The name of the ``[features]`` flag (``codex_hooks`` or ``hooks``) that is false in Codex's config file, or "". Codex's
    feature flags can switch its hooks off, and then the hooks installed here do not run."""
    try:
        features = tomllib.loads(path.read_text(encoding="utf-8")).get("features")
    except (OSError, ValueError):
        return ""
    if isinstance(features, dict):
        return next((name for name in ("codex_hooks", "hooks") if features.get(name) is False), "")
    return ""


def client_config_files(home: Path, cwd: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """(user files, project files): the MCP client config files ``doctor`` reads, those of the user's home and those of the
    current directory. A server wrapped in any other file is not found by it."""
    return ((home / ".claude.json", home / ".cursor" / "mcp.json", home / ".gemini" / "settings.json",
             home / ".codex" / "config.toml"),
            (cwd / ".mcp.json", cwd / ".cursor" / "mcp.json", cwd / ".gemini" / "settings.json", cwd / ".vscode" / "mcp.json"))


def legacy_project_settings(harness: str, cwd: Path | None = None) -> Path | None:
    """The shared ``.claude/settings.json`` of the project, where 0.4.3 and earlier wrote Claude Code's project-scope hooks (now
    ``settings.local.json``); None for any other harness."""
    return (cwd or Path.cwd()) / ".claude" / "settings.json" if harness == "claude" else None


def _holds_our_hooks(path: Path) -> bool:
    try:
        return path.exists() and bool(_our_commands(_read_json(path)))
    except ValueError:
        return False


def uninstall(harness: str, scope: str = "user", dry_run: bool = False,
              home: Path | None = None, cwd: Path | None = None) -> Path:
    path = settings_path(harness, scope, home, cwd)
    legacy = legacy_project_settings(harness, cwd) if scope == "project" else None
    if legacy is not None and _holds_our_hooks(legacy):
        _uninstall_file(harness, legacy, dry_run, home)  # a hook an earlier version put in the shared file
    return _uninstall_file(harness, path, dry_run, home)


def _uninstall_file(harness: str, path: Path, dry_run: bool, home: Path | None) -> Path:
    if not path.exists():
        print(f"nothing to remove: {path}")
        return path
    backup = _backup_path(path, home)  # this install is being undone either way
    existed_before = backup.exists()  # the file was there before the first install: it is put back, not deleted
    if harness == "codex":
        text, changed = _strip_toml_block(_exact_text(path))
        if changed:
            text, _ = _undone_toml(path, text, home)
    else:
        settings, changed = remove_hooks(_read_json(path, _BY_HAND_UNINSTALL))
        text, _ = _undone_text(path, settings, home)
    if not changed:
        print(f"nothing to remove: {path}")
        return path
    emptied = not text.strip() or text.strip() in ("{}", json.dumps({"version": 1}, indent=2))
    if emptied and not existed_before and not path.is_symlink():  # a file only `install` created: leave nothing behind
        if not dry_run:
            path.unlink()
            backup.unlink(missing_ok=True)
            _record_install(path, home)
        print(f"{'would remove' if dry_run else 'removed'} {path} (it held only IntentShield's hooks)")
        return path
    records._write(path, text, dry_run)
    if not dry_run:
        if not _backup_holds_servers(backup):  # wrap's record of the servers it rewrote is still needed
            backup.unlink(missing_ok=True)
        _record_install(path, home)
    print(f"{'would remove' if dry_run else 'removed'} {harness} hooks from {path}")
    return path


NEXT_STEP = "Start {harness} and send any prompt, then run `intentshield doctor`."
