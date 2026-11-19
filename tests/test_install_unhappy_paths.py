"""What a stranger meets when the machine is not as the README assumes, and the shape of the ``install`` package."""
from __future__ import annotations

import argparse
import errno
import json
import os
import re
import tempfile
from pathlib import Path

import pytest

from intentshield import install
from intentshield.install import cli, records, wrapping

GATEWAY = "https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md#real-mcp-proxy"


@pytest.fixture(autouse=True)
def _no_harness_probe(monkeypatch):
    monkeypatch.setattr(install.translation, "probe_and_record", lambda *args, **kwargs: None)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


def _args(command: str, **fields) -> argparse.Namespace:
    defaults = {"harness": "claude", "scope": "user", "review": None, "dry_run": False, "judge": None, "api_key": None,
                "judge_url": None, "judge_outputs": False, "builtin_tools": False, "gemini_ask": False, "no_translate": True,
                "allow_ephemeral": True, "servers": None, "out_dir": None}
    return argparse.Namespace(command=command, **{**defaults, **fields})


# --- the documents a message names ---------------------------------------------------------------------------------------

def test_no_message_names_a_document_by_a_path_the_wheel_does_not_have():
    """The wheel carries no docs/ directory: a message that sends the reader to one gives the GitHub address."""
    for source in sorted(Path(install.__file__).parent.glob("*.py")):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            for found in re.finditer(r"(?<![/\w])docs/[\w.-]+\.md", line):
                assert line[:found.start()].endswith("main/"), f"{source.name}:{number}: {line.strip()}"


def test_every_message_that_cites_the_gateway_document_gives_its_full_address(tmp_path: Path, home: Path, capsys, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    empty = tmp_path / "e.json"
    empty.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="no servers wrap can read") as caught:
        install.wrap(empty, out_dir=tmp_path / "out")
    assert GATEWAY in str(caught.value)
    toml = tmp_path / "bad.toml"
    toml.write_text("= broken", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid TOML") as caught:
        install.wrap(toml, out_dir=tmp_path / "out")
    assert GATEWAY in str(caught.value)
    inline = tmp_path / "inline.toml"
    inline.write_text('[mcp_servers]\nnotes = { command = "n" }\n', encoding="utf-8")
    install.wrap(inline, out_dir=tmp_path / "out", proxy="/opt/bin/intentshield-mcp")
    assert f"(see {GATEWAY})" in capsys.readouterr().out
    http = tmp_path / "h.json"
    http.write_text(json.dumps({"mcpServers": {"h": {"url": "http://example.test"}}}), encoding="utf-8")
    install.wrap(http, out_dir=tmp_path / "out", proxy="/opt/bin/intentshield-mcp")
    assert GATEWAY in capsys.readouterr().out


# --- a file that does not parse ------------------------------------------------------------------------------------------

def test_wrap_gives_advice_that_fits_wrap_for_a_file_that_is_not_json(tmp_path: Path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{ bad json", encoding="utf-8")
    assert cli.run(_args("wrap", config=bad)) == 1
    err = capsys.readouterr().err
    assert "is not valid JSON" in err and GATEWAY in err and "run the command again" in err
    assert "install <harness> --dry-run" not in err, "that prints hook entries, which a wrap does not need"
    assert bad.read_text(encoding="utf-8") == "{ bad json"


def test_unwrap_and_wrap_of_commented_json_say_to_remove_the_comments(tmp_path: Path, capsys):
    commented = tmp_path / ".mcp.json"
    commented.write_text('// mine\n{"mcpServers": {"a": {"command": "x"}}}', encoding="utf-8")
    assert cli.run(_args("unwrap", config=commented)) == 1
    err = capsys.readouterr().err
    assert "remove its comments and trailing commas" in err and GATEWAY in err


def test_a_syntax_error_without_comments_is_not_blamed_on_comments(tmp_path: Path):
    settings = tmp_path / "s.json"
    settings.write_text('{"model": "x" "y": 1}', encoding="utf-8")
    with pytest.raises(ValueError) as caught:
        records._read_json(settings)
    assert "fix the syntax error at that position" in str(caught.value) and "comments" not in str(caught.value)


def test_install_keeps_its_advice_and_uninstall_does_not_ask_for_entries_to_add(home: Path, capsys, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text("// note\n{}", encoding="utf-8")
    assert cli.run(_args("install")) == 1
    assert "`intentshield install claude --dry-run`" in capsys.readouterr().err
    assert cli.run(_args("uninstall")) == 1
    err = capsys.readouterr().err
    assert "remove the entries whose command runs intentshield-hook by hand" in err and "--dry-run" not in err


# --- the machine is not as expected --------------------------------------------------------------------------------------

def test_a_home_that_cannot_be_written_is_named_with_what_to_do(home: Path, capsys, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    real = tempfile.mkstemp

    def refuse(*args, **kwargs):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(kwargs.get("dir")))

    monkeypatch.setattr(tempfile, "mkstemp", refuse)
    code = cli.run(_args("install"))
    monkeypatch.setattr(tempfile, "mkstemp", real)
    err = capsys.readouterr().err
    assert code == 1
    assert f"cannot use {home / '.claude'} (Permission denied)" in err, "the directory, not a temporary file in it"
    assert "readable and writable by you" in err and "[Errno" not in err
    assert not (home / ".claude" / "settings.json").exists()


def test_a_read_only_home_on_a_real_file_system(home: Path, capsys, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("root can write to a read-only directory")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    home.chmod(0o555)
    try:
        assert cli.run(_args("install")) == 1
        assert "readable and writable by you" in capsys.readouterr().err
        mcp = home / "none.json"
        assert cli.run(_args("wrap", config=mcp)) == 1
    finally:
        home.chmod(0o755)


def test_a_file_that_changed_meanwhile_keeps_its_own_message(capsys):
    error = records.ChangedMeanwhile("x.json changed while IntentShield was editing it")
    assert cli._explain(error) == "x.json changed while IntentShield was editing it"
    assert cli._explain(OSError(errno.ENOENT, "No such file", "y.json")).startswith("[Errno 2]")


def test_a_missing_claude_binary_is_named(home: Path, capsys):
    install.install("claude", home=home, cwd=home, hook="/opt/bin/intentshield-hook")
    out = capsys.readouterr().out
    assert "could not read the version of claude (it is not on PATH, or its --version printed no number" in out
    assert "Put it on PATH" in out and "blocked instead, which is the safe side" in out


def test_a_missing_cursor_binary_is_named_by_the_program_that_was_looked_for(home: Path, capsys):
    install.install("cursor", home=home, cwd=home, hook="/opt/bin/intentshield-hook")
    out = capsys.readouterr().out
    assert "could not read the version of cursor (`cursor-agent` is not on PATH, or its --version printed no number" in out
    assert "records it once `cursor-agent` is on PATH" in out


# --- Claude Code's built-in tools ----------------------------------------------------------------------------------------

def test_a_search_result_is_scanned_like_a_read_result_with_builtin_tools():
    entries = install.hook_entries("claude", "intentshield-hook claude --builtin-tools", builtin_tools=True, translate=False)
    for event in ("PostToolUse", "PostToolUseFailure"):
        matcher = entries[event][0]["matcher"]
        assert re.fullmatch(matcher, "Grep") and re.fullmatch(matcher, "Read") and re.fullmatch(matcher, "mcp__srv__tool")
    assert re.fullmatch(entries["PreToolUse"][0]["matcher"], "Grep")
    plain = install.hook_entries("claude", "intentshield-hook claude", translate=False)
    assert not re.fullmatch(plain["PostToolUse"][0]["matcher"], "Grep"), "without --builtin-tools only MCP results are read"


# --- long names ----------------------------------------------------------------------------------------------------------

def test_a_server_with_a_very_long_name_is_wrapped_and_unwrapped(tmp_path: Path, home: Path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    name = "a" * 400
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {name: {"command": "srv", "args": ["--x"]}, "short": {"command": "s"}}}),
        encoding="utf-8")
    out = tmp_path / "proxies"
    wrapped = install.wrap(mcp, out_dir=out, proxy="/opt/bin/intentshield-mcp")
    assert sorted(wrapped) == sorted([name, "short"])
    names = [p.name for p in out.iterdir()]
    assert names and all(len(n) <= 120 for n in names), names
    install.unwrap(mcp)
    assert json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"][name] == {"command": "srv", "args": ["--x"]}


def test_a_stem_is_cut_and_stays_unique(tmp_path: Path):
    one, two = "a" * 300, "a" * 299 + "b"
    assert len(wrapping.server_stem(one)) <= wrapping._MAX_STEM + 9 and wrapping.server_stem(one) != wrapping.server_stem(two)
    assert wrapping.server_stem("plain-name") == "plain-name", "an ordinary name is unchanged"
    assert wrapping.server_stem("a" * wrapping._MAX_STEM) == "a" * wrapping._MAX_STEM
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", wrapping.server_stem("../../" + "x" * 500, tmp_path / ".mcp.json"))


# --- the package keeps the names of the module it was split from ---------------------------------------------------------

def test_every_name_the_package_lists_can_be_imported():
    missing = [name for name in install.__all__ if not hasattr(install, name)]
    assert missing == []
    for name in ("install", "uninstall", "wrap", "unwrap", "hook_command", "hook_entries", "ensure_judge_key", "settings_path",
                 "strip_json_comments", "proxy_config", "server_stem", "codex_toml", "add_subcommands", "run", "HARNESSES",
                 "ChangedMeanwhile", "client_config_files", "legacy_project_settings", "installed_at", "executable",
                 "ephemeral_location", "NEXT_STEP", "_ours", "_toml_set", "_read_client", "_server_groups", "_backup_path"):
        assert callable(getattr(install, name)) or name in ("HARNESSES", "NEXT_STEP"), name


def test_a_function_patched_on_the_package_is_the_one_the_code_calls(tmp_path: Path, home: Path, monkeypatch):
    """Tests and callers replace ``install._write``, ``install._json_text`` and ``install.executable``."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    seen: list[str] = []
    real = install._write

    def spy(path, text, dry_run):
        seen.append(path.name)
        return real(path, text, dry_run)

    monkeypatch.setattr(install, "_write", spy)
    install.install("claude", home=home, cwd=tmp_path, hook="/opt/bin/intentshield-hook", translate=False)
    assert "settings.json" in seen
    monkeypatch.setattr(install, "executable", lambda name: f"/patched/{name}")
    install.uninstall("claude", home=home, cwd=tmp_path)
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}), encoding="utf-8")
    install.wrap(mcp, out_dir=tmp_path / "out")
    assert json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]["a"]["command"] == "/patched/intentshield-mcp"


def test_the_patch_of_a_package_name_is_undone_where_it_was_applied(monkeypatch):
    real = install._write
    with monkeypatch.context() as patch:
        patch.setattr(install, "_write", lambda *args: None)
        assert records._write is not real
    assert install._write is real and records._write is real
