"""What `intentshield doctor`, `install`, `wrap` and `unwrap` say and do."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path

import pytest

from intentshield import doctor, install
from intentshield.harness import HarnessGuard, handle


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    """A home directory of its own: wrap and unwrap keep their backups under Path.home()."""
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))
    for key in ("GROQ_API_KEY", "GEMINI_API_KEY", "INTENTSHIELD_JUDGE_URL"):
        monkeypatch.delenv(key, raising=False)
    return path


def _exe(tmp_path: Path, shebang: str = "#!/bin/sh") -> str:
    exe = tmp_path / "bin" / "intentshield-hook"
    exe.parent.mkdir(exist_ok=True)
    exe.write_text(shebang + "\n")
    exe.chmod(0o755)
    return str(exe)


def _db(home: Path) -> Path:
    return home / ".intentshield" / "hooks.db"


def _ran(db: Path, harness: str, when: float, cwd: str | None = None) -> None:
    db.parent.mkdir(parents=True, exist_ok=True)
    HarnessGuard(db).close()
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT OR REPLACE INTO harness_events VALUES (?, ?)", (harness, when))
        if cwd:
            conn.execute("INSERT OR REPLACE INTO harness_dirs VALUES (?, ?, ?)", (harness, cwd, when))


def _doctor(home: Path, cwd: Path, capsys) -> tuple[int, str]:
    rc = doctor.doctor(home, cwd, _db(home))
    return rc, capsys.readouterr().out


# --- hooks-11: a hook whose interpreter is gone -------------------------------------------------------------

def test_doctor_fails_a_hook_executable_with_a_dead_shebang(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path, "#!/nonexistent/venv/bin/python"), translate=False)
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "#!/nonexistent/venv/bin/python" in out and "exits 126" in out
    # a hook installed without the launcher: the call runs unguarded in Claude Code (and refused behind the launcher: see
    # tests/test_harness_translation.py for Gemini CLI's own boundary at 0.30.0)
    assert "Claude Code runs the call unguarded" in out


@pytest.mark.parametrize("shebang", ["#!/bin/sh", "#!/usr/bin/env sh", ""])
def test_doctor_passes_a_hook_executable_whose_interpreter_exists(tmp_path: Path, home: Path, capsys, shebang):
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path, shebang))
    _ran(_db(home), "claude", time.time() + 5)
    assert _doctor(home, cwd, capsys)[0] == 0


def test_doctor_fails_an_env_shebang_for_a_program_that_is_not_on_path(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path, "#!/usr/bin/env no-such-interpreter-xyz"), translate=False)
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "no-such-interpreter-xyz" in out


@pytest.mark.parametrize("body", [
    "\'\'\'exec\' \"/nonexistent dir/venv/bin/python\" \"$0\" \"$@\"\n\' \'\'\'\nprint(1)\n",
    "exec /nonexistent/venv/bin/python -m intentshield \"$@\"\n",
])
def test_doctor_fails_a_shell_wrapper_that_execs_a_missing_interpreter(tmp_path: Path, home: Path, capsys, body):
    cwd = tmp_path / "work"
    cwd.mkdir()
    exe = _exe(tmp_path)
    Path(exe).write_text("#!/bin/sh\n" + body)
    install.install("claude", home=home, cwd=cwd, hook=exe, translate=False)
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "/nonexistent" in out and "does not exist" in out
    assert "ok   claude" not in out  # one verdict per harness, not a FAIL and an ok


def test_doctor_passes_a_shell_wrapper_that_execs_an_existing_interpreter(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    exe = _exe(tmp_path)
    Path(exe).write_text('#!/bin/sh\n# exec /nonexistent/in-a-comment\nexec /bin/sh -c true "$@"\n')
    install.install("claude", home=home, cwd=cwd, hook=exe)
    _ran(_db(home), "claude", time.time() + 5)
    assert _doctor(home, cwd, capsys)[0] == 0


# --- hooks-12: evidence that the hooks ran -------------------------------------------------------------------

def test_an_unrelated_settings_edit_does_not_make_doctor_fail(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    path = install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5)
    assert _doctor(home, cwd, capsys)[0] == 0
    data = json.loads(path.read_text())
    data["model"] = "sonnet"
    path.write_text(json.dumps(data))
    os.utime(path, (time.time() + 60, time.time() + 60))  # the edit is newer than the last hook run
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 0 and "ok   claude" in out


def test_a_project_install_needs_a_hook_run_inside_the_project(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", "project", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5, cwd=str(tmp_path / "elsewhere"))  # ran, but in another project
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "no hook has run" in out
    _ran(_db(home), "claude", time.time() + 6, cwd=str(cwd / "src"))
    assert _doctor(home, cwd, capsys)[0] == 0


def test_the_hook_records_the_directory_it_ran_in(tmp_path: Path):
    g = HarnessGuard(tmp_path / "hooks.db")
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "hi", "cwd": "/work/proj"}, g)
    assert g.db.execute("SELECT harness, cwd FROM harness_dirs").fetchall() == [("claude", "/work/proj")]


def test_doctor_fails_hooks_that_claude_code_is_told_not_to_run(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    path = install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5)
    data = json.loads(path.read_text())
    data["disableAllHooks"] = True
    path.write_text(json.dumps(data))
    os.utime(path, (time.time() - 60, time.time() - 60))
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "disableAllHooks is true" in out


def test_doctor_fails_a_matcher_that_matches_no_mcp_tool(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    path = install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5)
    data = json.loads(path.read_text())
    data["hooks"]["PreToolUse"][0]["matcher"] = "NoSuchTool"
    path.write_text(json.dumps(data))
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "does not match MCP tools" in out


# --- hooks-13: wrap and ${...} -------------------------------------------------------------------------------

def test_wrap_leaves_a_server_alone_whose_command_line_uses_interpolation(tmp_path: Path, home: Path, capsys):
    mcp = tmp_path / ".mcp.json"
    servers = {"fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "${HOME}/data", "${workspaceFolder}"]},
               "tool": {"command": "${TOOLS}/bin/server"},
               "ok": {"command": "plain-server", "args": ["--port", "1"], "env": {"TOKEN": "${TOKEN}"}}}
    mcp.write_text(json.dumps({"mcpServers": servers}))
    out_dir = tmp_path / "proxies"
    assert install.wrap(mcp, out_dir=out_dir) == ["ok"]
    wrapped = json.loads(mcp.read_text())["mcpServers"]
    assert wrapped["fs"] == servers["fs"] and wrapped["tool"] == servers["tool"]  # as they were: the client expands them
    assert wrapped["ok"]["env"] == {"TOKEN": "${TOKEN}"} and wrapped["ok"]["args"][0] == "--transparent"
    out = capsys.readouterr().out
    assert "skipped fs" in out and "skipped tool" in out and "interpolation" in out
    assert len(list(out_dir.glob("*.json"))) == 1  # no generated config holds the literal ${HOME}


@pytest.mark.parametrize("arg", ["$HOME/data", "$PROJECT_DIR", "%USERPROFILE%\\x"])
def test_wrap_leaves_a_server_alone_whose_args_use_a_bare_variable(tmp_path: Path, home: Path, capsys, arg):
    mcp = tmp_path / "settings.json"
    mcp.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "srv", arg]},
                                              "re": {"command": "srv", "args": ["--pattern", "^a.*$", "$(pwd)", "~/x"]}}}))
    assert install.wrap(mcp, out_dir=tmp_path / "proxies") == ["re"]
    assert json.loads(mcp.read_text())["mcpServers"]["fs"]["args"] == ["-y", "srv", arg]
    assert "skipped fs" in capsys.readouterr().out


def test_doctor_accepts_a_matcher_the_user_narrowed_to_one_server(tmp_path: Path, home: Path, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    path = install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5)
    data = json.loads(path.read_text())
    data["hooks"]["PreToolUse"][0]["matcher"] = "mcp__github__.*"
    path.write_text(json.dumps(data))
    assert _doctor(home, cwd, capsys)[0] == 0


# --- hooks-14: unwrap without the generated config ---------------------------------------------------------

def _wrapped(tmp_path: Path) -> tuple[Path, dict]:
    mcp = tmp_path / ".mcp.json"
    original = {"command": "demo-server", "args": ["--root", "/srv/data"], "env": {"A": "1"}}
    mcp.write_text(json.dumps({"mcpServers": {"demo": original}}, indent=2))
    install.wrap(mcp, out_dir=tmp_path / "proxies")
    return mcp, original


def test_unwrap_restores_the_entry_from_the_backup_when_the_generated_config_is_gone(tmp_path: Path, home: Path, capsys):
    mcp, original = _wrapped(tmp_path)
    for config in (tmp_path / "proxies").glob("*.json"):
        config.unlink()
    assert install.unwrap(mcp) == ["demo"]
    assert json.loads(mcp.read_text())["mcpServers"]["demo"] == original


def test_unwrap_says_what_is_missing_when_nothing_can_restore_the_entry(tmp_path: Path, home: Path, capsys):
    mcp, _ = _wrapped(tmp_path)
    for config in (tmp_path / "proxies").glob("*.json"):
        config.unlink()
    for backup in (home / ".intentshield" / "backups").glob("*.json"):
        backup.unlink()
    before = mcp.read_text()
    with pytest.raises(ValueError, match="cannot restore demo .*proxy config .* missing.*Edit .* by hand"):
        install.unwrap(mcp)
    assert mcp.read_text() == before
    cli = type("Args", (), {"command": "unwrap", "config": mcp, "servers": None, "dry_run": False})
    assert install.run(cli) == 1


def test_doctor_points_at_the_backup_when_the_proxy_config_is_gone(tmp_path: Path, home: Path, capsys):
    mcp, _ = _wrapped(tmp_path)
    for config in (tmp_path / "proxies").glob("*.json"):
        config.unlink()
    out = _doctor(home, mcp.parent, capsys)[1]
    assert "restores it from" in out and "backups" in out
    for backup in (home / ".intentshield" / "backups").glob("*.json"):
        backup.unlink()
    assert "edit" in _doctor(home, mcp.parent, capsys)[1]


def test_unwrap_restores_the_command_of_the_latest_wrap_not_of_the_first(tmp_path: Path, home: Path):
    mcp, _ = _wrapped(tmp_path)
    data = json.loads(mcp.read_text())
    data["mcpServers"]["demo"] = {"command": "npx", "args": ["-y", "srv", "Y"]}  # the user replaced the server
    mcp.write_text(json.dumps(data))
    install.wrap(mcp, out_dir=tmp_path / "proxies")
    for config in (tmp_path / "proxies").glob("*.json"):
        config.unlink()
    assert install.unwrap(mcp) == ["demo"]
    assert json.loads(mcp.read_text())["mcpServers"]["demo"] == {"command": "npx", "args": ["-y", "srv", "Y"]}


def test_doctor_does_not_promise_a_restore_the_backup_cannot_make(tmp_path: Path, home: Path, capsys):
    mcp, _ = _wrapped(tmp_path)
    data = json.loads(mcp.read_text())
    data["mcpServers"]["renamed"] = data["mcpServers"].pop("demo")  # the backup knows no entry of this name
    mcp.write_text(json.dumps(data))
    for config in (tmp_path / "proxies").glob("*.json"):
        config.unlink()
    out = _doctor(home, mcp.parent, capsys)[1]
    assert "renamed" in out and "restores it from" not in out and "by hand" in out
    with pytest.raises(ValueError, match="cannot restore renamed"):
        install.unwrap(mcp)


# --- hooks-17: Gemini settings with comments ------------------------------------------------------------------

COMMENTED = '{\n  // my theme\n  "theme": "dark", /* inline */\n  "homepage": "http://example.test//x"\n}\n'


def test_comments_are_stripped_outside_strings_only():
    assert json.loads(install.strip_json_comments(COMMENTED)) == {"theme": "dark", "homepage": "http://example.test//x"}
    assert install.strip_json_comments('{"a": "/* not */ // a comment"}') == '{"a": "/* not */ // a comment"}'


def test_install_reads_a_commented_gemini_settings_file_and_uninstall_restores_it_exactly(tmp_path: Path, home: Path, capsys):
    path = home / ".gemini" / "settings.json"
    path.parent.mkdir()
    path.write_text(COMMENTED)
    install.install("gemini", home=home, hook=_exe(tmp_path))
    captured = capsys.readouterr()
    assert "has comments" in captured.err and "BeforeTool" in path.read_text()
    assert json.loads(path.read_text())["theme"] == "dark"
    install.uninstall("gemini", home=home)
    assert path.read_text() == COMMENTED


def test_doctor_reads_a_commented_gemini_settings_file(tmp_path: Path, home: Path, capsys):
    path = home / ".gemini" / "settings.json"
    path.parent.mkdir()
    path.write_text("// installed by hand\n" + json.dumps({"hooks": {event: [{"matcher": ".*", "hooks": [
        {"type": "command", "command": f"{_exe(tmp_path)} gemini"}]}] for event in doctor.REQUIRED["gemini"]}}))
    _ran(_db(home), "gemini", time.time() + 5)
    rc, out = _doctor(home, tmp_path, capsys)
    assert rc == 0 and "cannot read" not in out


def test_claude_settings_with_comments_are_still_refused(tmp_path: Path, home: Path):
    path = home / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text(COMMENTED)
    with pytest.raises(ValueError, match="not valid JSON"):
        install.install("claude", home=home, hook=_exe(tmp_path))


# --- hooks-18: the judge's key -------------------------------------------------------------------------------

def test_a_key_only_in_the_installing_shell_is_stored_for_the_hooks(tmp_path: Path, home: Path, monkeypatch, capsys):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_shell_only_value")
    path = install.ensure_judge_key("groq", home)
    assert path == home / ".intentshield" / ".env" and "GROQ_API_KEY=gsk_shell_only_value" in path.read_text()
    out = capsys.readouterr().out
    assert "set in this shell only" in out and "gsk_shell_only_value" not in out


def test_doctor_does_not_take_the_shell_environment_as_proof_that_the_hook_has_a_key(tmp_path: Path, home: Path,
                                                                                    monkeypatch, capsys):
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path), judge="groq", api_key="gsk_stored")
    (home / ".intentshield" / ".env").unlink()  # the key was never stored
    _ran(_db(home), "claude", time.time() + 5)
    monkeypatch.setenv("GROQ_API_KEY", "gsk_shell")
    rc, out = _doctor(home, cwd, capsys)
    assert "warn claude" in out and "this shell only" in out and "ok   claude" not in out.split("warn")[0]
    monkeypatch.delenv("GROQ_API_KEY")
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "FAIL claude" in out and "no GROQ_API_KEY" in out
    install.ensure_judge_key("groq", home, api_key="gsk_stored")
    assert _doctor(home, cwd, capsys)[0] == 0


def test_a_custom_judge_url_only_in_the_installing_shell_is_stored_and_checked(tmp_path: Path, home: Path,
                                                                              monkeypatch, capsys):
    monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", "https://judge.example/v1/chat/completions")
    path = install.ensure_judge_key("custom:m", home, api_key="k-1")
    text = path.read_text()
    assert "INTENTSHIELD_JUDGE_URL=https://judge.example/v1/chat/completions" in text and "INTENTSHIELD_JUDGE_API_KEY=k-1" in text
    assert "INTENTSHIELD_JUDGE_URL is set in this shell only" in capsys.readouterr().out
    monkeypatch.setenv("INTENTSHIELD_JUDGE_URL", "http://attacker.example/v1")  # not https, not localhost
    with pytest.raises(ValueError, match="https"):
        install.ensure_judge_key("custom:m", home / "other", api_key="k-1")
    monkeypatch.delenv("INTENTSHIELD_JUDGE_URL")
    with pytest.raises(ValueError, match="--judge-url"):
        install.ensure_judge_key("custom:m", home / "third", api_key="k-1")


# --- what the lines say and how often -------------------------------------------------------------------------------------

def test_a_missing_hook_executable_is_one_line_and_one_problem(tmp_path: Path, home: Path, capsys, monkeypatch):
    monkeypatch.setattr(doctor, "_harness_version", lambda harness, home: (2, 1, 316))
    cwd = tmp_path / "work"
    cwd.mkdir()
    exe = _exe(tmp_path)
    install.install("claude", home=home, cwd=cwd, hook=exe)  # the default install puts the launcher in front of every call hook
    Path(exe).unlink()
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1
    assert out.count("does not exist") == 1
    assert "\n1 problem(s)" in out


def test_facts_about_the_harness_are_notes_and_a_clean_install_prints_no_warning(tmp_path: Path, home: Path, capsys, monkeypatch):
    monkeypatch.setattr(doctor, "_harness_version", lambda harness, home: (2, 1, 316))
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path))
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 0
    lines = out.splitlines()
    assert any(line.startswith("note claude") and "prints nothing or malformed JSON" in line for line in lines)
    assert not any(line.startswith(("warn", "FAIL")) for line in lines)
    assert any(line.startswith("ok   claude") for line in lines)
    assert "need no action" in out and "no problems found" in out


def test_a_setting_of_the_users_that_has_a_cost_stays_a_warning(tmp_path: Path, home: Path, capsys, monkeypatch):
    monkeypatch.setattr(doctor, "_harness_version", lambda harness, home: (0, 66, 0))
    cwd = tmp_path / "work"
    cwd.mkdir()
    install.install("gemini", home=home, cwd=cwd, hook=_exe(tmp_path), gemini_ask=True)
    _ran(_db(home), "gemini", time.time() + 5)
    _rc, out = _doctor(home, cwd, capsys)
    assert any(line.startswith("warn gemini") and "--gemini-ask is on" in line for line in out.splitlines())
    assert re.search(r"no problems found, \d+ warning\(s\) above", out)  # the summary does not hide the warning


def test_the_module_text_names_no_flag_that_the_command_does_not_have(capsys):
    assert "--home" not in doctor.__doc__
    parser = __import__("argparse").ArgumentParser()
    sub = parser.add_subparsers()
    doctor.add_subcommand(sub)
    with pytest.raises(SystemExit):
        parser.parse_args(["doctor", "--home", "x"])
    capsys.readouterr()
    flags = {"--db"}
    for word in doctor.__doc__.split():
        if word.startswith("--") and word.rstrip("].,)") not in flags:
            raise AssertionError(f"doctor's text names {word}")


# --- Codex config.toml and VS Code files: wrap and unwrap ------------------------------------------------------------------

CODEX_TOML = '''# my Codex config
model = "gpt-5"   # the default

[mcp_servers.fs]   # files
command = "npx"
args = ["-y", "@mcp/fs", "/tmp"]

[mcp_servers.fs.env]
TOKEN = "t"

[mcp_servers."my server"]
args = [
  "serve",
  "a]b",
]
command = "node"   # no args line above this one
cwd = "/srv"

[mcp_servers.plain]
command = "uvx"

[mcp_servers.web]
url = "https://mcp.example.org/mcp"

[profiles.fast]
model = "gpt-5-mini"
'''


def _servers(path: Path) -> dict:
    import tomllib

    return tomllib.loads(path.read_text()).get("mcp_servers", {})


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_wrap_and_unwrap_edit_codex_tables_and_restore_the_file_byte_for_byte(tmp_path: Path, home: Path, capsys, eol: str):
    path = tmp_path / "config.toml"
    before = CODEX_TOML.replace("\n", eol)
    path.write_bytes(before.encode())
    done = install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp")
    assert done == ["fs", "my server", "plain"]
    servers = _servers(path)
    for name in done:
        assert servers[name]["command"] == "/bin/intentshield-mcp" and servers[name]["args"][:2] == ["--transparent", "--config"]
    assert servers["web"] == {"url": "https://mcp.example.org/mcp"}  # not a stdio server
    assert servers["my server"]["cwd"] == "/srv" and servers["fs"]["env"] == {"TOKEN": "t"}
    text = path.read_bytes().decode()
    assert text.count("# files") == 1 and "# my Codex config" in text and "[profiles.fast]" in text  # the rest is as it was
    assert install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp") == []  # idempotent
    assert install.unwrap(path) == ["fs", "my server", "plain"]
    assert path.read_bytes() == before.encode()


def test_unwrap_of_a_codex_table_the_user_edited_meanwhile_restores_the_command_and_keeps_the_edit(tmp_path: Path, home: Path):
    path = tmp_path / "config.toml"
    path.write_text(CODEX_TOML)
    install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp")
    path.write_text(path.read_text().replace('model = "gpt-5"', 'model = "gpt-6"'))
    install.unwrap(path)
    servers = _servers(path)
    assert servers["fs"]["command"] == "npx" and servers["fs"]["args"] == ["-y", "@mcp/fs", "/tmp"]
    assert "args" not in servers["plain"] and servers["plain"]["command"] == "uvx"
    assert 'model = "gpt-6"' in path.read_text()


def test_a_codex_entry_that_is_not_a_table_of_its_own_is_skipped_with_what_to_do(tmp_path: Path, home: Path, capsys):
    path = tmp_path / "config.toml"
    path.write_text('[mcp_servers]\nfs = { command = "npx", args = ["x"] }\n\n[mcp_servers.ok]\ncommand = "uvx"\n')
    assert install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp") == ["ok"]
    out = capsys.readouterr().out
    assert "skipped fs" in out and "[mcp_servers.NAME] table" in out and "--transparent" in out
    assert _servers(path)["fs"] == {"command": "npx", "args": ["x"]}


def test_a_toml_file_with_no_codex_servers_names_the_formats_wrap_reads(tmp_path: Path, home: Path):
    path = tmp_path / "other.toml"
    path.write_text('model = "x"\n')
    with pytest.raises(ValueError) as exc:
        install.wrap(path, out_dir=tmp_path / "proxies")
    message = str(exc.value)
    for named in ("mcpServers", "servers", "mcp.servers", "[mcp_servers.NAME]", "Codex CLI", "--transparent --config"):
        assert named in message
    assert not (tmp_path / "proxies").exists()


def test_a_toml_file_that_does_not_parse_is_refused_and_untouched(tmp_path: Path, home: Path):
    path = tmp_path / "config.toml"
    path.write_text('[mcp_servers.fs\ncommand = "npx"\n')
    with pytest.raises(ValueError, match="not valid TOML"):
        install.wrap(path, out_dir=tmp_path / "proxies")
    assert path.read_text() == '[mcp_servers.fs\ncommand = "npx"\n'


VSCODE_JSON = '''// MCP servers of this workspace
{
  "servers": {
    "fs": {"type": "stdio", "command": "npx", "args": ["-y", "@mcp/fs"], "env": {"A": "${input:key}"}},
    "remote": {"type": "http", "url": "https://mcp.example.org/mcp"}, /* hosted */
  },
  "inputs": [{"id": "key", "type": "promptString"}]
}
'''


def test_wrap_and_unwrap_read_the_servers_key_of_a_vscode_file_and_restore_it_byte_for_byte(tmp_path: Path, home: Path):
    path = tmp_path / ".vscode" / "mcp.json"
    path.parent.mkdir()
    path.write_text(VSCODE_JSON)
    assert install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp") == ["fs"]
    data = json.loads(path.read_text())
    assert data["servers"]["fs"]["command"] == "/bin/intentshield-mcp" and data["servers"]["fs"]["env"] == {"A": "${input:key}"}
    assert data["servers"]["remote"]["url"] == "https://mcp.example.org/mcp" and data["inputs"][0]["id"] == "key"
    assert install.unwrap(path) == ["fs"]
    assert path.read_text() == VSCODE_JSON


def test_wrap_reads_mcp_servers_of_a_vscode_settings_file(tmp_path: Path, home: Path):
    path = tmp_path / "settings.json"
    before = json.dumps({"editor.fontSize": 14, "mcp": {"servers": {"fs": {"command": "npx", "args": ["x"]}}}}, indent=2) + "\n"
    path.write_text(before)
    assert install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp") == ["fs"]
    assert json.loads(path.read_text())["mcp"]["servers"]["fs"]["command"] == "/bin/intentshield-mcp"
    install.unwrap(path)
    assert path.read_text() == before


def test_a_file_with_both_keys_wraps_each_server_under_its_own_config(tmp_path: Path, home: Path):
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}, "servers": {"a": {"command": "y"}}}))
    assert install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp") == ["a", "a [servers]"]
    configs = {json.loads(path.read_text())[key]["a"]["args"][2] for key in ("mcpServers", "servers")}
    assert len(configs) == 2
    install.unwrap(path)
    assert json.loads(path.read_text()) == {"mcpServers": {"a": {"command": "x"}}, "servers": {"a": {"command": "y"}}}


def test_a_json_file_with_no_servers_names_the_formats_wrap_reads(tmp_path: Path, home: Path):
    path = tmp_path / "x.json"
    path.write_text('{"theme": "dark"}')
    with pytest.raises(ValueError) as exc:
        install.wrap(path, out_dir=tmp_path / "proxies")
    assert "Codex CLI" in str(exc.value) and "VS Code" in str(exc.value) and "Windsurf" in str(exc.value)


def test_a_missing_file_points_at_the_claude_json_for_servers_added_by_the_cli(tmp_path: Path, home: Path):
    with pytest.raises(FileNotFoundError, match=r"~/\.claude\.json"):
        install.wrap(tmp_path / ".mcp.json")


def test_the_same_server_name_in_two_client_files_has_its_own_proxy_config_and_audit_database(tmp_path: Path, home: Path):
    for name, command in (("a.json", "serverA"), ("b.json", "serverB")):
        (tmp_path / name).write_text(json.dumps({"mcpServers": {"github": {"command": command}}}))
        install.wrap(tmp_path / name, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp")
    configs = [json.loads(Path(json.loads((tmp_path / n).read_text())["mcpServers"]["github"]["args"][2]).read_text())
               for n in ("a.json", "b.json")]
    assert configs[0]["database_path"] != configs[1]["database_path"]
    assert {c["upstreams"][0]["server_id"] for c in configs} == {"github"}  # the hook finds the tool catalog by this name


# --- an install and its undoing give the file back as it was -------------------------------------------------------------------

@pytest.mark.parametrize("original", [b'{\r\n  "a": 1\r\n}\r\n', b"", b"{}", b"{}\n", b'{\n\t"a": 1\n}'])
@pytest.mark.parametrize("harness", ["claude", "cursor", "gemini"])
def test_install_then_uninstall_gives_back_the_exact_bytes_even_for_crlf_and_empty_files(tmp_path: Path, home: Path, harness: str,
                                                                                         original: bytes):
    path = install.settings_path(harness, "user", home, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(original)
    install.install(harness, "user", hook="intentshield-hook", home=home, cwd=tmp_path)
    assert b"intentshield-hook" in path.read_bytes()
    install.uninstall(harness, "user", home=home, cwd=tmp_path)
    assert path.read_bytes() == original


@pytest.mark.parametrize("original", [b'model = "o3"\r\n\r\n[mcp_servers.demo]\r\ncommand = "demo"\r\n', b"",
                                      b"# only a comment\n"])
def test_codex_install_then_uninstall_gives_back_the_exact_bytes(tmp_path: Path, home: Path, original: bytes):
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_bytes(original)
    install.install("codex", "user", hook="intentshield-hook", home=home)
    install.uninstall("codex", "user", home=home)
    assert path.read_bytes() == original


def test_wrap_then_unwrap_gives_back_the_exact_bytes_of_a_crlf_mcp_file(tmp_path: Path, home: Path):
    path = tmp_path / ".mcp.json"
    original = b'{\r\n  "mcpServers": {\r\n    "a": {"command": "x"}\r\n  }\r\n}\r\n'
    path.write_bytes(original)
    install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp")
    install.unwrap(path)
    assert path.read_bytes() == original


def test_an_install_in_a_file_that_was_not_there_is_removed_again(tmp_path: Path, home: Path):
    path = install.settings_path("claude", "user", home, tmp_path)
    install.install("claude", "user", hook="intentshield-hook", home=home, cwd=tmp_path)
    install.uninstall("claude", "user", home=home, cwd=tmp_path)
    assert not path.exists()


def test_codex_hooks_and_wrapped_servers_in_one_file_come_back_exactly_in_either_order(tmp_path: Path, home: Path):
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text(CODEX_TOML)
    install.install("codex", "user", hook="intentshield-hook", home=home)
    install.wrap(path, out_dir=tmp_path / "proxies", proxy="/bin/intentshield-mcp")
    install.uninstall("codex", "user", home=home)
    install.unwrap(path)
    assert path.read_text() == CODEX_TOML


# --- what install says -------------------------------------------------------------------------------------------------------

def test_a_reinstall_without_an_option_says_that_the_option_is_gone(tmp_path: Path, home: Path, capsys):
    install.install("claude", "user", hook="intentshield-hook", home=home, builtin_tools=True, review="always")
    capsys.readouterr()
    install.install("claude", "user", hook="intentshield-hook", home=home)
    out = capsys.readouterr().out
    assert "replaced the previous install" in out and "--builtin-tools" in out and "--review always" in out


@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_an_unchanged_reinstall_does_not_claim_a_replacement(tmp_path: Path, home: Path, capsys, harness: str):
    install.install(harness, "user", hook="intentshield-hook", home=home, builtin_tools=True)
    capsys.readouterr()
    install.install(harness, "user", hook="intentshield-hook", home=home, builtin_tools=True)
    assert "replaced" not in capsys.readouterr().out


@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_a_codex_or_claude_reinstall_without_the_option_names_it(tmp_path: Path, home: Path, capsys, harness: str):
    install.install(harness, "user", hook="intentshield-hook", home=home, builtin_tools=True)
    capsys.readouterr()
    install.install(harness, "user", hook="intentshield-hook", home=home)
    assert "no longer set: --builtin-tools" in capsys.readouterr().out


@pytest.mark.parametrize("builtin", [False, True])
def test_install_says_that_shell_and_file_tools_are_guarded_only_with_the_option(tmp_path: Path, home: Path, capsys,
                                                                                 builtin: bool):
    install.install("claude", "user", hook="intentshield-hook", home=home, builtin_tools=builtin)
    out = capsys.readouterr().out
    assert ("MCP calls only, not the shell or the file tools" in out) is not builtin
    assert ("--builtin-tools" in out) is not builtin
