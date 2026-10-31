"""Regression tests for hooks-11 to hooks-18 of the 2026-10-31 audit: what `intentshield doctor`, `install`, `wrap` and
`unwrap` say and do."""
from __future__ import annotations

import json
import os
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
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path, "#!/nonexistent/venv/bin/python"))
    _ran(_db(home), "claude", time.time() + 5)
    rc, out = _doctor(home, cwd, capsys)
    assert rc == 1 and "#!/nonexistent/venv/bin/python" in out and "exits 126" in out


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
    install.install("claude", home=home, cwd=cwd, hook=_exe(tmp_path, "#!/usr/bin/env no-such-interpreter-xyz"))
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
    install.install("claude", home=home, cwd=cwd, hook=exe)
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
