"""``install``, ``uninstall``, ``wrap``, ``unwrap``, ``scan`` and ``wrap-hook``: the installers, the scan and the hook wrapper."""
# ruff: noqa: E501
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from intentshield import __main__ as cli
from intentshield import install, scan, translation, wrap_hook


@pytest.fixture(autouse=True)
def _no_harness_probe(monkeypatch):
    monkeypatch.setattr(install.translation, "probe_and_record", lambda *args, **kwargs: None)


# --- a commented Gemini settings file -------------------------------------------------------------------------------------------

def test_uninstall_puts_back_a_commented_gemini_file_with_an_empty_hooks_object_byte_for_byte(tmp_path, capsys):
    original = '{ // keep this note\n  "theme": "dark", /* and this */\n  "hooks": {}\n}\n'
    path = tmp_path / "home" / ".gemini" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(original)
    install.install("gemini", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path / "home")
    assert "hooks" in json.loads(install.strip_json_comments(path.read_text()))
    assert "its original text is saved" in capsys.readouterr().err
    install.uninstall("gemini", "user", home=tmp_path / "home")
    assert path.read_text() == original


def test_a_commented_gemini_file_with_no_hooks_key_comes_back_too(tmp_path):
    original = '{\n  // c\n  "theme": "dark"\n}\n'
    path = tmp_path / "home" / ".gemini" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(original)
    install.install("gemini", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path / "home")
    install.uninstall("gemini", "user", home=tmp_path / "home")
    assert path.read_text() == original


def test_an_edit_made_after_install_is_kept_and_the_original_text_is_not_forced_back(tmp_path):
    path = tmp_path / "home" / ".gemini" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{ // c\n "hooks": {} }\n')
    install.install("gemini", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path / "home")
    data = json.loads(path.read_text())
    data["theme"] = "light"
    path.write_text(json.dumps(data))
    install.uninstall("gemini", "user", home=tmp_path / "home")
    assert json.loads(path.read_text()) == {"theme": "light"}


# --- wrap: one bad entry, proxy configs, unwrap warning ---------------------------------------------------------------------------

def _mcp(tmp_path: Path, servers: dict) -> Path:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return path


def test_wrap_skips_an_entry_the_proxy_cannot_take_and_wraps_the_rest_without_a_traceback(tmp_path, capsys):
    mcp = _mcp(tmp_path, {"good": {"command": "npx", "args": ["a"]}, "bad": {"command": 5, "args": "x"},
                          "badargs": {"command": "x", "args": "x"}, "badenv": {"command": "x", "env": ["A"]},
                          "also": {"command": "py", "args": ["b"]}})
    out = tmp_path / "proxies"
    assert install.wrap(mcp, out_dir=out, proxy="/opt/is/bin/intentshield-mcp") == ["good", "also"]
    said = capsys.readouterr().out
    assert "skipped bad: command must be a string" in said and "skipped badargs: args must be a list of strings" in said
    assert "skipped badenv: env must be an object" in said
    data = json.loads(mcp.read_text())["mcpServers"]
    assert data["bad"] == {"command": 5, "args": "x"} and data["good"]["command"] == "/opt/is/bin/intentshield-mcp"
    assert len(list(out.glob("*.json"))) == 2


def test_wrap_leaves_no_proxy_config_behind_when_the_client_file_cannot_be_written(tmp_path, monkeypatch):
    mcp = _mcp(tmp_path, {"a": {"command": "npx"}, "b": {"command": "py"}})
    out = tmp_path / "proxies"
    real = install._write

    def failing(path, text, dry_run):
        if path == mcp:
            raise install.ChangedMeanwhile("changed")
        return real(path, text, dry_run)
    monkeypatch.setattr(install, "_write", failing)
    with pytest.raises(install.ChangedMeanwhile):
        install.wrap(mcp, out_dir=out, proxy="/opt/is/bin/intentshield-mcp")
    assert list(out.glob("*.json")) == []
    assert json.loads(mcp.read_text())["mcpServers"]["a"] == {"command": "npx"}


def test_wrap_writes_nothing_when_every_entry_is_refused(tmp_path):
    mcp = _mcp(tmp_path, {"bad": {"command": ["x"]}})
    out = tmp_path / "proxies"
    assert install.wrap(mcp, out_dir=out, proxy="/opt/is/bin/intentshield-mcp") == []
    assert not out.exists() or list(out.iterdir()) == []


def test_unwrap_says_so_when_the_wrapped_entry_was_edited_and_drops_the_edit(tmp_path, capsys):
    mcp = _mcp(tmp_path, {"fs": {"command": "npx", "args": ["-y", "srv"]}})
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp")
    capsys.readouterr()
    data = json.loads(mcp.read_text())
    data["mcpServers"]["fs"]["args"].append("--extra")
    mcp.write_text(json.dumps(data))
    install.unwrap(mcp)
    err = capsys.readouterr().err
    assert "fs has other arguments than the ones wrap wrote" in err and "--extra" in err
    assert json.loads(mcp.read_text())["mcpServers"]["fs"] == {"command": "npx", "args": ["-y", "srv"]}


def test_unwrap_of_an_untouched_entry_prints_no_warning(tmp_path, capsys):
    mcp = _mcp(tmp_path, {"fs": {"command": "npx", "args": ["-y", "srv"]}})
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp")
    capsys.readouterr()
    install.unwrap(mcp)
    assert "warning" not in capsys.readouterr().err


# --- a hook or proxy path in a run-once cache ----------------------------------------------------------------------------------------

CACHE_HOOK = "/Users/x/.cache/uv/archive-v0/B4wUP7pzIJydhgG-/bin/intentshield-hook"


def test_install_refuses_a_hook_in_the_uvx_cache_and_names_the_way_out(tmp_path):
    with pytest.raises(ValueError, match="uv tool install intentshield-mcp"):
        install.install("claude", "user", hook=CACHE_HOOK, home=tmp_path)
    assert not (tmp_path / ".claude").exists()


def test_a_dry_run_only_warns_and_allow_ephemeral_installs_anyway(tmp_path, capsys):
    install.install("claude", "user", hook=CACHE_HOOK, home=tmp_path, dry_run=True)
    assert "archive-v0" in capsys.readouterr().err
    install.install("claude", "user", hook=CACHE_HOOK, home=tmp_path, allow_ephemeral=True)
    assert CACHE_HOOK in (tmp_path / ".claude" / "settings.json").read_text()


@pytest.mark.parametrize("path,ephemeral", [
    (CACHE_HOOK, True), ("/Users/x/Library/Caches/uv/archive-v0/abc/bin/intentshield-hook", True),
    ("/home/x/.cache/uv/builds-v0/.tmpAbc/bin/x", True), ("/home/x/.npm/_npx/9f/node_modules/.bin/x", True),
    ("/Users/x/.local/share/uv/tools/intentshield-mcp/bin/intentshield-hook", False), ("/Users/x/proj/.venv/bin/intentshield-hook", False),
    ("/opt/pipx/venvs/intentshield-mcp/bin/intentshield-hook", False),
])
def test_ephemeral_locations(path, ephemeral):
    assert install.ephemeral_location(path) is ephemeral


def test_wrap_refuses_a_proxy_in_the_uvx_cache(tmp_path):
    mcp = _mcp(tmp_path, {"fs": {"command": "npx"}})
    with pytest.raises(ValueError, match="run-once launcher"):
        install.wrap(mcp, out_dir=tmp_path / "p", proxy="/Users/x/.cache/uv/archive-v0/h/bin/intentshield-mcp")
    assert json.loads(mcp.read_text())["mcpServers"]["fs"] == {"command": "npx"}


# --- install arguments are checked in a dry run too, errors name their file ---------------------------------------------------------

def test_a_dry_run_of_a_custom_judge_without_an_endpoint_fails_like_the_real_install(tmp_path, monkeypatch):
    monkeypatch.delenv("INTENTSHIELD_JUDGE_URL", raising=False)
    for dry in (True, False):
        with pytest.raises(ValueError, match="--judge custom needs --judge-url"):
            install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path, judge="custom:m", api_key="k", dry_run=dry)


def test_a_dry_run_of_a_custom_judge_checks_the_endpoint_and_stores_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("INTENTSHIELD_JUDGE_URL", raising=False)
    with pytest.raises(ValueError):
        install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path, judge="custom:m", api_key="k",
                        judge_url="not a url", dry_run=True)
    install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path, judge="custom:m", api_key="k",
                    judge_url="https://llm.example.com/v1/chat/completions", dry_run=True)
    assert not (tmp_path / ".intentshield").exists() and not (tmp_path / ".claude").exists()


def test_a_judge_url_without_a_custom_judge_is_refused(tmp_path):
    with pytest.raises(ValueError, match="--judge-url is for --judge custom only"):
        install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path, judge_url="https://x.example/v1", dry_run=True)


def test_a_hooks_value_that_is_not_an_object_is_reported_with_its_file(tmp_path, capsys):
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text('{"hooks": "x"}')
    with pytest.raises(ValueError, match="settings.local.json: 'hooks' is not an object"):
        install.install("claude", "project", hook="/opt/is/bin/intentshield-hook", cwd=tmp_path)
    path.write_text('{"hooks": {"PreToolUse": 5}}')
    with pytest.raises(ValueError, match="settings.local.json: hooks.PreToolUse is not a list"):
        install.install("claude", "project", hook="/opt/is/bin/intentshield-hook", cwd=tmp_path)


def test_the_command_line_says_which_file_for_a_bad_hooks_value(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text('{"hooks": "x"}')
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stop:
        cli.main(["install", "claude", "--scope", "project"])
    assert stop.value.code == 1
    assert "settings.local.json: 'hooks' is not an object" in capsys.readouterr().err


def test_install_ends_with_the_next_step(tmp_path, capsys):
    install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path)
    out = capsys.readouterr().out
    assert "Next: Start claude and send any prompt" in out and "intentshield doctor" in out and "no hook has run" in out
    install.install("claude", "user", hook="/opt/is/bin/intentshield-hook", home=tmp_path / "other", dry_run=True)
    assert "Next:" not in capsys.readouterr().out


# --- scan ----------------------------------------------------------------------------------------------------------------------------

def _server(client="claude-code", name="s", path="/proj/.mcp.json", **kw) -> scan.Server:
    return scan.Server(client, Path(path), name, {"command": "x"}, **kw)


def test_the_scan_report_names_not_started_servers_once_and_drops_the_hook_label(tmp_path):
    servers = [_server(name=n, project=True) for n in "abcd"]
    scan.scan(servers, connect=True)
    text = scan.report(servers, [], tmp_path, connected=True)
    assert text.count("--connect-project") == 1
    assert "no IntentShield hooks" not in text and text.splitlines()[0] == "claude-code: 4 server(s), 0 tool(s)"
    assert text.count("not started (config in the current directory)") == 4


def test_the_scan_report_says_when_hooks_are_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "guarded", lambda client, home: True)
    assert scan.report([_server()], [], tmp_path, connected=False).splitlines()[0] == \
        "claude-code: 1 server(s), IntentShield hooks installed"


def test_a_server_that_dies_at_start_gives_the_line_it_wrote_to_stderr(tmp_path):
    """In a process of its own: the server inherits file descriptor 2, which the test runner replaces."""
    import subprocess
    code = "import sys; print('boom: no such module foo', file=sys.stderr); sys.exit(3)"
    script = ("import sys\nfrom pathlib import Path\nfrom intentshield import scan\n"
              f"s = scan.Server('claude-code', Path('/p/mcp.json'), 'dies', {{'command': sys.executable, 'args': ['-c', {code!r}]}})\n"
              "scan.scan([s], connect=True, timeout=20)\nprint('ERROR:', s.error)\n")
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                          env={**__import__("os").environ, "PYTHONPATH": str(Path(scan.__file__).parents[1])})
    line = next(line for line in done.stdout.splitlines() if line.startswith("ERROR:"))
    assert "Could not connect" in line and "the server's stderr says: boom: no such module foo" in line
    assert "boom: no such module foo" not in done.stderr  # held back for the report, not printed twice


def test_the_stderr_reason_is_the_last_line_of_a_traceback_and_masks_credentials():
    assert scan._stderr_reason("Traceback (most recent call last):\n  File x\nModuleNotFoundError: No module named 'foo'\n") == \
        "ModuleNotFoundError: No module named 'foo'"
    assert scan._stderr_reason("starting\nsecond line") == "starting"
    assert scan._stderr_reason("   \n") == ""
    assert "ghp_" + "a1B2" * 9 not in scan._stderr_reason("token ghp_" + "a1B2" * 9)


def test_the_scan_help_and_docs_state_the_exit_codes():
    assert "Exit status: 0" in scan.__doc__ and "2 when nothing could be scanned" in scan.__doc__
    import argparse
    parser = argparse.ArgumentParser()
    scan.add_subcommand(parser.add_subparsers())
    help_text = " ".join(parser._subparsers._group_actions[0].choices["scan"].format_help().split())
    assert "exit status: 0" in help_text and "2 nothing could be scanned" in help_text


def test_a_scan_of_one_unstartable_project_server_exits_2(tmp_path, monkeypatch, capsys):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"command": "x"}}}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    with pytest.raises(SystemExit) as stop:
        cli.main(["scan", "--no-pins"])
    assert stop.value.code == 2


# --- wrap-hook ---------------------------------------------------------------------------------------------------------------------------

def _crash(tmp_path) -> list[str]:
    path = tmp_path / "g.py"
    path.write_text("import sys\nsys.stdin.read()\nsys.stderr.write('Traceback: boom')\nsys.exit(1)\n")
    return [sys.executable, str(path)]


@pytest.mark.parametrize("event", [
    {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
    {"hook_event_name": "pretooluse", "tool_name": "Bash", "tool_input": {"command": "x"}},
    {"hook_event_name": "Weird", "tool_name": "mcp__srv__tool", "tool_input": {}},
])
def test_a_guard_crash_on_an_event_with_an_unknown_name_is_refused_not_passed_through(tmp_path, event):
    out, err = io.StringIO(), io.StringIO()
    code = wrap_hook.wrap("claude", _crash(tmp_path), json.dumps(event), mode="headless", version="2.1.316", stdout=out, stderr=err)
    assert code == 0
    reply = json.loads(out.getvalue())
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("event", [
    {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}},
    {"hook_event_name": "UserPromptSubmit", "prompt": "x"}, {"hook_event_name": "SessionStart"},
])
def test_an_event_that_is_not_a_call_still_passes_the_guards_exit_code_through(tmp_path, event):
    out, err = io.StringIO(), io.StringIO()
    code = wrap_hook.wrap("claude", _crash(tmp_path), json.dumps(event), mode="headless", version="2.1.316", stdout=out, stderr=err)
    assert code == 1


def test_looks_like_call():
    assert translation.looks_like_call({"tool_name": "Bash"})
    assert translation.looks_like_call({"hook_event_name": "Weird", "tool_name": "x"})
    assert not translation.looks_like_call({"hook_event_name": "PreToolUse", "tool_name": "x"})
    assert not translation.looks_like_call({"hook_event_name": "PostToolUse", "tool_name": "x"})
    assert not translation.looks_like_call({"hook_event_name": "Weird"})


@pytest.mark.parametrize("flag,value", [("--deadline", "nan"), ("--deadline", "inf"), ("--deadline", "-1"), ("--deadline", "0"),
                                        ("--deadline", "99999"), ("--hook-timeout", "nan"), ("--hook-timeout", "-3")])
def test_wrap_hook_refuses_a_deadline_it_cannot_arm(tmp_path, monkeypatch, capsys, flag, value):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    with pytest.raises(SystemExit) as stop:
        wrap_hook.main(["--harness", "claude", flag, value, "--", sys.executable, "-c", "pass"])
    assert stop.value.code == 2
    assert flag in capsys.readouterr().err


# --- the bare command --------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [[], ["serve"], ["serve", "--port", "8123"]])
def test_serving_says_where_the_dashboard_is_before_it_starts(monkeypatch, capsys, argv):
    import uvicorn

    printed_first: list[bool] = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: printed_first.append("IntentShield dashboard on" in capsys.readouterr().out))
    cli.main(argv)
    assert printed_first == [True]


def test_the_dashboard_line_names_the_port_and_the_help_command(monkeypatch, capsys):
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    cli.main(["serve", "--port", "8123"])
    assert capsys.readouterr().out.strip() == ("IntentShield dashboard on http://127.0.0.1:8123, Ctrl-C to stop; "
                                               "`intentshield --help` for commands")


# --- ~/.intentshield is private on every path that creates it ---------------------------------------------------------------

def _mode(path: Path) -> int:
    import stat

    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def fresh_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "fresh-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    return home


def test_wrap_creates_the_state_directory_private(fresh_home, tmp_path):
    mcp = _mcp(tmp_path, {"a": {"command": "npx", "args": ["x"]}})
    install.wrap(mcp, proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    assert _mode(fresh_home / ".intentshield") == 0o700


def test_install_creates_the_state_directory_private(fresh_home, tmp_path):
    install.install("claude", home=fresh_home, hook="/opt/is/bin/intentshield-hook")
    assert _mode(fresh_home / ".intentshield") == 0o700


def test_a_proxy_database_and_its_catalog_and_threat_memory_create_it_private(fresh_home):
    from intentshield.storage import Storage
    from intentshield.threat_memory import ThreatMemory

    Storage(fresh_home / ".intentshield" / "proxies" / "x.db")
    assert _mode(fresh_home / ".intentshield") == 0o700
    other = fresh_home.parent / "other-home"
    other.mkdir()
    ThreatMemory(other / ".intentshield" / "threats.db")
    assert _mode(other / ".intentshield") == 0o700
    third = fresh_home.parent / "third-home"
    third.mkdir()
    translation.private_dir(third / ".intentshield" / "tools")
    assert _mode(third / ".intentshield") == 0o700


def test_the_hook_creates_it_private_and_an_existing_loose_one_is_tightened(fresh_home):
    from intentshield.harness import HarnessGuard

    HarnessGuard(fresh_home / ".intentshield" / "hooks.db").close()
    assert _mode(fresh_home / ".intentshield") == 0o700
    loose = fresh_home.parent / "loose-home" / ".intentshield"
    loose.mkdir(parents=True)
    loose.chmod(0o755)
    HarnessGuard(loose / "hooks.db").close()
    assert _mode(loose) == 0o700


def test_a_directory_that_is_not_the_state_directory_is_just_created(tmp_path):
    other = tmp_path / "project" / "out"
    translation.private_dir(other)
    assert other.is_dir() and not (tmp_path / "project" / ".intentshield").exists()
