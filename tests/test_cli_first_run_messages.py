"""What a person sees on a first run: install notes, a settings file that does not parse, unwrap of a missing file, doctor on a
machine with nothing installed, a wrapped server whose command is gone, and the hook entry `wrap-hook` prints."""
# ruff: noqa: E501
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from intentshield import __main__ as cli
from intentshield import doctor, install, scan, wrap_hook


@pytest.fixture(autouse=True)
def _no_harness_probe(monkeypatch):
    monkeypatch.setattr(install.translation, "probe_and_record", lambda *args, **kwargs: None)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    (tmp_path / "home").mkdir()
    return tmp_path / "home"


HOOK = "/opt/is/bin/intentshield-hook"


# --- settings files that do not parse -------------------------------------------------------------------------------------

def test_a_gemini_settings_file_with_a_trailing_comma_and_comments_is_read_and_restored_on_uninstall(home, capsys):
    original = '{\n  // my model\n  "model": {"name": "x",},\n}\n'
    path = home / ".gemini" / "settings.json"
    path.parent.mkdir()
    path.write_text(original)
    install.install("gemini", home=home, hook=HOOK)
    err = capsys.readouterr().err
    assert "comments or trailing commas" in err and "puts it back" in err
    data = json.loads(path.read_text())
    assert data["model"] == {"name": "x"} and "BeforeTool" in data["hooks"]
    install.uninstall("gemini", home=home)
    assert path.read_text() == original


def test_a_claude_settings_file_that_is_not_json_says_what_to_do_and_is_left_alone(home, capsys):
    path = home / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text('{\n  // note\n  "theme": "dark"\n}\n')
    code = cli.install.run(type("A", (), {"command": "install", "harness": "claude", "scope": "user", "review": None, "dry_run": False,
                                          "judge": None, "api_key": None, "judge_url": None, "judge_outputs": False,
                                          "builtin_tools": False, "gemini_ask": False, "no_translate": False,
                                          "allow_ephemeral": True})())
    err = capsys.readouterr().err
    assert code == 1 and "remove its comments and trailing commas" in err and "install <harness> --dry-run" in err
    assert path.read_text() == '{\n  // note\n  "theme": "dark"\n}\n'


# --- install notes ----------------------------------------------------------------------------------------------------------

def test_the_next_step_after_an_install_asks_for_any_prompt_not_a_tool_call(home, capsys):
    install.install("claude", home=home, hook=HOOK)
    out = capsys.readouterr().out
    assert "Next: Start claude and send any prompt, then run `intentshield doctor`." in out
    assert "tool call" not in out
    assert install.NEXT_STEP.format(harness="claude") in out


def test_a_project_install_warns_that_the_file_holds_this_machines_paths(home, tmp_path, capsys):
    install.install("claude", "project", home=home, cwd=tmp_path, hook=HOOK)
    out = capsys.readouterr().out
    assert "absolute paths of this machine" in out and "do not commit it" in out
    install.install("claude", "user", home=home, hook=HOOK)
    assert "do not commit" not in capsys.readouterr().out


def test_a_dry_run_of_a_project_install_prints_no_note(home, tmp_path, capsys):
    install.install("claude", "project", home=home, cwd=tmp_path, hook=HOOK, dry_run=True)
    assert "do not commit" not in capsys.readouterr().out


def test_wrap_warns_when_the_file_lies_in_a_git_working_tree(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"s": {"command": sys.executable, "args": ["-c", "pass"]}}}))
    install.wrap(path, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    assert "do not commit it" in capsys.readouterr().out


def test_the_next_step_and_the_readme_give_the_same_instruction():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    assert "send any prompt" in readme and "send any prompt" in install.NEXT_STEP


# --- unwrap and wrap of a file that is not there ------------------------------------------------------------------------------

def test_unwrap_of_a_missing_file_says_it_was_not_found(tmp_path, capsys):
    code = cli.install.run(type("A", (), {"command": "unwrap", "config": tmp_path / "nonexist.json", "servers": None, "dry_run": False})())
    err = capsys.readouterr().err
    assert code == 1 and "nonexist.json was not found" in err and "no 'mcpServers'" not in err


def test_wrap_of_a_missing_file_says_the_same(tmp_path, capsys):
    code = cli.install.run(type("A", (), {"command": "wrap", "config": tmp_path / "nonexist.json", "servers": None, "dry_run": False,
                                          "out_dir": None, "allow_ephemeral": True})())
    assert code == 1 and "nonexist.json was not found" in capsys.readouterr().err


# --- doctor ------------------------------------------------------------------------------------------------------------------------

def test_doctor_with_nothing_installed_says_so_and_does_not_say_all_is_well(home, tmp_path, capsys):
    code = doctor.doctor(home=home, cwd=tmp_path / "project", db=home / "hooks.db")
    out = capsys.readouterr().out
    assert code == 0
    assert "nothing is installed" in out and "intentshield install <harness>" in out
    assert "no problems found" not in out


def test_doctor_after_an_install_does_not_say_nothing_is_installed(home, tmp_path, capsys):
    install.install("claude", home=home, hook=HOOK)
    doctor.doctor(home=home, cwd=tmp_path, db=home / "hooks.db")
    assert "nothing is installed" not in capsys.readouterr().out


def test_doctor_help_states_its_exit_status():
    import argparse

    parser = argparse.ArgumentParser()
    doctor.add_subcommand(parser.add_subparsers())
    text = " ".join(parser._subparsers._group_actions[0].choices["doctor"].format_help().split())
    assert "Exit status: 0" in text and "1 when any check printed FAIL" in text


def test_doctor_fails_a_wrapped_server_whose_command_does_not_exist(home, tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    mcp = project / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"gone": {"command": "/no/such/binary", "args": ["--x"]}}}))
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    capsys.readouterr()
    code = doctor.doctor(home=home, cwd=project, db=home / "hooks.db")
    out = capsys.readouterr().out
    assert code == 1
    assert "the server's command '/no/such/binary' does not exist" in out
    assert "no problems found" not in out and "nothing is installed" not in out


def test_doctor_fails_a_wrapped_server_whose_command_is_not_on_path(home, tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    mcp = project / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"gone": {"command": "no-such-program-xyz"}}}))
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    capsys.readouterr()
    assert doctor.doctor(home=home, cwd=project, db=home / "hooks.db") == 1
    assert "'no-such-program-xyz' is not on PATH" in capsys.readouterr().out


def test_doctor_passes_a_wrapped_server_whose_command_exists(home, tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    mcp = project / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"fine": {"command": sys.executable, "args": ["-c", "pass"]}}}))
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    capsys.readouterr()
    assert doctor.doctor(home=home, cwd=project, db=home / "hooks.db") == 0
    out = capsys.readouterr().out
    assert "no problems found" in out and "nothing is installed" not in out


# --- scan -------------------------------------------------------------------------------------------------------------------------

def test_scan_names_the_cause_when_a_server_cannot_be_started(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"nope": {"command": "/no/such/binary"}}}))
    servers = scan.discover(tmp_path, tmp_path, [path])
    scan.scan(servers, connect=True, timeout=10, pins={})
    assert servers[0].error and "'/no/such/binary' does not exist" in servers[0].error


# --- wrap-hook --print-entry --------------------------------------------------------------------------------------------------

def test_print_entry_gives_the_hook_command_with_the_absolute_path_of_the_launcher(capsys, monkeypatch):
    monkeypatch.setattr(install, "executable", lambda name: f"/opt/is bin/{name}")
    wrap_hook.main(["--harness", "claude", "--hook-timeout", "5", "--print-entry", "--", "pnpm", "dlx", "block-no-verify"])
    line = capsys.readouterr().out.strip()
    assert line.startswith("'/opt/is bin/intentshield' wrap-hook --harness claude --hook-timeout 5 -- pnpm dlx block-no-verify")
    assert line.endswith("exit 2; }") and "IntentShield hook did not run" in line


def test_print_entry_keeps_a_guard_given_as_one_shell_string_as_it_is(capsys):
    wrap_hook.main(["--harness", "gemini", "--print-entry", "--", "node /x/guard.js --strict"])
    assert " -- node /x/guard.js --strict " in capsys.readouterr().out


def test_print_entry_quotes_the_words_of_a_guard_given_as_words(capsys):
    wrap_hook.main(["--harness", "claude", "--print-entry", "--", "python3", "-c", "print('a b')"])
    assert "-- python3 -c 'print('\"'\"'a b'\"'\"')'" in capsys.readouterr().out


def test_wrapped_command_accepts_a_list():
    assert " -- pnpm dlx 'a b' " in wrap_hook.wrapped_command("claude", ["pnpm", "dlx", "a b"])


# --- the hook shown without a harness -------------------------------------------------------------------------------------

def test_the_demo_command_prints_an_allow_an_ask_and_a_deny_from_the_real_hook(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["intentshield", "demo"])
    with pytest.raises(SystemExit) as done:
        cli.main()
    assert done.value.code == 0
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line[:5].strip() in ("allow", "ask", "deny")]
    assert [line.split()[0] for line in lines] == ["allow", "ask", "deny", "deny"]
    assert "ls -la" in lines[0] and "git reset --hard" in lines[1] and ".ssh/id_rsa" in lines[2]
    assert "$" in lines[2] and "mcp__notes__save_note" in lines[3] and "$" not in lines[3]  # the last is an MCP call, not a shell one


def test_the_demo_says_that_shell_commands_are_guarded_only_with_the_option_and_shows_an_mcp_call(capsys):
    assert doctor.demo() == 0
    out = capsys.readouterr().out
    assert "guarded only with --builtin-tools" in out and "default install guards MCP calls only" in out
    assert out.index("default install guards MCP calls only") < out.index("$ ls -la")
    assert "Arguments carry injected instructions" in out
    assert out.rstrip().endswith("intentshield install claude --builtin-tools")


def test_the_demo_runs_nothing_and_writes_only_to_a_temporary_directory(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    assert doctor.demo() == 0
    capsys.readouterr()
    assert not (tmp_path / "home").exists()
    assert list(tmp_path.iterdir()) == []


def test_the_demo_is_listed_in_the_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "demo" in capsys.readouterr().out


def test_wrap_points_a_remote_server_to_a_url_not_to_a_path_only_a_clone_has(tmp_path, capsys):
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"remote": {"url": "https://mcp.example.org/sse"}}}))
    install.wrap(mcp, out_dir=tmp_path / "proxies", proxy="/opt/is/bin/intentshield-mcp", allow_ephemeral=True)
    said = capsys.readouterr().out
    assert "skipped remote: not a stdio server" in said
    assert "https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md#real-mcp-proxy" in said
    assert " docs/gateway.md" not in said.replace("/blob/main/docs/gateway.md", "")


# --- doctor on wrapped servers ----------------------------------------------------------------------------------------------

def _proxy(tmp_path: Path, body: str = "exit 3") -> str:
    """A program named like the proxy, so that ``wrap`` and ``doctor`` take an entry that runs it for a wrapped one."""
    script = tmp_path / "bin" / "intentshield-mcp"
    script.parent.mkdir(exist_ok=True)
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return str(script)


def _wrapped(tmp_path: Path, home: Path, entry: dict, name: str = ".mcp.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"mcpServers": {"demo": entry}}))
    install.wrap(path, out_dir=home / ".intentshield" / "proxies", proxy=_proxy(tmp_path))
    return path


def test_doctor_prints_an_ok_line_for_each_wrapped_file_it_checked(tmp_path, home, capsys):
    path = _wrapped(tmp_path, home, {"command": sys.executable, "args": ["-m", "x"]})
    assert doctor.doctor(home, tmp_path, home / "hooks.db") == 0
    out = capsys.readouterr().out
    assert f"ok   {path}: 1 server(s) behind the proxy (demo)" in out
    assert "does not start the proxy" in out and "--connect" in out


def test_doctor_prints_no_ok_line_for_a_server_whose_command_is_gone(tmp_path, home, capsys):
    path = _wrapped(tmp_path, home, {"command": "/nonexistent/server", "args": []})
    assert doctor.doctor(home, tmp_path, home / "hooks.db") == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and f"ok   {path}" not in out


def test_doctor_says_what_it_checks_and_what_it_does_not_start(capsys):
    with pytest.raises(SystemExit):
        cli.main(["doctor", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "without starting anything" in out
    assert "--connect" in out and "runs the server's code" in out
    assert "installed and running" not in out and "installed and run" not in out


def test_doctor_reads_codex_toml_and_vscode_files_too(tmp_path, home, capsys):
    toml = home / ".codex" / "config.toml"
    toml.parent.mkdir(parents=True)
    toml.write_text(f'[mcp_servers.demo]\ncommand = "{sys.executable}"\nargs = ["-m", "x"]\n')
    install.wrap(toml, out_dir=home / ".intentshield" / "proxies", proxy=_proxy(tmp_path))
    vscode = tmp_path / ".vscode" / "mcp.json"
    vscode.parent.mkdir()
    vscode.write_text(json.dumps({"servers": {"demo": {"command": sys.executable, "args": ["-m", "x"]}}}))
    install.wrap(vscode, out_dir=home / ".intentshield" / "proxies", proxy=_proxy(tmp_path))
    doctor.doctor(home, tmp_path, home / "hooks.db")
    out = capsys.readouterr().out
    assert f"ok   {str(toml).replace(str(home), '~')}" in out and f"ok   {vscode}" in out  # a path under home is written ~/...


def test_doctor_connect_starts_a_wrapped_server_through_its_proxy_and_lists_its_tools(tmp_path, home, capsys):
    import shutil

    proxy = shutil.which("intentshield-mcp") or str(Path(sys.executable).parent / "intentshield-mcp")
    if not Path(proxy).exists():
        pytest.skip("the intentshield-mcp program is not installed in this environment")
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"demo": {"command": sys.executable, "args": ["-m",
        "intentshield.demo_mcp_server"]}}}))
    install.wrap(path, out_dir=home / ".intentshield" / "proxies", proxy=proxy)
    monkey_cwd = tmp_path / "elsewhere"
    monkey_cwd.mkdir()
    # the file is outside the working directory and the home: it is read through a home-level path
    user_file = home / ".cursor" / "mcp.json"
    user_file.parent.mkdir(parents=True)
    user_file.write_text(path.read_text())
    assert doctor.doctor(home, monkey_cwd, home / "hooks.db", connect=True) == 0
    out = capsys.readouterr().out
    assert "demo: started through the proxy and listed" in out and "tool(s)" in out


def test_doctor_connect_reports_a_server_that_does_not_start_and_still_checks_the_others(tmp_path, home, capsys):
    user_file = home / ".cursor" / "mcp.json"
    user_file.parent.mkdir(parents=True)
    script = tmp_path / "dies.sh"
    script.write_text("#!/bin/sh\nexit 3\n")
    script.chmod(0o755)
    user_file.write_text(json.dumps({"mcpServers": {"dead": {"command": str(script), "args": []}}}))
    install.wrap(user_file, out_dir=home / ".intentshield" / "proxies", proxy=_proxy(tmp_path))
    assert doctor.doctor(home, tmp_path / "x", home / "hooks.db", connect=True) == 1
    assert "dead: the proxy did not answer tools/list" in capsys.readouterr().out


def test_doctor_connect_does_not_start_a_server_named_by_a_file_in_the_working_directory(tmp_path, home, capsys):
    marker = tmp_path / "started"
    script = tmp_path / "server.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\nexit 3\n")
    script.chmod(0o755)
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"repo": {"command": str(script), "args": []}}}))
    install.wrap(path, out_dir=home / ".intentshield" / "proxies", proxy=_proxy(tmp_path, f"touch {marker}"))
    doctor.doctor(home, tmp_path, home / "hooks.db", connect=True)
    assert not marker.exists() and "not started" in capsys.readouterr().out


def test_print_entry_for_cursor_says_to_set_fail_closed_and_the_others_do_not(capsys):
    wrap_hook.main(["--harness", "cursor", "--print-entry", "--", "./guard.sh"])
    captured = capsys.readouterr()
    assert "./guard.sh" in captured.out and '"failClosed": true' in captured.err
    wrap_hook.main(["--harness", "claude", "--print-entry", "--", "./guard.sh"])
    assert capsys.readouterr().err == ""
