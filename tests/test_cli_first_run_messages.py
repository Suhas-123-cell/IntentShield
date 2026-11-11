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
