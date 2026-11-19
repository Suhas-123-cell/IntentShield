"""What a new user sees when something is not as expected: a harness that is not on PATH, a settings file that does not parse,
a directory where a file should be, a scan that cannot save its hashes, a server that is slow to start, a terminal."""
from __future__ import annotations

import argparse
import errno
import json
import sys
from pathlib import Path

import pytest

from intentshield import __main__ as cli
from intentshield import doctor, install, mcp_verify, scan


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))
    return path


def _hook(tmp_path: Path) -> str:
    exe = tmp_path / "bin" / "intentshield-hook"
    exe.parent.mkdir(exist_ok=True)
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    return str(exe)


# --- a harness that is not on PATH ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("harness, program", [("claude", "claude"), ("codex", "codex"), ("cursor", "cursor-agent"),
                                               ("gemini", "gemini")])
def test_a_plain_doctor_warns_when_the_harness_version_is_unknown(tmp_path, home, capsys, monkeypatch, harness, program):
    monkeypatch.setattr(doctor, "gemini_version", lambda: None)  # a Gemini CLI on the machine running the tests is not read
    install.install(harness, home=home, cwd=tmp_path, hook=_hook(tmp_path))
    capsys.readouterr()
    assert doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db") == 0
    out = capsys.readouterr().out
    if harness == "claude":  # the one harness whose verdicts here depend on the version
        line = next(ln for ln in out.splitlines() if ln.startswith(f"warn {harness}") and "could not be read" in ln)
        assert f"the version of {program} could not be read" in line and "is blocked instead" in line
        assert f"Put {program} on PATH, then run `intentshield doctor` again" in line
        assert "2 warning(s) above" in out
    else:  # a fact with no cost: a note, which is not counted as a warning and is shown with --verbose
        assert "could not be read" not in out and "1 warning(s) above" in out
        assert doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db", verbose=True) == 0
        shown = capsys.readouterr().out.splitlines()
        line = next(ln for ln in shown if ln.startswith(f"note {harness}") and "could not be read" in ln)
        assert f"the version of {program} could not be read" in line and "do not depend on it" in line
        assert "blocked instead" not in line
    assert "no problems found" in out
    assert "version unknown" not in out, "the longer note stays behind --verbose"


def test_the_version_warning_goes_away_when_the_version_is_known(tmp_path, home, capsys, monkeypatch):
    monkeypatch.setattr(doctor, "_harness_version", lambda harness, home: (2, 1, 316))
    install.install("claude", home=home, cwd=tmp_path, hook=_hook(tmp_path))
    capsys.readouterr()
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db")
    assert "could not be read" not in capsys.readouterr().out


# --- a file that does not parse -----------------------------------------------------------------------------------------------

def test_a_dry_run_on_a_settings_file_that_does_not_parse_prints_the_entries_the_error_points_to(tmp_path, home, capsys):
    path = home / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text("// note\n{}", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        install.install("claude", home=home, cwd=tmp_path, hook=_hook(tmp_path), dry_run=True)
    out = capsys.readouterr().out
    assert "not written" in out and '"PreToolUse"' in out and path.read_text(encoding="utf-8") == "// note\n{}"
    with pytest.raises(json.JSONDecodeError):
        install.install("claude", home=home, cwd=tmp_path, hook=_hook(tmp_path))  # a real run prints no entries
    assert "not written" not in capsys.readouterr().out


def test_a_dry_run_on_a_codex_file_that_does_not_parse_prints_the_block(tmp_path, home, capsys):
    path = home / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text("[x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid TOML"):
        install.install("codex", home=home, cwd=tmp_path, hook=_hook(tmp_path), dry_run=True)
    out = capsys.readouterr().out
    assert "not written" in out and "[[hooks.PreToolUse]]" in out and path.read_text(encoding="utf-8") == "[x\n"


@pytest.mark.parametrize("text, expected", [("[]", "must start with {"), ('{"hooks": 3}', "must map event names"),
                                            ('{"hooks": {"PreToolUse": 3}}', "must hold the hooks of that event")])
def test_a_settings_file_of_the_wrong_shape_says_what_to_do(tmp_path, home, capsys, text, expected):
    path = home / ".cursor" / "hooks.json"
    path.parent.mkdir()
    path.write_text(text, encoding="utf-8")
    harness = "cursor" if "PreToolUse" not in text else "claude"
    if harness == "claude":
        path = home / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text(text, encoding="utf-8")
    args = argparse.Namespace(command="install", harness=harness, scope="user", review=None, dry_run=False, judge=None,
                              api_key=None, judge_url=None, judge_outputs=False, builtin_tools=False, gemini_ask=False,
                              no_translate=False, allow_ephemeral=True)
    assert cli.install.run(args) == 1
    err = capsys.readouterr().err
    assert expected in err and "then run the command again" in err and "Traceback" not in err


def test_a_directory_in_place_of_the_settings_file_is_named(tmp_path, home, capsys):
    path = home / ".codex" / "config.toml"
    path.mkdir(parents=True)
    args = argparse.Namespace(command="uninstall", harness="codex", scope="user", dry_run=False)
    assert cli.install.run(args) == 1
    err = capsys.readouterr().err
    assert str(path) in err and "not a file IntentShield can edit" in err and "move it aside" in err


def test_the_doctor_names_the_next_step_for_a_settings_file_it_cannot_read(tmp_path, home, capsys, monkeypatch):
    path = home / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text("{}", encoding="utf-8")

    def refused(harness, found):
        raise PermissionError(errno.EACCES, "Permission denied", str(found))

    monkeypatch.setattr(doctor, "_hooks", refused)
    assert doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db") == 1
    out = capsys.readouterr().out
    assert "cannot read the settings file" in out and "make the file readable by you" in out
    assert "then run `intentshield doctor` again" in out


def test_connect_with_nothing_wrapped_says_so(tmp_path, home, capsys):
    assert doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db", connect=True) == 0
    out = capsys.readouterr().out
    assert "--   --connect: no wrapped MCP server was found to start" in out and "intentshield wrap <file>" in out


def test_the_doctor_says_to_run_itself_again_for_an_mcp_file_that_does_not_parse(tmp_path, home, capsys):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {', encoding="utf-8")
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db")
    out = capsys.readouterr().out
    assert "cannot read MCP servers" in out and "then run `intentshield doctor` again" in out
    assert "run the command again" not in out and "by hand instead" not in out


# --- help ---------------------------------------------------------------------------------------------------------------------

def test_the_help_of_builtin_tools_says_what_the_documents_say(capsys):
    with pytest.raises(SystemExit):
        cli.main(["install", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "opt-in and best effort" in text and "not a sandbox" in text and "review load" not in text
    assert "Install again without it to turn them off" in text


@pytest.mark.parametrize("columns", ["40", "80", "120"])
def test_the_address_in_the_help_is_not_broken_across_lines(capsys, monkeypatch, columns):
    monkeypatch.setenv("COLUMNS", columns)
    with pytest.raises(SystemExit):
        cli.main(["install", "--help"])
    assert "https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/rules.md" in capsys.readouterr().out


# --- scan ---------------------------------------------------------------------------------------------------------------------

def test_the_scan_report_names_the_flag_and_the_file_to_start_a_project_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    server = scan.Server("claude-code", tmp_path / ".mcp.json", "notes", {"command": "x"}, project=True)
    scan.scan([server], connect=True)
    text = scan.report([server], [], tmp_path / "nohome", connected=True)
    assert "`intentshield scan --connect-project`" in text and "`intentshield scan .mcp.json`" in text
    summary = text.splitlines()[-1]
    assert summary.startswith("0 of 1 server(s) checked, 1 not scanned: ") and "--no-connect" not in summary


def test_the_scan_summary_keeps_the_no_connect_advice_for_a_server_that_failed(tmp_path):
    server = scan.Server("cursor", Path("mcp.json"), "remote", {"url": "https://mcp.example.org/mcp"})
    server.error = "MCPUpstreamError: Could not connect"
    assert "(--no-connect checks the configs without starting them)" in scan.report([server], [], tmp_path).splitlines()[-1]


def test_a_scan_in_json_says_on_stderr_how_to_start_a_project_config(tmp_path, home, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"notes": {"command": "x"}}}), encoding="utf-8")
    args = argparse.Namespace(files=None, no_connect=False, connect_project=False, format="json", timeout=1.0,
                              pins=tmp_path / "pins.json", no_pins=True, update_pins=False)
    assert scan.run(args) == 2
    err = capsys.readouterr().err
    assert "`intentshield scan --connect-project`" in err and "was not started" not in err and "were not started" in err


def test_an_unreadable_config_says_what_to_do(tmp_path):
    bad = tmp_path / "mcp.json"
    bad.write_text('{"mcpServers": {', encoding="utf-8")
    (server,) = scan.discover(tmp_path, tmp_path, [bad])
    assert server.error and "fix the syntax error at that position, then scan again" in server.error


def test_a_server_that_does_not_answer_in_time_says_how_long_and_what_to_try(monkeypatch):
    import asyncio

    async def slow(*args, **kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr("intentshield.mcp_upstream.MCPUpstream.__aenter__", slow)
    server = scan.Server("file", Path("mcp.json"), "slow", {"command": sys.executable, "args": ["-c", "pass"]})
    asyncio.run(scan._list_tools(server, 0.05))
    assert server.error and "did not list its tools within 0.05 s" in server.error and "larger --timeout" in server.error


def test_a_scan_that_cannot_save_its_hashes_says_so_and_does_not_print_a_traceback(tmp_path, home, capsys, monkeypatch):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}), encoding="utf-8")

    async def fake_list(server, timeout):
        server.tools = [{"name": "t", "title": None, "description": "Does a thing.", "input_schema": {"type": "object"},
                         "annotations": {}}]

    def refuse(path, pins):
        raise OSError(errno.EROFS, "Read-only file system", str(path.parent))

    monkeypatch.setattr(scan, "_list_tools", fake_list)
    monkeypatch.setattr(scan, "save_pins", refuse)
    args = argparse.Namespace(files=[cfg], no_connect=False, connect_project=False, format="text", timeout=5.0,
                              pins=tmp_path / "pins.json", no_pins=False, update_pins=False)
    assert scan.run(args) == 1
    captured = capsys.readouterr()
    assert "could not save the tool hashes" in captured.err and "--no-pins" in captured.err
    assert "1 server(s) checked" in captured.out


# --- the verifier -------------------------------------------------------------------------------------------------------------

def test_the_verifier_prints_json_when_piped_and_a_summary_on_a_terminal(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "")
    assert mcp_verify.main(["--demo"]) == 0
    piped = capsys.readouterr().out
    assert json.loads(piped)["status"] == "PASS" and piped.count("\n") == 1

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert mcp_verify.main(["--demo"]) == 0
    shown = capsys.readouterr().out
    assert shown.startswith("PASS 13/13 checks\n") and "add --json" in shown
    assert mcp_verify.main(["--demo", "--json"]) == 0
    again = capsys.readouterr().out
    assert again.count("\n") == 1 and json.loads(again)["summary"] == json.loads(piped)["summary"]
    assert mcp_verify.main(["--demo", "--summary"]) == 0
    assert capsys.readouterr().out == "PASS 13/13 checks\n"


def test_the_in_process_check_does_not_print_the_log_line_of_its_own_blocked_canary(monkeypatch, capsys):
    import logging

    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("INTENTSHIELD_LOG_LEVEL", raising=False)
    root_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))  # the MCP library logs to the terminal like this
    before = logging.getLogger("intentshield").level
    try:
        assert mcp_verify.main(["--demo"]) == 0
        assert logging.getLogger("intentshield").level == before, "the level is lowered for the run only"
    finally:
        logging.getLogger().setLevel(root_level)
        logging.getLogger().handlers[:] = [h for h in logging.getLogger().handlers if not isinstance(h, logging.StreamHandler)
                                           or getattr(h, "stream", None) is not sys.stderr]
    captured = capsys.readouterr()
    assert "policy decision" not in captured.err and json.loads(captured.out)["status"] == "PASS"


def test_the_summary_of_a_failed_run_says_why_and_what_next(tmp_path, capsys):
    assert mcp_verify.main(["--config", str(tmp_path / "nothere.json"), "--summary"]) == 1
    out = capsys.readouterr().out
    assert "FAIL 0/1 checks" in out and f"File not found: {tmp_path / 'nothere.json'}" in out
    assert "next: Check the configuration and upstream MCP server, then rerun verification." in out


# --- Ctrl-C -------------------------------------------------------------------------------------------------------------------

def test_ctrl_c_ends_a_command_with_one_line_not_a_traceback(monkeypatch, capsys):
    def interrupted(argv=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", interrupted)
    with pytest.raises(SystemExit) as stop:
        cli.main(["scan"])
    assert stop.value.code == 130 and capsys.readouterr().err == "intentshield: interrupted\n"
