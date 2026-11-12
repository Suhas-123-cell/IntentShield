"""What install, wrap, doctor and the verify command tell a person: the version line in plain words, a Codex config that switches
hooks off, a wrapped file that doctor does not read, and the log line of the verify command's canary call."""
# ruff: noqa: E501
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from intentshield import doctor, install, mcp_verify, translation
from intentshield.mcp_proxy import MCPProxyConfig


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))
    return path


def _hook(tmp_path: Path) -> str:
    exe = tmp_path / "bin" / "intentshield-hook"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    return str(exe)


def _doctor(home: Path, capsys) -> str:
    capsys.readouterr()
    doctor.doctor(home, home / "proj", home / ".intentshield" / "hooks.db")
    return capsys.readouterr().out


# --- the version line ---------------------------------------------------------------------------------------------------------

def test_install_says_in_plain_words_what_an_unread_harness_version_costs(tmp_path, home, capsys, monkeypatch):
    monkeypatch.setattr(translation, "probe_and_record", lambda *a, **k: None)
    install.install("claude", hook=_hook(tmp_path), home=home)
    out = capsys.readouterr().out
    assert "could not read the version of claude (it is not on PATH)" in out
    assert "blocked instead, which is the safe side" in out and "run `intentshield doctor`" in out
    assert "asks are sent as refusals" not in out


def test_install_says_the_version_it_found(tmp_path, home, capsys, monkeypatch):
    monkeypatch.setattr(translation, "probe_and_record", lambda *a, **k: (2, 1, 316))
    install.install("claude", hook=_hook(tmp_path), home=home)
    out = capsys.readouterr().out
    assert "claude version 2.1.316 found and recorded" in out and "the hook picks its replies" not in out


# --- Codex's feature flags ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("flag", ["codex_hooks", "hooks"])
def test_install_and_doctor_warn_when_codex_config_switches_hooks_off(tmp_path, home, capsys, flag):
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(f"[features]\n{flag} = false   # mine\n")
    install.install("codex", hook=_hook(tmp_path), home=home)
    out = capsys.readouterr().out
    assert f"`{flag} = false` under [features]" in out and "can switch Codex's hooks off" in out
    report = _doctor(home, capsys)
    assert any(line.startswith("warn") and f"[features] {flag} is false" in line for line in report.splitlines())
    assert "no problems found" in report or "warning(s)" in report


@pytest.mark.parametrize("features", ["", "[features]\ncodex_hooks = true\n", "[features]\nother = false\n", "[features]\nhooks = \"yes\"\n"])
def test_install_and_doctor_say_nothing_about_flags_that_leave_hooks_on(tmp_path, home, capsys, features):
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(features)
    install.install("codex", hook=_hook(tmp_path), home=home)
    assert "switch Codex's hooks off" not in capsys.readouterr().out
    assert "switch Codex's hooks off" not in _doctor(home, capsys)


def test_a_config_that_is_not_toml_is_not_a_reason_to_warn(tmp_path):
    bad = tmp_path / "config.toml"
    bad.write_text("[features\ncodex_hooks = false")
    assert install.codex_hooks_switched_off(bad) == ""
    assert install.codex_hooks_switched_off(tmp_path / "missing.toml") == ""


# --- what wrap tells a person to run next ----------------------------------------------------------------------------------------

def test_the_files_doctor_reads_are_the_ones_wrap_names_doctor_for(tmp_path, home):
    user_files, project_files = install.client_config_files(home, tmp_path)
    assert home / ".claude.json" in user_files and home / ".codex" / "config.toml" in user_files
    assert tmp_path / ".mcp.json" in project_files and tmp_path / ".vscode" / "mcp.json" in project_files


def test_doctor_says_where_it_looked_and_how_to_check_another_file_when_it_finds_nothing(tmp_path, home, capsys):
    out = _doctor(home, capsys)
    assert "nothing is installed: no IntentShield hooks and no wrapped MCP server were found, so nothing is guarded." in out
    assert "the usual config files of each client" in out and "intentshield scan <file>" in out


# --- the verify command ------------------------------------------------------------------------------------------------------------

def test_the_verify_command_starts_the_proxy_with_info_logs_off(tmp_path, monkeypatch):
    config = MCPProxyConfig.from_file(mcp_verify.demo_config(tmp_path))
    monkeypatch.delenv("INTENTSHIELD_LOG_LEVEL", raising=False)
    assert mcp_verify._stdio_target(tmp_path / "x.json", config).env["INTENTSHIELD_LOG_LEVEL"] == "WARNING"
    monkeypatch.setenv("INTENTSHIELD_LOG_LEVEL", "DEBUG")
    assert mcp_verify._stdio_target(tmp_path / "x.json", config).env["INTENTSHIELD_LOG_LEVEL"] == "DEBUG"


def test_the_summary_of_the_verify_command_prints_no_log_line(tmp_path):
    env = {**os.environ, "INTENTSHIELD_INTENT_MODEL_DIR": "/nonexistent", "INTENTSHIELD_PROXY_CONFIG": "", "INTENTSHIELD_CONTROL_TOKEN": "",
           "GEMINI_API_KEY": "", "GROQ_API_KEY": "", "HOME": str(tmp_path)}
    env.pop("INTENTSHIELD_LOG_LEVEL", None)
    done = subprocess.run([sys.executable, "-m", "intentshield.mcp_verify", "--demo", "--stdio", "--summary"], capture_output=True,
                          text=True, env=env, timeout=120, check=False, cwd=tmp_path)
    assert done.stdout.strip() == "PASS 13/13 checks", done.stderr[-500:]
    assert not [line for line in done.stderr.splitlines() if line.startswith("{") and '"policy decision"' in line]

