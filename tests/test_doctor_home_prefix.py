"""``intentshield doctor`` writes the home directory as ``~`` only where a path starts, and prints a wrap command that can be
copied."""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

import pytest

from intentshield import doctor


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))
    return path


def test_a_path_that_only_contains_the_home_directory_is_left_whole(capsys):
    report = doctor.Report(Path("/data/home"))
    report.line("warn", "/mnt/data/home/proj/.mcp.json", "see /mnt/data/home/proj/x and /data/home/.intentshield/hooks.db")
    out = capsys.readouterr().out
    assert "/mnt/data/home/proj/.mcp.json" in out and "/mnt/data/home/proj/x" in out
    assert "~/.intentshield/hooks.db" in out and "/mnt~" not in out


def test_the_resolved_name_of_the_home_directory_is_shortened_too(tmp_path: Path, capsys):
    real = tmp_path / "real"
    (real / "proj").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real)
    doctor.Report(link).line("ok", f"{real}/proj/.mcp.json", f"config {link}/proj/b")
    assert capsys.readouterr().out.strip().endswith("ok   ~/proj/.mcp.json: config ~/proj/b")


def test_the_home_directory_is_shortened_after_a_quote_or_a_space(capsys):
    doctor.Report(Path("/Users/x")).line("FAIL", "/Users/x/.claude/settings.json", "runs '/Users/x/bin/h' and /Users/x/bin/g")
    out = capsys.readouterr().out
    assert "~/.claude/settings.json: runs '~/bin/h' and ~/bin/g" in out


def test_the_wrap_command_is_the_whole_path_and_can_be_copied(tmp_path: Path, home: Path, capsys):
    project = home / "my proj"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node", "args": ["server.js"]}}}))
    doctor.doctor(home, project, home / ".intentshield" / "hooks.db")
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "not behind the transparent proxy" in ln)
    command = line[line.index("Run `") + 5:line.rindex("`")]
    assert shlex.split(command) == ["intentshield", "wrap", str(project / ".mcp.json")]
    assert "~" not in command


def test_the_wrap_command_of_a_plain_path_is_copyable_too(tmp_path: Path, home: Path, capsys):
    project = home / "proj"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node"}}}))
    doctor.doctor(home, project, home / ".intentshield" / "hooks.db")
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "not behind the transparent proxy" in ln)
    command = line[line.index("Run `") + 5:line.rindex("`")]
    assert os.path.isfile(shlex.split(command)[2])
