"""What ``install``, ``wrap`` and ``scan`` say when a file or a server is not what they expected."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from intentshield import install, scan


@pytest.fixture(autouse=True)
def _no_harness_probe(monkeypatch):
    monkeypatch.setattr(install.translation, "probe_and_record", lambda *args, **kwargs: None)


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: path))
    return path


def test_a_byte_order_mark_is_named_as_the_cause(tmp_path: Path):
    mcp = tmp_path / ".mcp.json"
    mcp.write_bytes(b"\xef\xbb\xbf" + json.dumps({"mcpServers": {"a": {"command": "x"}}}).encode())
    before = mcp.read_bytes()
    with pytest.raises(json.JSONDecodeError) as caught:
        install.wrap(mcp, out_dir=tmp_path / "out")
    assert "byte order mark" in str(caught.value) and "comments" not in str(caught.value)
    assert mcp.read_bytes() == before, "the file is left as it was"


def test_a_file_without_a_mark_still_gets_the_comments_hint(tmp_path: Path):
    mcp = tmp_path / ".mcp.json"
    mcp.write_text('{"mcpServers": {},}')
    with pytest.raises(json.JSONDecodeError) as caught:
        install.wrap(mcp, out_dir=tmp_path / "out")
    assert "comments and trailing commas" in str(caught.value) and "byte order mark" not in str(caught.value)


def test_wrap_asks_to_close_the_client_only_for_the_file_it_rewrites(tmp_path: Path, home: Path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    vscode = tmp_path / ".vscode" / "mcp.json"
    vscode.parent.mkdir()
    vscode.write_text(json.dumps({"servers": {"ok": {"command": "plain-server"}}}))
    install.wrap(vscode, out_dir=tmp_path / "out")
    assert "Next: restart the MCP client that reads" in (out := capsys.readouterr().out) and "claude.json" not in out
    claude = home / ".claude.json"
    claude.write_text(json.dumps({"mcpServers": {"ok": {"command": "plain-server"}}}))
    install.wrap(claude, out_dir=tmp_path / "out2")
    assert "close it before wrapping ~/.claude.json" in capsys.readouterr().out


def test_a_server_error_is_cut_at_a_word_and_ends_with_dots():
    line = "ImportError: " + "the old module was removed in this release, " * 12 + "see the migration guide at the docs site"
    out = scan._stderr_reason(line)
    kept = out[:-3]
    assert len(out) <= 303 and out.endswith("...") and line.startswith(kept) and line[len(kept)] in " ,;:"
    assert scan._stderr_reason("short line") == "short line"


def test_a_server_error_that_fits_is_not_changed():
    text = "ImportError: no module named x; see the migration guide"
    assert scan._clip(text) == text
    assert scan._clip("a" * 400).endswith("...") and len(scan._clip("a" * 400)) == 303


def test_a_scan_of_the_current_directory_says_how_to_start_one_file(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "plain-server"}}}))
    servers = scan.discover(tmp_path / "nohome", tmp_path)
    findings = scan.scan(servers)
    assert "intentshield scan .mcp.json" in scan.report(servers, findings, tmp_path / "nohome")
