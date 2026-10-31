"""Regression tests for the proxy group of the 2026-10-31 audit (proxy-6 and proxy-13, the scan command)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from intentshield import scan


def test_user_scope_servers_are_kept_when_the_cwd_has_a_project_entry(tmp_path: Path):
    """proxy-6: the local-scope entry was assigned to the loop's ``project`` flag, so a user's own server was
    treated as the repository's and never started."""
    home, cwd = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"usersrv": {"command": "x"}},
        "projects": {str(cwd): {"mcpServers": {"localsrv": {"command": "y"}}, "allowedTools": []}}}))
    (cwd / ".mcp.json").write_text(json.dumps({"mcpServers": {"reposrv": {"command": "z"}}}))
    found = {s.name: s.project for s in scan.discover(home, cwd)}
    assert found == {"usersrv": False, "localsrv": False, "reposrv": True}


def test_a_scan_that_started_nothing_does_not_exit_green(tmp_path: Path, capsys, monkeypatch):
    """proxy-6: all servers skipped (a repository's config, not connected) reported 'checked' and exit 0."""
    home, cwd = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    (cwd / ".mcp.json").write_text(json.dumps({"mcpServers": {"reposrv": {"command": "z"}}}))
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(cwd)
    args = argparse.Namespace(files=None, no_connect=False, connect_project=False, format="text", timeout=1.0,
                              pins=tmp_path / "pins.json", no_pins=True, update_pins=False)
    assert scan.run(args) == 2
    assert "0 of 1 server(s) checked" in capsys.readouterr().out


def _pin_run(monkeypatch, tmp_path: Path, tools_of: dict, *, update: bool = False, failing: tuple = ()) -> dict:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}}}))

    async def fake_list(server, timeout):
        if server.name in failing:
            server.error = "TimeoutError: slow start"
            return
        server.tools = [{"name": n, "title": None, "description": "Does a thing.", "input_schema": {"type": "object"},
                         "annotations": a} for n, a in tools_of[server.name]]

    monkeypatch.setattr(scan, "_list_tools", fake_list)
    args = argparse.Namespace(files=[cfg], no_connect=False, connect_project=False, format="json", timeout=5.0,
                              pins=tmp_path / "pins.json", no_pins=False, update_pins=update)
    rc = scan.run(args)
    return {"rc": rc, "pins": json.loads((tmp_path / "pins.json").read_text())}


def test_update_pins_keeps_the_baseline_of_a_server_that_did_not_start(tmp_path: Path, monkeypatch):
    """proxy-13: --update-pins wrote only the servers that started, so a rug pull made on the others was 'new'."""
    tools = {"a": [("t", {})], "b": [("t", {})]}
    first = _pin_run(monkeypatch, tmp_path, tools)["pins"]
    assert len(first) == 2
    later = _pin_run(monkeypatch, tmp_path, tools, update=True, failing=("b",))["pins"]
    assert later == first
    # a tool that vanished from a server that did start is dropped
    gone = _pin_run(monkeypatch, tmp_path, {"a": [("u", {})], "b": [("t", {})]}, update=True)["pins"]
    assert sorted(k.rsplit("|", 2)[-2:] for k in gone) == [["a", "u"], ["b", "t"]]


def test_a_changed_annotation_is_a_rug_pull_and_an_old_text_pin_is_moved_not_reported(tmp_path: Path, monkeypatch,
                                                                                   capsys):
    """proxy-13: the pin hashed the text only, so flipping readOnlyHint went unnoticed."""
    import hashlib

    from intentshield.mcp_inspect import tool_text

    ro = {"readOnlyHint": True}
    _pin_run(monkeypatch, tmp_path, {"a": [("t", ro)], "b": []})
    capsys.readouterr()
    result = _pin_run(monkeypatch, tmp_path, {"a": [("t", {"readOnlyHint": False})], "b": []})
    assert result["rc"] == 1 and "rug_pull" in capsys.readouterr().out
    # a pin an earlier version wrote (the text alone) is accepted once and upgraded, not reported
    pins = tmp_path / "pins.json"
    old = {k: hashlib.sha256(tool_text("Does a thing.", {"type": "object"}, None).encode()).hexdigest()
           for k in json.loads(pins.read_text())}
    pins.write_text(json.dumps(old))
    result = _pin_run(monkeypatch, tmp_path, {"a": [("t", ro)], "b": []})
    assert result["rc"] == 0 and all(v.startswith("v2:") for v in result["pins"].values())
