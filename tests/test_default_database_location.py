"""A database nobody named goes to ``~/.intentshield``, as the command line puts it, and not into the working directory."""
from __future__ import annotations

from pathlib import Path

from intentshield.mcp_proxy import MCPProxyConfig
from intentshield.service import IntentShieldService
from intentshield.storage import Storage, default_database


def test_the_default_database_lives_under_the_home_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert Path(default_database()) == Path.home() / ".intentshield" / "intentshield.db"
    assert Path(default_database("x.db")).parent == Path.home() / ".intentshield"


def test_storage_with_no_path_writes_under_home_not_the_working_directory(tmp_path, monkeypatch):
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(work)
    storage = Storage()
    assert Path(storage.path) == Path.home() / ".intentshield" / "intentshield.db" and Path(storage.path).exists()
    assert list(work.iterdir()) == []


def test_the_service_default_and_a_proxy_config_without_a_path_do_the_same(tmp_path, monkeypatch):
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(work)
    IntentShieldService.default()
    config = MCPProxyConfig.model_validate({"upstreams": [{"server_id": "s", "transport": "stdio", "command": "x"}]})
    assert Path(config.database_path) == Path.home() / ".intentshield" / "intentshield-mcp.db"
    assert list(work.iterdir()) == []


def test_a_path_that_is_given_is_used_as_it_is(tmp_path):
    named = tmp_path / "mine" / "x.db"
    assert Storage(named).path == str(named) and named.exists()
    config = MCPProxyConfig.model_validate({"upstreams": [{"server_id": "s", "transport": "stdio", "command": "x"}],
                                            "database_path": str(named)})
    assert config.database_path == str(named)


def test_a_database_an_older_version_left_in_the_working_directory_is_kept(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert Path(default_database("intentshield-mcp.db")).parent == Path.home() / ".intentshield"
    (tmp_path / "intentshield-mcp.db").write_bytes(b"")
    assert default_database("intentshield-mcp.db") == "intentshield-mcp.db"
