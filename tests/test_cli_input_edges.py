"""Config shapes that once broke wrap, unwrap or scan."""
import argparse
import json

import pytest

from intentshield import install, scan


def test_wrap_does_not_forward_an_empty_env_value(tmp_path):
    server = {"command": "echo", "env": {"FOO": "x", "EMPTY": ""}}
    upstream = install.proxy_config("s", server, tmp_path)["upstreams"][0]
    assert upstream["env_from_env"] == {"FOO": "FOO"}
    assert "env_from_env" not in install.proxy_config("s", {"command": "echo", "env": {"EMPTY": ""}}, tmp_path)["upstreams"][0]


def test_unwrap_leaves_a_hand_written_proxy_entry(tmp_path):
    config = tmp_path / "my.json"
    config.write_text(json.dumps({"upstreams": [{"server_id": "a", "transport": "stdio", "command": "echo"},
                                                {"server_id": "b", "transport": "stdio", "command": "cat"}]}))
    entry = {"command": "intentshield-mcp", "args": ["--transparent", "--config", str(config)]}
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"guarded": entry}}))
    with pytest.raises(ValueError, match="several upstreams"):
        install.unwrap(path)
    assert json.loads(path.read_text())["mcpServers"]["guarded"] == entry


def test_unwrap_of_an_entry_without_config_says_so(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"s": {"command": "intentshield-mcp", "args": ["--transparent"]}}}))
    with pytest.raises(ValueError, match="names no --config"):
        install.unwrap(path)


@pytest.mark.parametrize("entry", [{"command": "echo", "env": ["A=1"]}, {"command": "echo", "args": 5},
                                   {"url": "https://example.com/mcp", "headers": ["x"]}])
def test_scan_reports_a_malformed_entry(tmp_path, entry):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"bad": entry}}))
    servers = scan.discover(tmp_path, tmp_path, [path])
    scan.scan(servers, connect=True, timeout=5, pins={})
    assert servers[0].error and "malformed entry" in servers[0].error


def test_scan_reads_a_config_with_comments(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{\n  // my servers\n  "mcpServers": {"s": {"command": "echo"}} /* end */\n}')
    servers = scan.discover(tmp_path, tmp_path, [path])
    assert [s.name for s in servers] == ["s"] and servers[0].error is None


def _args(files, **kw):
    return argparse.Namespace(files=files, no_connect=True, no_pins=True, update_pins=False, pins=None, timeout=5,
                              connect_project=False, format="text", **kw)


def test_scan_of_a_missing_file_is_not_green(tmp_path, capsys):
    assert scan.run(_args([tmp_path / "nope.json"])) == 2
    assert "no such file" in capsys.readouterr().err


def test_scan_of_an_unreadable_config_is_not_green(tmp_path, capsys):
    path = tmp_path / "mcp.json"
    path.write_text("{not json")
    assert scan.run(_args([path])) == 2
