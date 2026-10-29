"""``intentshield install|uninstall|wrap|unwrap``: the hook and proxy installers."""
from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path

import pytest

from intentshield import __main__ as cli
from intentshield import install

ROOT = Path(__file__).resolve().parents[1]


def _normalize(command: str, data):
    """The committed example configs name the bare command; the installer names a path."""
    return json.loads(json.dumps(data).replace(command, "intentshield-hook"))


@pytest.mark.parametrize("harness,example", [("claude", "claude-settings.json"), ("cursor", "cursor-hooks.json"),
                                             ("gemini", "gemini-settings.json")])
def test_installed_hooks_match_the_shipped_examples(tmp_path: Path, harness: str, example: str):
    home = tmp_path / "home"
    path = install.install(harness, "user", hook="/opt/is/bin/intentshield-hook", home=home)
    assert path == home / {"claude": ".claude/settings.json", "cursor": ".cursor/hooks.json",
                           "gemini": ".gemini/settings.json"}[harness]
    written = _normalize("/opt/is/bin/intentshield-hook", json.loads(path.read_text()))
    assert written == json.loads((ROOT / "configs" / "harness" / example).read_text())


def test_codex_block_matches_the_shipped_example(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('model = "o3"\n')
    path = install.install("codex", "user", hook="intentshield-hook", home=home)
    parsed = tomllib.loads(path.read_text())
    assert parsed["model"] == "o3"
    assert parsed["hooks"] == tomllib.loads((ROOT / "configs" / "harness" / "codex-config.toml").read_text())["hooks"]
    # Idempotent, then reversible.
    install.install("codex", "user", hook="intentshield-hook", home=home)
    assert path.read_text().count(install._TOML_BEGIN) == 1
    install.uninstall("codex", "user", home=home)
    assert tomllib.loads(path.read_text()) == {"model": "o3"}


def test_install_keeps_other_hooks_and_is_idempotent_and_reversible(tmp_path: Path):
    home = tmp_path / "home"
    path = home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    theirs = {"type": "command", "command": "my-linter"}
    path.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]},
                                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [theirs]}]}}))
    install.install("claude", "user", hook="intentshield-hook", review="always", home=home)
    install.install("claude", "user", hook="intentshield-hook", review="always", home=home)
    settings = json.loads(path.read_text())
    assert settings["permissions"] == {"allow": ["Bash(ls)"]}
    assert settings["hooks"]["PreToolUse"][0]["hooks"] == [theirs]
    ours = [g for g in settings["hooks"]["PreToolUse"] if any(install._ours(h) for h in g["hooks"])]
    assert len(ours) == 1
    assert ours[0]["hooks"][0]["command"] == "intentshield-hook claude --review always"
    assert ours[0]["hooks"][0]["onFailure"] == "block"
    assert len(settings["hooks"]["UserPromptSubmit"]) == 1
    install.uninstall("claude", "user", home=home)
    assert json.loads(path.read_text()) == {"permissions": {"allow": ["Bash(ls)"]},
                                            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [theirs]}]}}


def test_project_scope_and_codex_has_none(tmp_path: Path):
    cwd = tmp_path / "repo"
    path = install.install("gemini", "project", hook="intentshield-hook", cwd=cwd, home=tmp_path / "home")
    assert path == cwd / ".gemini" / "settings.json"
    assert "BeforeTool" in json.loads(path.read_text())["hooks"]
    with pytest.raises(ValueError, match="scope user"):
        install.install("codex", "project", hook="intentshield-hook", cwd=cwd, home=tmp_path / "home")


def test_install_refuses_a_settings_file_it_cannot_read(tmp_path: Path):
    home = tmp_path / "home"
    path = home / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    with pytest.raises(json.JSONDecodeError):
        install.install("cursor", "user", hook="intentshield-hook", home=home)
    assert path.read_text() == "{not json"


def test_dry_run_writes_nothing(tmp_path: Path, capsys):
    home = tmp_path / "home"
    install.install("claude", "user", hook="intentshield-hook", dry_run=True, home=home)
    assert not (home / ".claude" / "settings.json").exists()
    assert "would write" in capsys.readouterr().out


def test_wrap_puts_the_proxy_in_front_of_stdio_servers_and_unwrap_restores_them(tmp_path: Path):
    mcp = tmp_path / ".mcp.json"
    original = {"mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
        "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_secret"}},
        "remote": {"url": "https://mcp.example.com/mcp"},
    }}
    mcp.write_text(json.dumps(original))
    out = tmp_path / "proxies"
    assert install.wrap(mcp, out_dir=out, proxy="/opt/is/bin/intentshield-mcp") == ["filesystem", "github"]
    data = json.loads(mcp.read_text())
    assert data["mcpServers"]["remote"] == {"url": "https://mcp.example.com/mcp"}
    fs = data["mcpServers"]["filesystem"]
    assert fs["command"] == "/opt/is/bin/intentshield-mcp"
    assert fs["args"][:2] == ["--transparent", "--config"]
    config = json.loads(Path(fs["args"][2]).read_text())
    assert config["upstreams"] == [{"server_id": "filesystem", "transport": "stdio", "command": "npx",
                                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}]
    assert config["database_path"] == str(out / "filesystem.db")
    # The secret stays in the harness file (set on the proxy process) and is forwarded by name only.
    gh = data["mcpServers"]["github"]
    assert gh["env"] == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_secret"}
    gh_config = Path(gh["args"][2]).read_text()
    assert json.loads(gh_config)["upstreams"][0]["env_from_env"] == {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "GITHUB_PERSONAL_ACCESS_TOKEN"}
    assert "ghp_secret" not in gh_config
    # The generated configs are ones the proxy accepts.
    from intentshield.mcp_proxy import MCPProxyConfig
    MCPProxyConfig.from_file(fs["args"][2])
    MCPProxyConfig.from_file(gh["args"][2])
    # Idempotent, then reversible.
    assert install.wrap(mcp, out_dir=out, proxy="/opt/is/bin/intentshield-mcp") == []
    assert install.unwrap(mcp) == ["filesystem", "github"]
    assert json.loads(mcp.read_text()) == original


def test_wrap_names_unknown_servers(tmp_path: Path):
    mcp = tmp_path / "mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    with pytest.raises(ValueError, match="no such server"):
        install.wrap(mcp, servers=["b"], out_dir=tmp_path, proxy="intentshield-mcp")


def test_cli_dispatches_and_reports_errors(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["install", "claude", "--dry-run"])
    assert exit_.value.code == 0
    assert "would install claude hooks" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_:
        cli.main(["wrap", str(tmp_path / "missing.json")])
    assert exit_.value.code == 1
    assert "does not exist" in capsys.readouterr().err


def test_executable_is_found_beside_an_unresolved_interpreter_symlink(tmp_path: Path, monkeypatch):
    """A uv venv's python is a symlink to an interpreter with no scripts beside it; the scripts
    sit beside the symlink, so the path must not be resolved first."""
    real = tmp_path / "toolchain" / "bin"
    real.mkdir(parents=True)
    (real / "python3.12").write_text("")
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(real / "python3.12")
    (venv / "intentshield-hook").write_text("")
    monkeypatch.setattr(install.sys, "executable", str(venv / "python"))
    monkeypatch.setattr(install.sys, "prefix", str(tmp_path / "venv"))
    assert install.executable("intentshield-hook") == str(venv / "intentshield-hook")
    monkeypatch.setattr(install.shutil, "which", lambda name: None)
    assert install.executable("intentshield-mcp") == "intentshield-mcp"


_THEIRS = {
    "claude": {"permissions": {"allow": ["Bash(ls)"]},
               "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}},
    "cursor": {"version": 1, "hooks": {"beforeShellExecution": [{"command": "their-hook"}]}},
    "gemini": {"theme": "dark", "hooks": {"BeforeTool": [{"matcher": "run_shell_command",
                                                          "hooks": [{"type": "command", "command": "their-hook"}]}]}},
}


@pytest.mark.parametrize("style", ["indented", "hand-written"])
@pytest.mark.parametrize("scope", ["user", "project"])
@pytest.mark.parametrize("harness", ["claude", "cursor", "gemini"])
def test_install_then_uninstall_restores_every_json_settings_file_byte_for_byte(tmp_path: Path, harness: str,
                                                                               scope: str, style: str):
    home, cwd = tmp_path / "home", tmp_path / "repo"
    path = install.settings_path(harness, scope, home, cwd)
    path.parent.mkdir(parents=True)
    theirs = {**_THEIRS[harness], "note": "naïve ☃"}
    before = (json.dumps(theirs, indent=2) + "\n" if style == "indented"
              else json.dumps(theirs, indent=4, ensure_ascii=False).replace("\n    ", "\n\t"))
    path.write_text(before)
    install.install(harness, scope, hook="intentshield-hook", home=home, cwd=cwd)
    assert "intentshield-hook" in path.read_text()
    install.uninstall(harness, scope, home=home, cwd=cwd)
    assert path.read_text() == before


def test_uninstall_after_the_user_edited_the_file_keeps_their_edit_and_text(tmp_path: Path):
    home = tmp_path / "home"
    path = home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"theme": "dark", "note": "naïve ☃"}')
    install.install("claude", "user", hook="intentshield-hook", home=home)
    path.write_text(path.read_text().replace('"dark"', '"light"'))
    install.uninstall("claude", "user", home=home)
    assert json.loads(path.read_text()) == {"theme": "light", "note": "naïve ☃"} and "☃" in path.read_text()
    assert not list((home / ".intentshield" / "backups").iterdir())


def test_wrap_then_unwrap_restores_the_mcp_file_byte_for_byte(tmp_path: Path):
    path = tmp_path / ".mcp.json"
    before = '{"mcpServers": {"notes": {"command": "uvx", "args": ["notes-mcp"], "env": {"NAME": "t \\u2713"}}}}'
    path.write_text(before)
    install.wrap(path, out_dir=tmp_path / "proxies", proxy="intentshield-mcp")
    assert "--transparent" in path.read_text()
    install.unwrap(path)
    assert path.read_text() == before


def test_codex_install_then_uninstall_restores_the_file(tmp_path: Path):
    home = tmp_path / "home"
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    before = 'model = "o3"\n\n[mcp_servers.demo]\ncommand = "demo"\n'
    path.write_text(before)
    install.install("codex", "user", hook="intentshield-hook", home=home)
    assert "intentshield-hook" in path.read_text()
    install.uninstall("codex", "user", home=home)
    assert path.read_text() == before


def test_hook_command_quotes_and_validates_its_arguments():
    assert install.hook_command("claude", "/opt/is/bin/intentshield-hook", review="always",
                                judge="groq:openai/gpt-oss-20b") == \
        "/opt/is/bin/intentshield-hook claude --review always --judge groq:openai/gpt-oss-20b"
    with pytest.raises(ValueError, match="judge"):
        install.hook_command("claude", judge="groq:$(touch /tmp/pwned)")
    with pytest.raises(ValueError, match="review"):
        install.hook_command("claude", review="sometimes")
    assert install.hook_command("claude", "h", judge="ollama", judge_outputs=True) == \
        "h claude --judge ollama --judge-outputs"
    assert install.hook_command("claude", "h", judge_outputs=True) == "h claude"  # only with a judge


def test_judge_outputs_is_refused_without_a_judge(capsys):
    parser = argparse.ArgumentParser()
    install.add_subcommands(parser.add_subparsers(dest="command"))
    assert install.run(parser.parse_args(["install", "claude", "--judge-outputs", "--dry-run"])) == 1
    assert "--judge-outputs needs --judge" in capsys.readouterr().err


def test_install_writes_through_a_settings_symlink(tmp_path: Path):
    home = tmp_path / "home"
    target = tmp_path / "dotfiles" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}\n")
    link = home / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    install.install("claude", "user", hook="intentshield-hook", home=home)
    assert link.is_symlink() and "intentshield-hook" in target.read_text()


def test_a_wrapped_server_with_an_env_block_answers_tool_calls(tmp_path: Path, monkeypatch):
    """`wrap` turns a literal env block into env_from_env; the proxy must still forward the
    variable and the calls (an operator-reported failure mode)."""
    import asyncio
    import sys

    from mcp import Client

    from intentshield.mcp_proxy import MCPProxyConfig, MCPProxyRuntime
    from intentshield.mcp_server import create_transparent_mcp_server

    home = tmp_path / "home"
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text(json.dumps({"mcpServers": {"demo": {
        "command": sys.executable, "args": ["-m", "intentshield.demo_mcp_server"],
        "env": {"DEMO_TOKEN": "secret-value-123"}}}}))
    install.wrap(mcp_json, out_dir=home / ".intentshield" / "proxies")
    generated = json.loads(mcp_json.read_text())["mcpServers"]["demo"]
    assert generated["env"] == {"DEMO_TOKEN": "secret-value-123"}  # the client still owns the secret
    config = MCPProxyConfig.from_file(generated["args"][generated["args"].index("--config") + 1])
    assert config.upstreams[0].env_from_env == {"DEMO_TOKEN": "DEMO_TOKEN"}
    monkeypatch.setenv("DEMO_TOKEN", "secret-value-123")
    shield = MCPProxyRuntime(config)
    server = create_transparent_mcp_server(config, runtime=shield)

    async def exercise() -> None:
        async with Client(server, mode="legacy") as client:
            assert "read_note" in {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool("read_note", {"note_id": "welcome"})
            assert not result.is_error and "IntentShield demo note" in result.content[0].text

    asyncio.run(exercise())


def test_uninstall_removes_a_file_that_held_only_our_hooks_and_the_cli_dispatches(tmp_path: Path, capsys):
    from intentshield import __main__ as cli

    home = tmp_path / "home"
    path = install.install("claude", "user", hook="intentshield-hook", home=home)
    assert path.exists()
    install.uninstall("claude", "user", home=home)
    assert not path.exists() and "removed" in capsys.readouterr().out
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"demo": {"command": "demo-server", "args": []}}}))
    for argv in (["wrap", str(mcp), "--out-dir", str(tmp_path / "proxies")], ["unwrap", str(mcp)]):
        with pytest.raises(SystemExit) as exit_:
            cli.main(argv)
        assert exit_.value.code == 0
    assert json.loads(mcp.read_text())["mcpServers"]["demo"] == {"command": "demo-server", "args": []}
    out = capsys.readouterr().out
    assert "wrapped 1 server" in out and "unwrapped 1 server" in out and "kept" in out


def test_codex_install_says_the_hooks_must_be_trusted_before_they_run(tmp_path: Path, capsys):
    install.install("codex", "user", hook="intentshield-hook", home=tmp_path / "home")
    out = capsys.readouterr().out
    assert "trust" in out and "NOT guarded" in out
