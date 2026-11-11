"""Offline tests of the Cursor cells lane: the keychain-login run mode (real HOME for the login lookup only, config dir in
the run directory, sandbox-exec deny profile), the zsh shim for shell cells, the cap-10 plan and the quota error class.
Nothing here launches cursor-agent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
from hook_fidelity import cells, configs, cursor_cells, scoring  # noqa: E402


@pytest.fixture
def keychain(monkeypatch):
    monkeypatch.setattr(configs, "CURSOR_KEYCHAIN_LOGIN", True)


def _build(tmp_path, label="C1"):
    spec, cell, _ = cursor_cells.planned_runs((label,))[0]
    paths = configs.make_paths(tmp_path / "run")
    return cell, paths, configs.build(cell, paths, "00000-abcd", ["/bin/cursor-agent"], "auto", ())


def test_default_cursor_run_keeps_an_isolated_home(tmp_path):
    cell, paths, spec = _build(tmp_path)
    assert spec.env["HOME"] == str(paths.home) and spec.argv[0] == "/bin/cursor-agent"
    assert "CURSOR_CONFIG_DIR" not in spec.env
    assert configs.home_refusal("cursor", ()) != ""  # no login without a credential passed by name


def test_keychain_mode_uses_real_home_with_config_dir_and_sandbox(tmp_path, keychain):
    cell, paths, spec = _build(tmp_path)
    assert spec.env["HOME"] == str(Path.home())
    assert Path(spec.env["CURSOR_CONFIG_DIR"]).resolve().parent.parent == paths.root
    assert spec.argv[:3] == [configs.SANDBOX_EXEC, "-f", str(paths.root / "cursor-deny.sb")]
    assert configs.home_refusal("cursor", ()) == ""
    assert configs.user_level_leaks("cursor", paths, spec.env, system_files=(), argv=spec.argv) == []
    profile = (paths.root / "cursor-deny.sb").read_text()
    for name in (".cursor", ".claude", ".codex", ".gemini", ".config", ".ssh"):
        assert f'(subpath "{Path.home()}/{name}")' in profile
    assert "private-var-folders-" in profile and "(allow default)" in profile


def test_keychain_mode_flags_a_run_that_is_not_wrapped_or_not_relocated(tmp_path, keychain):
    cell, paths, spec = _build(tmp_path)
    assert any("keychain login mode" in p for p in configs.user_level_leaks(
        "cursor", paths, spec.env, system_files=(), argv=spec.argv[3:]))
    assert any("keychain login mode" in p for p in configs.user_level_leaks(
        "cursor", paths, {**spec.env, "CURSOR_CONFIG_DIR": str(Path.home() / ".cursor")}, system_files=(), argv=spec.argv))
    assert any("keychain login mode" in p for p in configs.user_level_leaks(
        "cursor", paths, {**spec.env, "HOME": str(paths.home)}, system_files=(), argv=spec.argv))
    hooks = Path(spec.env["CURSOR_CONFIG_DIR"]) / "hooks.json"
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_text("{}")
    assert any("hooks.json" in p for p in configs.user_level_leaks("cursor", paths, spec.env, (), argv=spec.argv))


def test_shell_cell_puts_the_touch_shim_first_in_every_zsh_start_file(tmp_path, keychain):
    cell, paths, spec = _build(tmp_path, "C3")
    zdot = Path(spec.env["ZDOTDIR"])
    for name in (".zshenv", ".zprofile", ".zshrc"):
        assert str(paths.shim_dir) in (zdot / name).read_text()
    assert (paths.shim_dir / "touch").is_file()
    mcp = _build(tmp_path / "m", "C1")[2]
    assert "ZDOTDIR" not in mcp.env


def test_cap10_plan_is_nine_runs_in_priority_order_and_covers_every_cell_once():
    runs = cursor_cells.planned_runs(profile="cap10")
    assert len(runs) == 9 and runs[0][0].label == "K1"
    assert {s.label for s, _, _ in runs} == {"K1", "C1", "D1", "E1", "K2", "E2", "C2", "C3"}
    assert sum(s.reps for s in cursor_cells.SPECS) == 38  # the designed plan stays under the 40 cap


def test_cells_match_the_matrix_keys_and_predictions():
    c1, e2 = (cursor_cells.cell_of(s) for s in cursor_cells.SPECS if s.label in ("C1", "E2"))
    assert (c1.state, c1.reply, c1.failcfg, c1.kind) == ("listed", "R3", "-", "mcp")
    assert (e2.reply, e2.failcfg) == ("R5", "closed")
    keys = {c.key for c in cells.generate()}
    assert c1.key in keys and e2.key in keys  # the lane's cells exist in the generated matrix


def test_usage_limit_text_is_a_rate_limit_not_an_unexplained_invalid():
    kind, _ = scoring.classify_errors("ActionRequiredError: You've hit your usage limit Get Cursor Pro for more Agent usage")
    assert kind == "rate_limit"


def test_reported_model_comes_from_the_event_stream():
    stream = json.dumps({"type": "system", "subtype": "init", "model": "Auto"}) + "\nnot json\n"
    assert cursor_cells.reported_model(stream) == "Auto" and cursor_cells.reported_model("") == ""
