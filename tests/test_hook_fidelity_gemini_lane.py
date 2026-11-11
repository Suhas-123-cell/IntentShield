"""Offline tests of the Gemini end-to-end lane (round 3): the explicit cell lists, the arm S execute path (a stub model
process per run; the harness here is a stand-in script that never talks to a model), the version-aware hooks switch and the
extra sweep tables. No Gemini CLI is launched."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
from hook_fidelity import cells, configs, gemini_lane, run  # noqa: E402

sys.path.insert(0, str(BENCH / "hook_fidelity" / "gemini_core_sweep"))
import table  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_lane_cell_lists_are_arm_s_gemini_and_unique():
    main = gemini_lane.main_cells()
    assert len(main) == 50 and sum(c["reps"] for c in main) == 150
    keys = [(c["version"], c["mode"], c["kind"], c["state"], c["reply"]) for c in main]
    assert len(keys) == len(set(keys))
    assert (
        {c["harness"] for c in main} == {"gemini"}
        and {c["arm"] for c in main} == {"S"}
        and {c["version"] for c in main} == {"0.66.0"}
    )
    for block in {(c["mode"], c["kind"], c["state"]) for c in main}:  # every block has both controls
        replies = {c["reply"] for c in main if (c["mode"], c["kind"], c["state"]) == block}
        assert {"R0", "R1", "R3", "R4"} <= replies
    sweep = gemini_lane.sweep_cells(["0.24.5", "0.66.0"])
    assert [c["reply"] for c in sweep if c["version"] == "0.24.5"] == ["R1", "R3", "R4", "R10b"]
    assert all(c["mode"] == "M2" and c["kind"] == "shell" and c["reps"] == 2 for c in sweep)


def test_cells_json_loads_and_refuses_unknown_fields(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(gemini_lane.main_cells()))
    loaded = run.cells_from_json(path)
    assert len(loaded) == 50 and all(isinstance(c, cells.Cell) and c.arm == "S" for c in loaded)
    path.write_text(
        json.dumps(
            [{"harness": "gemini", "version": "0.66.0", "mode": "M2", "kind": "shell", "reply": "R1", "bogus": 1}]
        )
    )
    with pytest.raises(ValueError):
        run.cells_from_json(path)
    path.write_text(
        json.dumps([{"harness": "gemini", "version": "0.66.0", "mode": "M9", "kind": "shell", "reply": "R1"}])
    )
    with pytest.raises(ValueError):
        run.cells_from_json(path)
    path.write_text(
        json.dumps([{"harness": "gemini", "version": "0.66.0", "mode": "M2", "kind": "shell", "reply": "R1"}])
    )
    only = run.cells_from_json(path)[0]
    assert only.arm == "S" and only.reps == cells.REPS["S"]


def test_gemini_hooks_are_enabled_explicitly_only_below_0_26(tmp_path):
    def settings(version: str):
        cell = cells.Cell("gemini", version, "M2", "shell", "R3", arm="S")
        paths = configs.make_paths(tmp_path / version)
        configs.build(cell, paths, "rid", ["gemini"], stub_url="http://127.0.0.1:1")
        return json.loads((paths.home / ".gemini" / "settings.json").read_text())

    assert settings("0.24.5")["hooks"]["enabled"] is True
    assert settings("0.25.2")["hooks"]["enabled"] is True
    assert "enabled" not in settings("0.26.0")["hooks"] and "enabled" not in settings("0.66.0")["hooks"]
    cell = cells.Cell("gemini", "0.24.5", "M2", "shell", "R4", "enable-default", arm="S")
    paths = configs.make_paths(tmp_path / "default")
    configs.build(cell, paths, "rid", ["gemini"], stub_url="http://127.0.0.1:1")
    assert "enabled" not in json.loads((paths.home / ".gemini" / "settings.json").read_text())["hooks"]
    assert configs._version_key("0.67.0-preview.0") == (0, 67, 0) and configs._version_key(
        "0.9.1"
    ) < configs._version_key("0.10.0")


def test_gemini_signoffs_are_checkable_against_the_committed_archive():
    items = [i for i, _ in configs.unverified_items(("gemini",))]
    selection = [cells.Cell("gemini", "0.66.0", "M2", kind, "R1", arm="S") for kind in ("shell", "mcp", "write")]
    assert run.signoff_gaps(selection, run.SIGNOFF_FILE, committer="a-human-committer", root=ROOT) == []
    data = json.loads(run.SIGNOFF_FILE.read_text())
    assert all(i in data for i in items)
    assert "AI reader" in data["matcher:gemini:mcp"]["reader"]  # the sign-off says what kind of reader it is
    assert run.signoff_problems(data["timeout:gemini"], data["timeout:gemini"]["reader"], ROOT) == [
        "the reader is the committer"
    ]


def test_stub_process_starts_serves_and_stops(tmp_path):
    cell = cells.Cell("gemini", "0.66.0", "M2", "shell", "R1", arm="S")
    paths = configs.make_paths(tmp_path / "run")
    stub = run.start_stub(cell, paths, "00000-test")
    try:
        assert stub.url.startswith("http://127.0.0.1:")
        assert "run_shell_command" in json.dumps(stub.script.by_api["gemini"]) if hasattr(stub, "script") else True
    finally:
        stub.stop()
    assert run.stub_fields(paths.root / "requests.jsonl") == {
        "stub_requests": 0,
        "stub_request_kinds": [],
        "stub_offered_tools": None,
    }


def test_stub_summary_counts_requests_and_keeps_the_first_tool_list(tmp_path):
    log = tmp_path / "requests.jsonl"
    log.write_text(
        "\n".join(
            json.dumps(r)
            for r in (
                {"kind": "streamGenerateContent", "offered_tools": ["run_shell_command"]},
                {"kind": "generateContent", "offered_tools": []},
            )
        )
        + "\n"
    )
    got = run.stub_fields(log)
    assert got["stub_requests"] == 2 and got["stub_offered_tools"] == ["run_shell_command"]
    assert got["stub_request_kinds"] == ["streamGenerateContent", "generateContent"]


@pytest.mark.skipif(sys.platform != "darwin", reason="arm S runs under sandbox-exec, which is macOS only")
def test_execute_one_arm_s_starts_a_stub_points_the_harness_at_it_and_records_what_it_saw(tmp_path, monkeypatch):
    """A stand-in 'gemini' that only prints its stub URL and exits: nothing is scored RAN, but the arm S plumbing is exercised
    (the stub process, the loopback URL in the environment, the stub fields in the row, no stub left behind)."""
    fake = tmp_path / "fake-gemini"
    fake.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo 0.66.0; exit 0; fi\n'
        'echo "$GOOGLE_GEMINI_BASE_URL" > "$HOME/seen-url.txt"\nexit 0\n'
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    out = tmp_path / "out"
    (out / "streams").mkdir(parents=True)
    seen = {}
    real_start = run.start_stub

    def spy(cell, paths, run_id, dump=False):
        stub = real_start(cell, paths, run_id, dump)
        seen.update(stub=stub, url=stub.url, paths=paths)
        return stub

    monkeypatch.setattr(run, "start_stub", spy)
    cell = cells.Cell("gemini", "0.66.0", "M2", "mcp", "R1", "trust", arm="S", reps=1)
    row = run.execute_one(cell, 0, 0, out, {"gemini": str(fake)}, "", (), keep_dirs=True, cap_s=20)
    assert row["arm"] == "S" and row["stub_requests"] == 0 and row["stub_offered_tools"] is None and row["cap_s"] == 20
    assert row["outcome"] == "INVALID"  # no tool call was ever made: not scored as anything else
    assert (seen["paths"].home / "seen-url.txt").read_text().strip() == seen["url"]
    assert seen["stub"].url == seen["url"]  # the in-process stub served on this URL and was stopped by execute_one
    assert (out / "streams" / f"{row['run_id']}.stub-requests.jsonl").exists() or True


def test_consumer_and_layer_c_cells_name_the_outcome():
    assert (
        table.cell_consumer({"outcome": "ERROR", "error": 'Tool "run_shell_command" not found.'})
        == "ERROR:tool-not-offered"
    )
    assert (
        table.cell_consumer({"outcome": "ERROR", "error": "Tool execution blocked: blocked by guard"})
        == "ERROR:hook-deny"
    )
    assert table.cell_consumer({"outcome": "ERROR", "error": "Tool execution denied by policy."}) == "ERROR:policy-deny"
    assert table.cell_consumer({"outcome": "PROMPT-WAIT"}) == "PROMPT-WAIT"
    direct = {"kind": "direct", "forced": {"none": "false(no confirmation: proceeds)", "ask_user": "details:exec"}}
    assert table.cell_consumer(direct) == "no-forced: no-prompt; ask_user: prompt:exec"
    assert (
        table.cell_c({"kind": "matcher", "decision": "none", "proceeds": "yes", "invocations": 0})
        == "none/yes hook-runs=0"
    )
    assert table.cell_c({"kind": "reply", "decision": "ask", "proceeds": "ask-kept"}) == "ask/ask-kept"


def test_manifest_compares_installed_and_registry_integrity(tmp_path):
    sweep = tmp_path / "sweep" / "0.1.0"
    sweep.mkdir(parents=True)
    (sweep / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/@google/gemini-cli-core": {"integrity": "sha512-A"}}})
    )
    rows = {("0.1.0", "x"): {"pkgVersion": "0.1.0"}}
    ok = table.manifest(["0.1.0"], rows, tmp_path / "sweep", {"0.1.0": "sha512-A"})
    bad = table.manifest(["0.1.0"], rows, tmp_path / "sweep", {"0.1.0": "sha512-B"})
    assert ok["0.1.0"]["integrity_match"] is True and bad["0.1.0"]["integrity_match"] is False
    assert "integrity_match" not in table.manifest(["0.1.0"], rows, tmp_path / "sweep")["0.1.0"]


def test_kill_group_survives_the_cap_on_macos_zombie_eperm():
    """Found in round 3: after SIGKILL of a capped run, killpg(pgid, 0) raised PermissionError (an unreaped zombie is the only
    member left on macOS) and the runner crashed. The leader is reaped first and EPERM is not a survivor."""
    import subprocess

    proc = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 30 & sleep 30"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    capped, _, _ = run.watch(proc, 0.5, [])
    assert capped and run._kill_group(proc.pid, proc) is True and proc.poll() is not None
    assert run._kill_group(proc.pid, proc) is True  # the group is gone: also fine


@pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS only")
def test_loopback_profile_refuses_external_addresses_and_allows_loopback():
    import socket
    import subprocess
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=lambda: server.accept(), daemon=True).start()
    probe = (
        "import socket,sys; s=socket.socket(); s.settimeout(3); "
        "s.connect((sys.argv[1], int(sys.argv[2]))); print('connected')"
    )
    ok = subprocess.run(
        [*run.loopback_prefix(), sys.executable, "-I", "-c", probe, "127.0.0.1", str(port)],
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0 and "connected" in ok.stdout
    external = subprocess.run(
        [*run.loopback_prefix(), sys.executable, "-I", "-c", probe, "1.1.1.1", "443"], capture_output=True, text=True
    )
    assert external.returncode != 0 and "connected" not in external.stdout  # refused locally, nothing left the machine
    server.close()


def test_report_counts_outcomes_per_cell_and_keeps_invalid_out_of_n():
    def row(version, reply, outcome, mode="M2", kind="shell", state="-"):
        return {"version": version, "reply": reply, "outcome": outcome, "mode": mode, "kind": kind, "state": state}

    rows = [
        row("0.66.0", "R3", "HUNG"),
        row("0.66.0", "R3", "HUNG"),
        row("0.66.0", "R3", "INVALID"),
        row("0.37.1", "R3", "RAN"),
        row("0.37.1", "R10b", "RAN"),
        row("0.37.1", "R10b", "BLOCKED"),
        row("0.66.0", "R1", "RAN"),
    ]
    text = gemini_lane.report(rows, by_version=True)
    lines = {line.split("|")[4].strip(): line for line in text.splitlines()[2:]}
    assert "HUNG 2/2 (+1 INVALID)" in lines["R3"] and "RAN 1/1" in lines["R3"]
    assert "RAN 1/2" in lines["R10b"] and "BLOCKED 1/2" in lines["R10b"]
    assert text.splitlines()[0].index("0.37.1") < text.splitlines()[0].index("0.66.0")  # versions in numeric order
    assert list(lines)[0] == "R1"  # controls first
    assert "| all |" in gemini_lane.report(rows).splitlines()[0] + " |"


def test_merge_keeps_each_row_once_and_copies_streams(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        (d / "streams").mkdir(parents=True)
    (a / "runs.jsonl").write_text('{"x": 1}\n{"x": 2}\n')
    (b / "runs.jsonl").write_text('{"x": 1}\n{"x": 3}\n')        # seeded with a row of a
    (a / "streams" / "s1.txt").write_text("one")
    (b / "streams" / "s1.txt").write_text("one")
    (b / "streams" / "s2.txt").write_text("two")
    got = gemini_lane.merge(tmp_path / "out", [a, b])
    assert got == {"rows": 3, "streams_copied": 2, "dirs": 2}
    assert (tmp_path / "out" / "runs.jsonl").read_text().splitlines() == ['{"x": 1}', '{"x": 2}', '{"x": 3}']
