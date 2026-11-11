"""Round 8 Linux probe (benchmarks/hook_fidelity/linux_probe.py): the case matrix, the constructed ground truth, the hook
subcommand and the committed rows. No container is started here; the committed rows came from one."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HF = Path(__file__).resolve().parents[1] / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(HF))

import linux_probe  # noqa: E402

LINUX = HF.parents[1] / "results" / "hook-fidelity" / "linux"


def test_matrix_has_unique_ids_and_every_case_has_a_constructed_expectation():
    cases = linux_probe.matrix_cases()
    assert len({c["id"] for c in cases}) == len(cases) == 28
    assert {c["harness"] for c in cases} == {"claude", "codex", "gemini"}
    modes = {linux_probe.expected(c)[0] for c in cases}
    assert modes == {"headless", "interactive", "unknown"}


def test_expected_modes_follow_the_construction():
    base = {"harness": "claude", "form": "native", "headless_flag": False, "pty": False}
    assert linux_probe.expected(base) == ("headless", "no terminal")
    assert linux_probe.expected({**base, "pty": True}) == ("interactive", "terminal and no headless flag")
    assert linux_probe.expected({**base, "headless_flag": True, "pty": True})[0] == "headless"
    assert linux_probe.expected({**base, "form": "none"})[1] == "not found among the ancestors"
    assert linux_probe.expected({**base, "sources": "ps"})[0] == "unknown"


def test_case_argv_names_the_dummy_harness_and_its_flag():
    case = {"harness": "claude", "form": "native", "headless_flag": True, "pty": False, "sources": None, "nested": False}
    argv = linux_probe.case_argv(case, "/tmp/x.json")
    assert argv[:3] == [f"{linux_probe.BIN}/claude", "-p", "-c"] and "--harness claude" in argv[3]
    node = linux_probe.case_argv({**case, "harness": "codex", "form": "node"}, "/tmp/x.json")
    assert node[:2] == [f"{linux_probe.BIN}/node/codex", "exec"]
    nested = linux_probe.case_argv({**case, "nested": True}, "/tmp/x.json")
    assert nested[:4] == ["env", "PROBE_NESTED=1", "timeout", "60"]


def test_the_hook_subcommand_reads_this_process_ancestry(tmp_path):
    out = tmp_path / "hook.json"
    done = subprocess.run([sys.executable, str(HF / "linux_probe.py"), "hook", "--harness", "claude", "--out", str(out)],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    record = json.loads(out.read_text())
    assert record["mode"] in ("interactive", "headless", "yolo", "unknown") and record["how"]
    assert record["source"] in ("proc", "libproc", "ps", "none") and isinstance(record["chain"], list)


def test_agree_needs_the_expected_reason_and_mode_equal_does_not():
    got = {"mode": "headless", "how": "the harness process was not found among the ancestors: assumed headless"}
    assert linux_probe._agree(got, "headless", "headless flag") == {"mode_equal": True, "agree": False}
    assert linux_probe._agree(got, "interactive", "x") == {"mode_equal": False, "agree": False}


@pytest.mark.parametrize("sub, rnd", [("", "r8"), ("r8fix", "r8fix")])
def test_committed_rows_regenerate_the_summary(sub, rnd):
    rows_path = LINUX / sub / "rows.jsonl"
    if not rows_path.exists():
        pytest.skip("no committed rows")
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    summary = json.loads((LINUX / sub / "summary.json").read_text())
    assert summary["rows"] == len(rows) and summary["agree"] == sum(bool(r.get("agree")) for r in rows)
    for group, got in summary["by_group"].items():
        sub = [r for r in rows if r.get("group") == group]
        assert got["n"] == len(sub) and got["agree"] == sum(bool(r.get("agree")) for r in sub)
        assert got["mode_equal"] == sum(bool(r.get("mode_equal")) for r in sub)
    assert all(r.get("round") == rnd for r in rows)
    assert all(r["source"] in ("proc", "none") for r in rows if "source" in r)    # never ps: the image has none


def test_the_r8fix_rerun_reads_a_harness_that_is_pid_1():
    path = LINUX / "r8fix" / "pid1.jsonl"
    if not path.exists():
        pytest.skip("no committed rows")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(rows) == 8 and all(r["agree"] and r["source"] == "proc" for r in rows)
    assert sum(r["mode"] == "interactive" for r in rows) == 2
    assert all("claude" in r["chain"][-1][1] for r in rows)        # the last process read is the harness, PID 1
