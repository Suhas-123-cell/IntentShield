"""Offline tests of the local-model lane (benchmarks/hook_fidelity/model_lane.py). No harness and no model is launched."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from hook_fidelity import model_lane as ml  # noqa: E402


def test_default_plan_is_within_the_cap_and_unique():
    cases = ml.plan()
    assert len(cases) == 54 <= ml.CAP
    assert len({ml.case_id(c) for c in cases}) == len(cases)
    counts = collections.Counter((c["arm_kind"], c["harness"], c["cell"]) for c in cases)
    for harness in ml.BUILDS:
        for cell in ("ask", "deny", "timeout", "malformed"):
            assert counts[("generic", harness, cell)] == 5
        assert counts[("generic", harness, "control")] == 1
        assert counts[("is", harness, "ask")] == counts[("is", harness, "timeout")] == 3


def test_replies_map_to_the_study_ids():
    assert ml.GENERIC == {"control": "R1", "ask": "R3", "deny": "R4", "timeout": "R9", "malformed": "R6"}


def test_budget_refusals():
    assert ml.check_budget(40, 2, "40") == ""
    assert "must equal" in ml.check_budget(40, 2, "41")
    assert "must equal" in ml.check_budget(40, 2, "")
    assert "exceeds the cap" in ml.check_budget(10, 55, "10")
    assert ml.check_budget(5, 55, "5") == ""


def test_ledger_counts_lines(tmp_path):
    assert ml.ledger_count(tmp_path) == 0
    (tmp_path / "launches.jsonl").write_text('{"a":1}\n\n{"a":2}\n')
    assert ml.ledger_count(tmp_path) == 2


def test_endpoint_must_be_loopback():
    assert ml.endpoint_is_local("http://127.0.0.1:11435")
    assert ml.endpoint_is_local("http://localhost:11434/")
    assert not ml.endpoint_is_local("https://api.example.com")
    assert not ml.endpoint_is_local("http://10.0.0.5:11434")
    assert not ml.endpoint_is_local("http://127.0.0.1.evil.example:80")


def test_prompt_calls_the_shim_by_absolute_path():
    p = ml.shell_prompt("/tmp/x/shim", "nzabc")
    assert "/tmp/x/shim/touch ran-nzabc.txt" in p and p.startswith("Run exactly this shell command")


def test_sandbox_profile_contains_the_model():
    text = ml.PROFILE.read_text()
    assert "(deny network-outbound)" in text and '(remote ip "localhost:*")' in text
    assert '(deny file-write* (subpath "/Users"))' in text
    assert "\\.env" in text


def test_select_filters_by_fields():
    cases = ml.plan()
    assert len(ml.select(cases, "arm_kind=is")) == 12
    assert len(ml.select(cases, "arm_kind=generic,cell=ask|deny")) == 20


def _row(arm_kind, harness, cell, outcome, hooks=1, attempted=True):
    return {"run_id": f"{arm_kind}{harness}{cell}{outcome}{hooks}{attempted}", "arm_kind": arm_kind,
            "harness": harness, "cell": cell, "outcome": outcome, "hook_invocations": hooks, "action_attempted": attempted}


def test_summary_agreement_and_tool_call_rate(tmp_path):
    root = tmp_path
    (root / "claude").mkdir()
    stub = [{"harness": "claude", "version": "2.1.316", "mode": "M1h", "kind": "shell", "reply": "R4", "outcome": "BLOCKED",
             "failcfg": "-", "variant": "plain"}] * 3
    (root / "claude" / "all-runs.jsonl").write_text("\n".join(json.dumps(r) for r in stub))
    rows = [_row("generic", "claude", "deny", "BLOCKED"), _row("generic", "claude", "deny", "RAN", hooks=1),
            _row("generic", "claude", "deny", "BLOCKED", hooks=2), _row("generic", "claude", "deny", "INVALID", 0, False)]
    s = ml.summarize(rows, root)
    c = s["cells"][0]
    assert (c["agree_k"], c["agree_n"], c["valid_n"], c["multi_call_runs"]) == (2, 3, 3, 1)
    assert c["stub_modal"] == "BLOCKED" and c["stub"] == {"BLOCKED": 3}
    assert s["tool_call_rate"]["claude"] == {"k": 3, "n": 4}
    assert "| generic |" in ml.render(s)


def test_modal_ignores_invalid():
    assert ml.modal({"INVALID": 5, "RAN": 1}) == "RAN"
    assert ml.modal({"INVALID": 2}) == ""


def test_committed_stub_baselines_exist_for_every_generic_cell():
    for harness in ml.BUILDS:
        for cell in ("ask", "deny", "timeout", "malformed"):
            assert sum(ml.stub_baseline(("generic", harness, cell)).values()) > 0, (harness, cell)
        for cell in ("ask", "timeout"):
            assert sum(ml.stub_baseline(("is", harness, cell)).values()) > 0, (harness, cell)
