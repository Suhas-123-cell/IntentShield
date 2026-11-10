"""Round 4 gap lane: the Codex matrices it added, the report script and the committed rows (no harness is launched)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

from hook_fidelity import codex_matrix, r4_report  # noqa: E402


def test_r4_matrices_sizes():
    persisted, r0 = codex_matrix.r4_persisted(), codex_matrix.r4_r0()
    assert sum(c.reps for c in persisted) == 24 and {c.state for c in persisted} == {"trusted-persisted"}
    assert sum(c.reps for c in r0) == 15 and {c.reply for c in r0} == {"R0"}
    assert not {c.version for c in r0} & set(codex_matrix.STAGE2_VERSIONS)


def test_r4_report_counts_valid_runs_only():
    base = {"harness": "codex", "version": "0.1", "mode": "M1", "kind": "shell", "state": "-",
            "reply": "R3", "hook_invoked": True}
    rows = [{**base, "outcome": "RAN"}, {**base, "outcome": "RAN"}, {**base, "outcome": "INVALID"}]
    text = r4_report.table(rows)
    assert "RAN 2/2" in text and "1 INVALID" in text


def test_committed_r4_rows_match_the_readme_counts():
    base = ROOT / "results" / "hook-fidelity"
    rows_path = base / "codex" / "r4-gaps" / "runs.jsonl"
    if not rows_path.is_file():
        return
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    persisted = [r for r in rows if r["state"] == "trusted-persisted" and r["reply"] in ("R3", "R5", "R9", "R11", "R16")]
    assert len(persisted) == 20 and all(r["outcome"] == "RAN" and r["hook_invoked"] is True for r in persisted)
    flip = [json.loads(x) for x in (base / "claude" / "r4-gaps" / "bisect" / "runs.jsonl").read_text().splitlines() if x.strip()]
    ask = {r["version"]: {x["outcome"] for x in flip if x["version"] == r["version"] and x["reply"] == "R3"} for r in flip}
    assert ask["2.1.84"] == {"RAN"} and ask["2.1.85"] == {"BLOCKED"}


def test_r4_integration_matrix_and_mitigation_plan(monkeypatch):
    assert sum(c.reps for c in codex_matrix.r4_persisted_b()) == 6
    assert {c.reply for c in codex_matrix.r4_persisted_b()} == {"R6", "R8", "R15"}
    sys.path.insert(0, str(ROOT / "benchmarks" / "hook_fidelity"))
    sys.path.insert(0, str(ROOT / "src"))
    import mitigation_eval

    plan = mitigation_eval.plan_r4()
    assert len(plan) == 36 and len({mitigation_eval.case_id(c) for c in plan}) == 36
    by = {}
    for c in plan:
        by[(c["scenario"], c["arm"])] = by.get((c["scenario"], c["arm"]), 0) + 1
    assert by == {("allow", "off"): 12, ("allow", "on"): 12, ("allow", "deny-all"): 6, ("slowdefault", "on"): 3, ("ask", "on"): 3}
    assert sum(1 for c in plan if c.get("norecord")) == 3


def test_deny_all_control_refuses_every_call_event_and_nothing_else(tmp_path):
    import subprocess

    hook = ROOT / "benchmarks" / "hook_fidelity" / "mitigation_hook.py"

    def run(event: dict) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(hook), "claude", "--eval-translate", "deny-all"], input=json.dumps(event),
                              capture_output=True, text=True, timeout=30)

    call = run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}})
    assert call.returncode == 2 and "refused" in call.stderr
    assert run({"hook_event_name": "PostToolUse", "tool_name": "Bash"}).returncode == 0
