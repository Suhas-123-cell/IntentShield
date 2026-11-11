"""A clean clone reproduces what the study documents say it reproduces.

The detection tables regenerate from the committed rows with no guard clone present, the corpus fetch plan matches
corpus.json, and generated scripts fall back to the running interpreter when the repository has no .venv. Nothing here uses the
network or launches a harness."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(BENCH))

import fetch_corpus as fc  # noqa: E402
import mitigation_eval as me  # noqa: E402

DETECT = ROOT / "results" / "hook-fidelity" / "detect"


def _clean_clone_env(scratch: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HF_SCRATCH"] = str(scratch)  # an empty directory: no corpus/ below it
    return env


def _run(args: list[str], scratch: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BENCH / "detect_compare.py"), *args], capture_output=True, text=True,
                          env=_clean_clone_env(scratch), cwd=ROOT, timeout=300)


# ------------------------------------------------------------------------------- report and breakdown without the guard clones
def test_report_and_breakdown_regenerate_byte_for_byte_with_no_clones(tmp_path):
    scratch, out = tmp_path / "empty-scratch", tmp_path / "out"
    scratch.mkdir()
    out.mkdir()
    decisions = str(DETECT / "decisions.jsonl")
    done = _run(["report", "--decisions", decisions, "--out", str(out)], scratch)
    assert done.returncode == 0, done.stderr[-800:]
    done = _run(["breakdown", "--decisions", decisions, "--out", str(out)], scratch)
    assert done.returncode == 0, done.stderr[-800:]
    for name in ("table.md", "summary.json", "delivery.json", "breakdown.md", "breakdown.json"):
        assert (out / name).read_bytes() == (DETECT / name).read_bytes(), name
    assert not (scratch / "corpus").exists()


def test_running_a_guard_without_its_clone_names_the_fetch_script(tmp_path):
    scratch = tmp_path / "empty-scratch"
    scratch.mkdir()
    done = _run(["decide", "--scratch", str(scratch), "--out", str(tmp_path / "d.jsonl"), "--guard", "knox"], scratch)
    assert done.returncode != 0
    assert "fetch_corpus.py" in done.stderr and not (tmp_path / "d.jsonl").exists()


# --------------------------------------------------------------------------------------------------------------- fetch plan
def test_fetch_plan_covers_every_pinned_guard(tmp_path):
    corpus = json.loads(fc.CORPUS.read_text())["guards"]
    items = fc.plan(scratch=tmp_path)
    assert len(items) == len(corpus) == 26
    assert [i["id"] for i in items] == [g["id"] for g in corpus]
    for item, g in zip(items, corpus):
        assert re.fullmatch(r"[0-9a-f]{40}", item["commit"]) and item["commit"] == g["commit"]
        assert item["repo"] == g["repo"] and item["repo"].startswith("https://github.com/")
        assert item["dest"] == str(tmp_path / "corpus" / g["dir"] / "repo") and item["present"] is False
    assert len({i["dest"] for i in items}) == 26


def test_fetch_plan_filters_and_rejects_unknown_guards(tmp_path):
    assert [i["id"] for i in fc.plan(scratch=tmp_path, only=["knox", "hookify-official"])] == ["hookify", "knox"]  # corpus order
    with pytest.raises(SystemExit):
        fc.plan(scratch=tmp_path, only=["no-such-guard"])


def test_fetch_plan_marks_an_existing_clone_and_dry_run_writes_nothing(tmp_path, capsys):
    (tmp_path / "corpus" / "knox" / "repo" / ".git").mkdir(parents=True)
    state = {i["id"]: i["present"] for i in fc.plan(scratch=tmp_path)}
    assert state["knox"] is True and sum(state.values()) == 1
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    assert fc.main(["--dry-run", "--scratch", str(tmp_path)]) == 0
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    text = capsys.readouterr().out
    assert "26 guard(s)" in text and "git fetch --depth 1 https://github.com/qoris-ai/knox" in text


def test_fetch_default_scratch_matches_the_clone_location_the_lanes_read(tmp_path):
    code = (f"import sys; sys.path.insert(0, {str(BENCH)!r}); import fetch_corpus, guard_capture; from pathlib import Path; "
            "print(fetch_corpus.default_scratch() == Path(guard_capture.SCRATCH_ROOT), guard_capture.CLONES.name)")
    for env in ({"HF_SCRATCH": str(tmp_path)}, {}):
        full = {k: v for k, v in os.environ.items() if k != "HF_SCRATCH"} | env
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=full, timeout=60)
        assert done.stdout.split() == ["True", "corpus"], done.stderr[-400:]


# ----------------------------------------------------------------------------------------------- interpreter of generated scripts
def test_generated_scripts_use_the_running_interpreter_when_the_repo_has_no_venv(tmp_path):
    assert me.pick_python(tmp_path) == sys.executable
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("")
    assert me.pick_python(tmp_path) == str(venv_python)
    assert me.VENV_PYTHON == me.pick_python(ROOT)
