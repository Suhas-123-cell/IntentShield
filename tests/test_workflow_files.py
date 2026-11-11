"""The workflow files and the documents agree with pyproject.toml on how to install and which Pythons are supported.

PyYAML is not a dependency, so the YAML is read by lines: a plain scalar with ``: `` inside it is a YAML error that GitHub
rejects and no other test would see."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_no_step_name_is_a_plain_scalar_with_a_colon_and_space():
    bad = []
    for path in WORKFLOWS:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"\s*(?:- )?name:\s+([^'\"|>].*)$", line)
            if match and ": " in match.group(1).split(" #")[0]:
                bad.append(f"{path.name}:{number}")
    assert not bad, f"quote these names, or remove the colon: {bad}"


def test_nothing_installs_a_dev_extra_that_the_package_no_longer_has():
    assert "dev" not in PYPROJECT["project"]["optional-dependencies"]
    assert "dev" in PYPROJECT["dependency-groups"]
    files = [*WORKFLOWS, ROOT / "Dockerfile", ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "docs" / "demo.tape",
             *(ROOT / "docs" / name for name in ("architecture-and-testing.md", "gateway.md", "guide.md", "layers.md"))]
    stale = [p.name for p in files if re.search(r"--extra dev|\[dev\]", p.read_text(encoding="utf-8"))]
    assert not stale, f"these still name the dev extra: {stale}"


def test_every_supported_python_has_a_classifier_and_a_ci_job():
    minimum = re.search(r">=\s*3\.(\d+)", PYPROJECT["project"]["requires-python"])
    assert minimum
    classifiers = {c for c in PYPROJECT["project"]["classifiers"] if c.startswith("Programming Language :: Python :: 3.")}
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    listed = re.search(r"python:\s*\[([^\]]*)\]", ci)
    assert listed
    in_ci = {m for m in re.findall(r"3\.\d+", listed.group(1))}
    assert f"3.{minimum.group(1)}" in in_ci, "the oldest supported Python has no test job"
    assert in_ci == {c.rsplit(" :: ", 1)[1] for c in classifiers}
