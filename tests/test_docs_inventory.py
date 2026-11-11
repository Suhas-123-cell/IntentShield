"""The module map and the test inventory in docs/architecture-and-testing.md name every module and every test file."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "docs" / "architecture-and-testing.md").is_file():
    pytest.skip("needs the repository's docs/ (a full clone, not an installed package)", allow_module_level=True)
DOC = (ROOT / "docs" / "architecture-and-testing.md").read_text(encoding="utf-8")


def test_every_module_is_in_the_module_map():
    package = ROOT / "src" / "intentshield"
    missing = [p.relative_to(package).as_posix() for p in sorted(package.rglob("*.py"))
               if p.stem != "__init__" and f"`{p.relative_to(package).as_posix()}`" not in DOC]
    assert not missing, f"add these modules to the module map in docs/architecture-and-testing.md: {missing}"


def test_every_test_file_is_in_the_inventory():
    missing = [p.name for p in sorted((ROOT / "tests").glob("test_*.py")) if p.name not in DOC]
    assert not missing, f"add these test files to the inventory in docs/architecture-and-testing.md: {missing}"


def test_the_benchmark_scripts_of_the_study_are_named():
    scripts = sorted((ROOT / "benchmarks" / "hook_fidelity").glob("*.py"))
    missing = [p.name for p in scripts if p.name in {"fetch_corpus.py", "report_numbers.py"} and p.name not in DOC]
    assert not missing, missing


def test_the_typed_marker_ships_and_is_named():
    assert (ROOT / "src" / "intentshield" / "py.typed").is_file()
    assert "py.typed" in DOC
