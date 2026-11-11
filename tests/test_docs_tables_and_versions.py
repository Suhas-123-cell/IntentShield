"""Two guards on the front-door documents: no table cell is a paragraph, and the release version is the same everywhere."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_CELL = 300

# Section headings to skip, by file. Empty: the whole README and guide are checked.
EXCLUDED_SECTIONS: dict[str, tuple[str, ...]] = {}

_HEADING = re.compile(r"^(#{1,6})\s")
_CELL_SPLIT = re.compile(r"(?<!\\)\|")


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in _CELL_SPLIT.split(line.strip().strip("|"))]


def _long_cells(name: str) -> list[str]:
    skipped = EXCLUDED_SECTIONS.get(name, ())
    problems: list[str] = []
    excluded_level = 0     # the heading level of the section being skipped, 0 when none is
    fenced = False
    for number, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        if fenced:
            continue
        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            if excluded_level and level <= excluded_level:
                excluded_level = 0
            if line.strip() in skipped:
                excluded_level = level
        if excluded_level or not line.lstrip().startswith("|"):
            continue
        for cell in _cells(line):
            if len(cell) > MAX_CELL and not set(cell) <= set("-: "):
                problems.append(f"{name}:{number}: a table cell of {len(cell)} characters (limit {MAX_CELL}): {cell[:70]}...")
    return problems


def test_no_table_cell_in_the_readme_is_longer_than_300_characters():
    assert not _long_cells("README.md")


def test_no_table_cell_in_the_guide_is_longer_than_300_characters():
    assert not _long_cells("docs/guide.md")


def test_the_checker_finds_a_long_cell_and_skips_an_excluded_section(tmp_path, monkeypatch):
    long = "x" * (MAX_CELL + 1)
    doc = tmp_path / "doc.md"
    table = f"|---|\n| {long} |\n"
    head = f"# Title\n\n| a | b |\n|---|---|\n| short | {long} |\n\n"
    doc.write_text(f"{head}### Skipped\n\n| c |\n{table}\n## Next\n\n| d |\n{table}")
    monkeypatch.setitem(EXCLUDED_SECTIONS, "doc.md", ("### Skipped",))
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    found = _long_cells("doc.md")
    assert [problem.split(":")[1] for problem in found] == ["5", "17"]


def test_an_escaped_pipe_does_not_split_a_cell():
    assert _cells(r"| `a \| b` | c |") == [r"`a \| b`", "c"]


def _project_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_the_citation_file_names_the_package_version():
    text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert f'version: "{_project_version()}"' in text


def test_the_lock_file_names_the_package_version():
    text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'\[\[package\]\]\nname = "intentshield-mcp"\nversion = "([^"]+)"', text)
    assert match and match.group(1) == _project_version()


def test_the_changelog_has_a_heading_for_the_package_version():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## {re.escape(_project_version())} - \d{{4}}-\d{{2}}-\d{{2}}$", text, re.M)
