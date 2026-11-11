"""Guards on the front-door documents: no table cell or paragraph is a wall of text, and the release version is one everywhere."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

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


MAX_PARAGRAPH = 900
MAX_PARAGRAPH_ARCHITECTURE = 500
MAX_PARAGRAPH_README = 700
PARAGRAPH_FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/architecture-and-testing.md",
    "docs/contribution.md",
    "docs/hook-fidelity-report.md",
    "docs/guide.md",
)
# Sections that the paragraph test does not read, by file. None: every section of every file listed above is checked.
PARAGRAPH_EXCLUDED_SECTIONS: dict[str, tuple[str, ...]] = {}
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")


def _long_paragraphs(name: str, limit: int, root: Path | None = None) -> list[str]:
    """Paragraphs longer than ``limit`` characters. A paragraph is the lines between blank lines, with each list item counted
    on its own; code blocks, headings and table rows are not paragraphs."""
    problems: list[str] = []
    block: list[str] = []
    start = 0
    fenced = False
    skipped = PARAGRAPH_EXCLUDED_SECTIONS.get(name, ())
    excluded_level = 0     # the heading level of the section being skipped, 0 when none is

    def close() -> None:
        text = " ".join(part.strip() for part in block)
        if len(text) > limit and not excluded_level:
            problems.append(f"{name}:{start}: a paragraph of {len(text)} characters (limit {limit}): {text[:70]}...")
        block.clear()

    for number, line in enumerate(((root or ROOT) / name).read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            close()
            fenced = not fenced
            continue
        stripped = line.strip()
        heading = _HEADING.match(line)
        if heading and not fenced:
            close()
            level = len(heading.group(1))
            if excluded_level and level <= excluded_level:
                excluded_level = 0
            if stripped in skipped:
                excluded_level = level
            continue
        if fenced or not stripped or stripped.startswith(("|", "<!--", "<a ")):
            close()
            continue
        if _LIST_ITEM.match(line):
            close()
        if not block:
            start = number
        block.append(line)
    close()
    return problems


@pytest.mark.parametrize("name", PARAGRAPH_FILES)
def test_no_paragraph_in_the_front_door_documents_is_longer_than_900_characters(name):
    assert not _long_paragraphs(name, MAX_PARAGRAPH)


def test_no_paragraph_in_the_readme_is_longer_than_700_characters():
    assert not _long_paragraphs("README.md", MAX_PARAGRAPH_README)


def test_no_paragraph_in_the_architecture_document_is_longer_than_500_characters():
    assert not _long_paragraphs("docs/architecture-and-testing.md", MAX_PARAGRAPH_ARCHITECTURE)


def test_the_paragraph_checker_counts_a_wrapped_paragraph_and_a_list_item_separately(tmp_path):
    (tmp_path / "doc.md").write_text(
        "# Title\n\n" + "word " * 60 + "\nmore " * 60 + "\n\n- item one\n  continues\n- item two\n\n```\n" + "x" * 2000
        + "\n```\n"
    )
    found = _long_paragraphs("doc.md", 500, tmp_path)
    assert len(found) == 1 and found[0].startswith("doc.md:3:")
    assert not _long_paragraphs("doc.md", 700, tmp_path)


def test_the_paragraph_checker_skips_a_named_section_and_the_guide_is_checked_whole(tmp_path, monkeypatch):
    long = "word " * 300
    (tmp_path / "doc.md").write_text(f"# T\n\n## A\n\n### Skipped\n\n{long}\n\n#### Inside\n\n{long}\n\n## B\n\n{long}\n")
    monkeypatch.setitem(PARAGRAPH_EXCLUDED_SECTIONS, "doc.md", ("### Skipped",))
    assert [found.split(":")[1] for found in _long_paragraphs("doc.md", 900, tmp_path)] == ["15"]
    assert "docs/guide.md" in PARAGRAPH_FILES
    assert not PARAGRAPH_EXCLUDED_SECTIONS.get("docs/guide.md")


def test_the_changelog_opens_with_an_unreleased_heading_and_closed_code_spans():
    lines = (ROOT / "CHANGELOG.md").read_text().splitlines()
    headings = [line for line in lines if line.startswith("## ")]
    assert headings[0] == "## Unreleased"
    for number, line in enumerate(lines[:12], 1):
        assert line.count("`") % 2 == 0, f"CHANGELOG.md:{number} has an unclosed code span"
