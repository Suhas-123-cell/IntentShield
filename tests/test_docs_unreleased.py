"""What the documents say about behaviour that is in the repository but not in the latest package on PyPI.

While the "Unreleased" section of CHANGELOG.md is empty, the repository and the latest release are the same product, so no
document carries a qualifier such as "on main, after 0.4.3" and the README has no note that PyPI has an older version. While the
section is not empty, the README carries one note under the install block that says PyPI has the latest release and links the
changelog, and a statement in the guide about a feature listed under "Unreleased" says "on main, after <latest release>" in the
same paragraph, list item, table row or code line, until that version is released.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ("docs/guide.md",)
# Every Markdown file that describes the product; none may carry a qualifier while Unreleased is empty.
QUALIFIER_FILES = (
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "docs/guide.md", "docs/layers.md", "docs/gateway.md", "docs/detectors.md",
    "docs/benchmarks.md", "docs/security-review.md", "docs/architecture-and-testing.md", "docs/hook-fidelity-report.md",
    "docs/hook-fidelity-report-appendix.md", "docs/contribution.md", "results/hook-fidelity/README.md",
)
QUALIFIER = re.compile(r"\bon main,? after \d+\.\d+\.\d+", re.I)
PYPI_NOTE = re.compile(r"PyPI has \d+\.\d+\.\d+")

# Each "Added" bullet of the Unreleased section of CHANGELOG.md, by its first words, with the patterns by which the guide names
# that feature. An empty tuple says the two documents do not name it. A new bullet fails the first test until it is
# listed here, so that whoever adds a feature decides whether a document needs the mark. Empty while Unreleased is empty.
UNRELEASED_ADDED: dict[str, tuple[str, ...]] = {}
# Features of the "Changed" and "Fixed" lists that the guide also names.
UNRELEASED_OTHER: tuple[str, ...] = ()


def _changelog() -> str:
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def _latest_release() -> str:
    """The version of the first ``## X.Y.Z - date`` heading of the changelog: the release the repository was last tagged at."""
    match = re.search(r"^## (\d+\.\d+\.\d+) - ", _changelog(), re.M)
    assert match, "CHANGELOG.md has no release heading"
    return match.group(1)


def _mark() -> str:
    return f"on main, after {_latest_release()}"


def _unreleased() -> str:
    match = re.search(r"^## Unreleased\n(.*?)(?=^## )", _changelog(), re.M | re.S)
    return match.group(1) if match else ""


def _unreleased_added() -> list[str]:
    added = re.search(r"^### Added\n(.*?)(?=^### |\Z)", _unreleased(), re.M | re.S)
    if not added:
        return []
    bullets: list[str] = []
    for line in added.group(1).splitlines():
        if line.startswith("- "):
            bullets.append(line[2:].strip())
        elif line.strip() and bullets:
            bullets[-1] += " " + line.strip()
    return bullets


def _blocks(name: str) -> list[tuple[int, str]]:
    """(first line number, text) of each paragraph, list item and table row; a line of a code block is a block of its own."""
    out: list[tuple[int, str]] = []
    block: list[str] = []
    start = 0
    fenced = False

    def close() -> None:
        if block:
            out.append((start, " ".join(part.strip() for part in block)))
        block.clear()

    for number, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            close()
            fenced = not fenced
            continue
        if fenced:
            if stripped:
                out.append((number, stripped))
            continue
        if not stripped or stripped.startswith(("#", "|")):
            close()
            if stripped.startswith("|"):
                out.append((number, stripped))
            continue
        if re.match(r"^\s*(?:[-*+]|\d+[.)])\s", line):
            close()
        if not block:
            start = number
        block.append(line)
    close()
    return out


def _unmarked(patterns: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    mark = _mark()
    for name in FILES:
        for number, text in _blocks(name):
            if any(re.search(pattern, text) for pattern in patterns) and mark not in text:
                found.append(f"{name}:{number}: {text[:90]}")
    return found


def _qualifiers(text: str) -> list[str]:
    """The lines of ``text`` that carry a qualifier such as "on main, after 0.4.3"."""
    return [line.strip()[:100] for line in text.splitlines() if QUALIFIER.search(line)]


def test_every_unreleased_added_feature_is_listed_here():
    unlisted = [b[:60] for b in _unreleased_added() if not any(b.startswith(key) for key in UNRELEASED_ADDED)]
    assert not unlisted, f"list these CHANGELOG bullets in UNRELEASED_ADDED, with the patterns that name them: {unlisted}"


def test_a_statement_about_an_unreleased_feature_carries_the_mark():
    problems: list[str] = []
    for bullet in _unreleased_added():
        for key, patterns in UNRELEASED_ADDED.items():
            if bullet.startswith(key):
                problems += _unmarked(patterns)
    problems += _unmarked(UNRELEASED_OTHER) if _unreleased().strip() else []
    assert not problems, "\n".join(problems)


def test_the_guide_explains_the_mark_only_while_something_is_unreleased():
    guide = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
    explanation = f'A statement marked "({_mark()})"'
    if _unreleased().strip():
        assert explanation in guide
    else:
        assert "A statement marked" not in guide


def test_no_document_carries_a_qualifier_while_unreleased_is_empty():
    if _unreleased().strip():
        return
    found = {name: _qualifiers((ROOT / name).read_text(encoding="utf-8")) for name in QUALIFIER_FILES}
    assert not {name: lines for name, lines in found.items() if lines}


def test_the_checker_finds_a_statement_without_the_mark(tmp_path, monkeypatch):
    (tmp_path / "doc.md").write_text(
        "# T\n\nOne feature (--connect) here.\n\n- item (--connect, on main, after 0.4.3)\n\n```sh\nx --connect\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "FILES", ("doc.md",))
    monkeypatch.setattr(sys.modules[__name__], "_mark", lambda: "on main, after 0.4.3")
    assert [line.split(":")[1] for line in _unmarked((r"--connect(?![-\w])",))] == ["3", "8"]


def test_the_qualifier_pattern_matches_the_forms_the_documents_used():
    for text in ("(on main, after 0.4.3)", "On main, after 0.4.3, it", "the code on main after 0.4.3 is", "ON MAIN, AFTER 0.4.4"):
        assert _qualifiers(text), text
    for text in ("since 0.4.4", "on main, before the tag", "a clone of main, 0.4.3 denied it", "after 0.4.3 the hook sends"):
        assert not _qualifiers(text), text


def _readme_problems(text: str, unreleased: str, latest: str = "0.4.3") -> list[str]:
    """What is wrong with ``text`` as the README, given the body of the changelog's Unreleased section and the latest release."""
    problems: list[str] = []
    if f"on main, after {latest}" in text:
        problems.append(f'the README has an inline "on main, after {latest}"; the one note under the install block carries that')
    note = f"PyPI has {latest}"
    if not unreleased.strip():
        if PYPI_NOTE.search(text):
            problems.append("the README says PyPI has an older version, but Unreleased is empty")
        return problems
    paragraphs = [block for block in re.split(r"\n\s*\n", text) if note in block]
    if len(paragraphs) != 1:
        wrong = f'the README must have one note that says "{note}" while Unreleased is not empty; it has {len(paragraphs)}'
        return problems + [wrong]
    flat = re.sub(r"\s+", " ", paragraphs[0])
    links = ["CHANGELOG.md#unreleased"]
    if "### Upgrading from" in unreleased:
        links.append("CHANGELOG.md#upgrading-from-")
    return problems + [f"the note does not link {link}" for link in links if link not in flat]


def test_the_readme_describes_one_product_and_has_the_pypi_note_only_while_unreleased_is_not_empty():
    assert not _readme_problems((ROOT / "README.md").read_text(encoding="utf-8"), _unreleased(), _latest_release())


def test_the_latest_release_is_the_first_release_heading():
    assert re.fullmatch(r"\d+\.\d+\.\d+", _latest_release())


def test_the_note_is_required_while_unreleased_is_not_empty_and_only_once():
    note = (
        "> **PyPI has 0.4.3**, which predates some of this. See [Unreleased](x/CHANGELOG.md#unreleased) and"
        " [Upgrading](x/CHANGELOG.md#upgrading-from-043).\n"
    )
    full = "# T\n\nText.\n\n" + note + "\nMore.\n"
    unreleased = "### Upgrading from 0.4.3\n\n### Added\n\n- x\n"
    assert _readme_problems(full, unreleased) == []
    assert len(_readme_problems("# T\n\nText.\n", unreleased)) == 1
    assert len(_readme_problems(full + "\n" + note, unreleased)) == 1
    assert len(_readme_problems(full.replace("#upgrading-from-043", "#upgrading"), unreleased)) == 1
    assert _readme_problems(full.replace("#upgrading-from-043", "#upgrading"), "### Added\n\n- x\n") == []
    assert len(_readme_problems(full + "\nA feature (on main, after 0.4.3).\n", unreleased)) == 1


def test_with_unreleased_empty_the_note_and_every_inline_mark_are_errors():
    note = "> **PyPI has 0.4.3**, which predates some of this.\n"
    assert _readme_problems("# T\n\nText.\n", "\n") == []
    assert len(_readme_problems("# T\n\n" + note, "\n")) == 1
    assert len(_readme_problems("# T\n\nA feature (on main, after 0.4.3).\n", "\n")) == 1
