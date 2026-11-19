"""What the documents say about behaviour that is in the repository but not in the latest package on PyPI.

The pages describe what the tool does now: what changed between releases is in CHANGELOG.md, so no page carries a qualifier such
as "on main, after 0.4.3" or "since 0.4.4". The one place that tells a reader the repository is ahead of the package is a note in
the README under the quick start, and it is there only while the "Unreleased" section of CHANGELOG.md is not empty: it says
that PyPI has the latest release and links the changelog.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Every Markdown file that describes the product; none may carry an "on main, after <version>" qualifier.
QUALIFIER_FILES = (
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "docs/guide.md", "docs/rules.md", "docs/layers.md", "docs/gateway.md",
    "docs/detectors.md",
    "docs/benchmarks.md", "docs/security-review.md", "docs/architecture-and-testing.md", "docs/hook-fidelity-report.md",
    "docs/hook-fidelity-report-appendix.md", "docs/contribution.md", "results/hook-fidelity/README.md",
)
# The pages that tell a reader how to use the tool: none may date a statement by a release ("since 0.4.4", "in 0.4.3 it").
USAGE_FILES = (
    "README.md", "SECURITY.md", "docs/guide.md", "docs/rules.md", "docs/layers.md", "docs/gateway.md", "docs/detectors.md",
    "docs/architecture-and-testing.md", ".github/ISSUE_TEMPLATE/bug_report.md", ".github/ISSUE_TEMPLATE/feature_request.md",
)
QUALIFIER = re.compile(r"\bon main,? after \d+\.\d+\.\d+", re.I)
SINCE = re.compile(r"\bsince \d+\.\d+\.\d+|\bin \d+\.\d+\.\d+ it\b|\bbefore \d+\.\d+\.\d+ the\b", re.I)
PYPI_NOTE = re.compile(r"PyPI has \d+\.\d+\.\d+")


def _changelog() -> str:
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def _latest_release() -> str:
    """The version of the first ``## X.Y.Z - date`` heading of the changelog: the release the repository was last tagged at."""
    match = re.search(r"^## (\d+\.\d+\.\d+) - ", _changelog(), re.M)
    assert match, "CHANGELOG.md has no release heading"
    return match.group(1)


def _unreleased() -> str:
    match = re.search(r"^## Unreleased\n(.*?)(?=^## )", _changelog(), re.M | re.S)
    return match.group(1) if match else ""


def _qualifiers(text: str) -> list[str]:
    """The lines of ``text`` that carry a qualifier such as "on main, after 0.4.3"."""
    return [line.strip()[:100] for line in text.splitlines() if QUALIFIER.search(line)]


def _dated(text: str) -> list[str]:
    """The lines of ``text`` that date a statement by a release, such as "since 0.4.4" or "in 0.4.3 it exits 1"."""
    return [line.strip()[:100] for line in text.splitlines() if SINCE.search(line)]


def test_no_document_carries_an_on_main_qualifier():
    found = {name: _qualifiers((ROOT / name).read_text(encoding="utf-8")) for name in QUALIFIER_FILES}
    assert not {name: lines for name, lines in found.items() if lines}


def test_no_usage_page_dates_a_statement_by_a_release():
    found = {name: _dated((ROOT / name).read_text(encoding="utf-8")) for name in USAGE_FILES}
    assert not {name: lines for name, lines in found.items() if lines}


def test_the_guide_does_not_explain_a_mark():
    assert "A statement marked" not in (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")


def test_the_qualifier_pattern_matches_the_forms_the_documents_used():
    for text in ("(on main, after 0.4.3)", "On main, after 0.4.3, it", "the code on main after 0.4.3 is", "ON MAIN, AFTER 0.4.4"):
        assert _qualifiers(text), text
    for text in ("since 0.4.4", "on main, before the tag", "a clone of main, 0.4.3 denied it", "after 0.4.3 the hook sends"):
        assert not _qualifiers(text), text


def test_the_dating_pattern_matches_the_forms_the_documents_used():
    for text in ("since 0.4.4", "Since 0.4.3, `install` writes", "In 0.4.3 it exits 1", "(the last two since 0.4.4)",
                 "Before 0.4.3 the protocol library dropped"):
        assert _dated(text), text
    for text in ("the rules of 0.4.4", "scored with the 0.4.4 rules", "a hook that has run since the install", "0.4.3 is older"):
        assert not _dated(text), text


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
