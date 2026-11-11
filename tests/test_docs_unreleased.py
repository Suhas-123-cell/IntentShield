"""What the README and the guide say about behaviour that is on main but not in the 0.4.3 package on PyPI.

A reader who installs from PyPI gets 0.4.3. The README describes main and carries one note under the install block that says
so and links the changelog; it has no inline qualifier. In the guide, where the detail is, a statement about a feature listed
under "Unreleased" in CHANGELOG.md must say "on main, after 0.4.3" in the same paragraph, list item, table row or code line,
until that version is released.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARK = "on main, after 0.4.3"
FILES = ("docs/guide.md",)

NOTE = "PyPI has 0.4.3"
NOTE_LINKS = ("CHANGELOG.md#unreleased", "CHANGELOG.md#upgrading-from-043")

# Each "Added" bullet of the Unreleased section of CHANGELOG.md, by its first words, with the patterns by which the guide names
# that feature. An empty tuple says the two documents do not name it. A new bullet fails the first test until it is
# listed here, so that whoever adds a feature decides whether a document needs the mark.
UNRELEASED_ADDED: dict[str, tuple[str, ...]] = {
    "`wrap` and `unwrap` read Codex CLI's": (r"mcp_servers", r"VS Code"),
    "`doctor` prints an `ok` line": (r"--connect(?![-\w])",),
    "`doctor --verbose` lists": (r"--verbose",),
    "`intentshield-mcp-verify --summary`": (r"--summary",),
    "`intentshield demo` also sends one MCP call": (r"one MCP call", r"second deny"),
    "`wrap` ends with a `Next:` line": (r"--print-entry --harness cursor",),
    "`scan` prints what each matched": (),
    "Only with `--builtin-tools`: the hook also reads the arguments of an MCP tool": (r"arguments of an MCP tool",),
    "The proxy config takes `trusted_tools`": (r"trusted_tools",),
}
# Features of the "Changed" and "Fixed" lists that the guide also names.
UNRELEASED_OTHER = (r"3\.11", r"<server>-<hash>")


def _unreleased() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"^## Unreleased\n(.*?)(?=^## )", text, re.M | re.S)
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
    for name in FILES:
        for number, text in _blocks(name):
            if any(re.search(pattern, text) for pattern in patterns) and MARK not in text:
                found.append(f"{name}:{number}: {text[:90]}")
    return found


def test_every_unreleased_added_feature_is_listed_here():
    unlisted = [b[:60] for b in _unreleased_added() if not any(b.startswith(key) for key in UNRELEASED_ADDED)]
    assert not unlisted, f"list these CHANGELOG bullets in UNRELEASED_ADDED, with the patterns that name them: {unlisted}"


def test_a_statement_about_an_unreleased_feature_carries_the_mark():
    problems: list[str] = []
    for bullet in _unreleased_added():
        for key, patterns in UNRELEASED_ADDED.items():
            if bullet.startswith(key):
                problems += _unmarked(patterns)
    problems += _unmarked(UNRELEASED_OTHER)
    assert not problems, "\n".join(problems)


def test_the_marks_are_there_and_the_guide_explains_them():
    for name in FILES:
        assert MARK in (ROOT / name).read_text(encoding="utf-8"), name
    guide = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
    assert f'A statement marked "({MARK})"' in guide


def test_the_checker_finds_a_statement_without_the_mark(tmp_path, monkeypatch):
    import sys

    (tmp_path / "doc.md").write_text(
        "# T\n\nOne feature (--connect) here.\n\n- item (--connect, on main, after 0.4.3)\n\n```sh\nx --connect\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "FILES", ("doc.md",))
    assert [line.split(":")[1] for line in _unmarked((r"--connect(?![-\w])",))] == ["3", "8"]


def _readme_problems(text: str, unreleased: str) -> list[str]:
    """What is wrong with ``text`` as the README, given the body of the changelog's Unreleased section."""
    problems: list[str] = []
    if MARK in text:
        problems.append(f'the README has an inline "{MARK}"; the one note under the install block carries that')
    if not unreleased.strip():
        return problems
    paragraphs = [block for block in re.split(r"\n\s*\n", text) if NOTE in block]
    if len(paragraphs) != 1:
        wrong = f'the README must have one note that says "{NOTE}" while Unreleased is not empty; it has {len(paragraphs)}'
        return problems + [wrong]
    flat = re.sub(r"\s+", " ", paragraphs[0])
    return problems + [f"the note does not link {link}" for link in NOTE_LINKS if link not in flat]


def test_the_readme_describes_main_and_has_one_note_about_the_package_on_pypi():
    assert not _readme_problems((ROOT / "README.md").read_text(encoding="utf-8"), _unreleased())


def test_the_note_is_required_while_unreleased_is_not_empty_and_only_once():
    note = (
        f"> **{NOTE}**, which predates some of this. See [Unreleased](x/CHANGELOG.md#unreleased) and"
        " [Upgrading](x/CHANGELOG.md#upgrading-from-043).\n"
    )
    full = "# T\n\nText.\n\n" + note + "\nMore.\n"
    assert _readme_problems(full, "### Added\n\n- x\n") == []
    assert len(_readme_problems("# T\n\nText.\n", "### Added\n\n- x\n")) == 1
    assert len(_readme_problems(full + "\n" + note, "### Added\n\n- x\n")) == 1
    assert len(_readme_problems(full.replace("#upgrading-from-043", "#upgrading"), "### Added\n\n- x\n")) == 1
    assert _readme_problems("# T\n\nText.\n", "\n") == []
    assert len(_readme_problems(full + f"\nA feature ({MARK}).\n", "### Added\n\n- x\n")) == 1
