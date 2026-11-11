"""Every relative link and anchor in the repository's Markdown resolves, and so does every absolute link from the README to a file
in this repository (the README is the PyPI page, where relative links 404, so it links to GitHub by URL; a link to a section of
the README itself is a same-page `#anchor`).

GitHub's anchor rule: the heading text lowercased, every character that is not a letter, digit, space, hyphen or underscore
dropped, spaces turned into hyphens; a repeated heading gets -1, -2 and so on.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/Suhas-123-cell/IntentShield"
RAW_URL = "https://raw.githubusercontent.com/Suhas-123-cell/IntentShield"
# vendor documentation pages kept verbatim as evidence: their own links are the vendor's, not ours
VERBATIM = ("docs/hook-fidelity-archive/",)

_FENCE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*(<[^>]*>|[^()\s]*(?:\([^()\s]*\)[^()\s]*)*)(?:\s+\"[^\"]*\")?\s*\)")
_REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(\S+)", re.M)
_HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
_HTML_ANCHOR = re.compile(r"""<a\s[^>]*?(?:name|id)=["']([^"']+)["']""", re.I)


def _markdown_files() -> list[Path]:
    try:
        listed = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z", "--", "*.md"], cwd=ROOT, check=True,
                                capture_output=True, text=True).stdout.split("\0")
        found = {ROOT / name for name in listed if name}
    except (OSError, subprocess.CalledProcessError):
        found = {p for p in ROOT.rglob("*.md") if ".venv" not in p.parts and "node_modules" not in p.parts}
    wanted = []
    for path in sorted(found):
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file() or rel.startswith(VERBATIM):
            continue
        top = rel.split("/")[0]
        if "/" not in rel or top in ("docs", ".github") or rel in ("results/README.md", "results/hook-fidelity/README.md"):
            wanted.append(path)
    return wanted


def _prose(text: str) -> list[str]:
    """The lines outside fenced code blocks, with inline code removed (a link inside code is an example, not a link)."""
    out, fenced = [], False
    for line in text.splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            out.append(_INLINE_CODE.sub("", line))
    return out


def _plain(heading: str) -> str:
    heading = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)   # a link keeps its text
    heading = re.sub(r"<[^>]+>", "", heading)
    return heading.replace("`", "").replace("*", "").strip()


def _slug(heading: str) -> str:
    text = _plain(heading).lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


_anchor_cache: dict[Path, set[str]] = {}


def _anchors(path: Path) -> set[str]:
    if path not in _anchor_cache:
        text = path.read_text(encoding="utf-8")
        seen: dict[str, int] = {}
        found: set[str] = set(_HTML_ANCHOR.findall(text))
        fenced = False
        for line in text.splitlines():
            if _FENCE.match(line):
                fenced = not fenced
                continue
            match = None if fenced else _HEADING.match(line)
            if match:
                slug = _slug(match.group(2))
                count = seen.get(slug, 0)
                seen[slug] = count + 1
                found.add(slug if count == 0 else f"{slug}-{count}")
        _anchor_cache[path] = found
    return _anchor_cache[path]


def _targets(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    found = []
    for line in _prose(text):
        for match in _LINK.finditer(line):
            found.append(match.group(1).strip("<>"))
    found += [m.group(1).strip("<>") for m in _REFERENCE.finditer("\n".join(_prose(text)))]
    return found


def _check(source: Path, base: Path, target: str, problems: list[str], label: str) -> None:
    """``target`` is a path (relative to ``base``) with an optional ``#anchor``."""
    where = f"{source.relative_to(ROOT).as_posix()}: {label}"
    path_part, _, anchor = target.partition("#")
    anchor = unquote(anchor)
    resolved = (base / unquote(path_part)).resolve() if path_part else source
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        problems.append(f"{where} leaves the repository")
        return
    if not resolved.exists():
        problems.append(f"{where}: no such file {resolved.relative_to(ROOT).as_posix()}")
        return
    if anchor and resolved.suffix == ".md" and not re.fullmatch(r"L\d+(-L\d+)?", anchor):
        if anchor.lower() not in {a.lower() for a in _anchors(resolved)}:
            problems.append(f"{where}: no heading for #{anchor} in {resolved.relative_to(ROOT).as_posix()}")


FILES = _markdown_files()


def test_the_documents_to_check_are_found():
    names = {p.relative_to(ROOT).as_posix() for p in FILES}
    assert {"README.md", "CHANGELOG.md", "docs/README.md", "docs/layers.md", "results/README.md"} <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_relative_links_and_anchors_resolve(path: Path):
    problems: list[str] = []
    for target in _targets(path):
        if re.match(r"[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("//"):
            continue   # http, https, mailto: only the README's links to this repository are checked, below
        if target.startswith("/"):
            problems.append(f"{path.relative_to(ROOT).as_posix()}: {target} is an absolute path (404 on GitHub and PyPI)")
            continue
        _check(path, path.parent, target, problems, target)
    assert not problems, "\n".join(problems)


def test_the_readmes_absolute_links_into_this_repository_resolve():
    readme = ROOT / "README.md"
    problems: list[str] = []
    seen = 0
    for target in _targets(readme):
        for prefix in (f"{REPO_URL}/blob/main/", f"{REPO_URL}/tree/main/", f"{RAW_URL}/main/"):
            if target.startswith(prefix):
                seen += 1
                _check(readme, ROOT, target[len(prefix):], problems, target)
    assert seen > 10, "the README is expected to link to the repository by absolute URL"
    assert not problems, "\n".join(problems)


def test_the_readme_has_no_relative_links():
    """The README is the PyPI page: a relative link there is a 404."""
    relative = [t for t in _targets(ROOT / "README.md")
                if not re.match(r"[a-z][a-z0-9+.-]*:", t, re.I) and not t.startswith("#")]
    assert not relative, relative


def test_the_readme_links_to_its_own_sections_by_anchor_only():
    """A same-page link is `#results`, not a URL: it must work in a clone, on a fork and on the PyPI page."""
    targets = _targets(ROOT / "README.md")
    own = [t for t in targets if t.startswith(f"{REPO_URL}/blob/main/README.md")]
    assert not own, own
    anchors = [t for t in targets if t.startswith("#")]
    assert {"#results", "#the-hook-study"} <= set(anchors), anchors


def test_the_anchor_rule_matches_githubs_on_known_headings():
    assert _slug("What each layer sees and stops") == "what-each-layer-sees-and-stops"
    assert _slug("Built-in tools and the dangerous-command rules") == "built-in-tools-and-the-dangerous-command-rules"
    assert _slug("`wrap` & `unwrap`: 3 steps (v0.4)") == "wrap--unwrap-3-steps-v04"
    assert _slug("The [guide](x.md) page") == "the-guide-page"
