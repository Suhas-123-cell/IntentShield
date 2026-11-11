"""Every third-party package that src/intentshield imports is declared in pyproject.toml.

The local environment can hold packages that CI and a PyPI install do not, and a package such as httpx2 or starlette
arrives through mcp today and stops arriving the day mcp drops it. Reading the imports from the source with ast, not
from what happens to be installed, makes a missing declaration fail here."""
from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "intentshield"

# The distribution name is not the import name for these.
IMPORT_NAME = {"python-dotenv": "dotenv", "pyyaml": "yaml", "scikit-learn": "sklearn"}

# Heavy or optional packages that are never required: imported inside a function and guarded, or only in the two
# modules that need a feature extra. requirements-ml.txt lists the machine-learning ones; huggingface_hub comes with
# transformers.
OPTIONAL_ONLY = {"huggingface_hub"}
OPTIONAL_MODULES = {"exemplars.py", "learning.py"}  # numpy, from the "learning" extra


def import_name(requirement: str) -> str:
    name = re.split(r"[\s\[<>=!~;]", requirement.strip(), maxsplit=1)[0].lower().replace("_", "-")
    return IMPORT_NAME.get(name, name.replace("-", "_"))


def requirement_names(lines) -> set[str]:
    return {import_name(line) for line in lines if line.strip() and not line.lstrip().startswith("#")}


def declared() -> tuple[set[str], set[str]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    required = requirement_names(project["dependencies"])
    extras = {name for group in project["optional-dependencies"].values() for name in requirement_names(group)}
    ml = requirement_names((ROOT / "requirements-ml.txt").read_text().splitlines())
    return required, extras | ml | OPTIONAL_ONLY


def third_party_imports() -> list[tuple[str, str, bool]]:
    """(top-level module, file name, imported at module level) for each third-party import under src."""
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        top_level = {id(node) for node in tree.body}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            else:
                continue
            for module in modules:
                top = module.split(".")[0]
                if top not in sys.stdlib_module_names and top != "intentshield":
                    found.append((top, path.name, id(node) in top_level))
    return found


def test_the_scan_sees_the_known_third_party_imports():
    modules = {top for top, _, _ in third_party_imports()}
    assert {"fastapi", "pydantic", "mcp", "httpx2", "starlette", "anyio", "dotenv"} <= modules


def test_every_third_party_import_is_declared():
    required, optional = declared()
    undeclared = sorted({(top, name) for top, name, _ in third_party_imports() if top not in required | optional})
    assert not undeclared, f"imported by src but declared nowhere in pyproject.toml or requirements-ml.txt: {undeclared}"


def test_a_package_imported_in_the_server_or_at_module_level_is_a_required_dependency():
    required, _ = declared()
    needed = sorted({
        (top, name) for top, name, at_top in third_party_imports()
        if top not in required and name not in OPTIONAL_MODULES and top not in OPTIONAL_ONLY
        and (at_top or name in {"mcp_server.py", "mcp_upstream.py"})
    })
    assert not needed, f"optional packages used where a plain install must have them: {needed}"


def test_the_package_does_not_declare_what_it_never_imports():
    required, _ = declared()
    used = {top for top, _, _ in third_party_imports()}
    assert required <= used, f"declared but never imported by src: {sorted(required - used)}"

