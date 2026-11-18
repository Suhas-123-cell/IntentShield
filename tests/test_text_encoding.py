"""Every text-mode file call in the package, the tests and the benchmarks names its encoding.

Ruff's PLW1514 finds most of them but misses a call on a path built in the same expression (``(tmp / name).read_text()``),
so the tree is read here as well. Without the argument the result depends on the machine's locale.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Not file opens that return text: os.open takes flags, an opener's open sends a request.
NOT_TEXT_FILES = {"os", "opener"}


def _mode(call: ast.Call, position: int) -> object:
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    if len(call.args) > position and isinstance(call.args[position], ast.Constant):
        return call.args[position].value
    return None


def _without_encoding(path: Path) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)
        if name not in ("open", "read_text", "write_text", "fdopen") or any(k.arg == "encoding" for k in node.keywords):
            continue
        if isinstance(function, ast.Attribute) and ast.unparse(function.value) in NOT_TEXT_FILES and name == "open":
            continue
        if name in ("open", "fdopen"):
            position = 1 if isinstance(function, ast.Name) or ast.unparse(function) in ("gzip.open", "os.fdopen") else 0
            mode = _mode(node, position)
            if isinstance(mode, str) and "b" in mode and "t" not in mode:
                continue
        lines.append(node.lineno)
    return lines


def test_every_text_mode_file_call_names_its_encoding():
    missing = [
        f"{path.relative_to(ROOT)}:{line}"
        for folder in ("src", "tests", "benchmarks")
        for path in sorted((ROOT / folder).rglob("*.py"))
        for line in _without_encoding(path)
    ]
    assert not missing, 'add encoding="utf-8" to: ' + ", ".join(missing)
