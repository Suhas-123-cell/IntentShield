"""``pip install --no-deps intentshield-mcp`` leaves only the standard library. The commands that need a package say so in
one line.

Each case runs in a process of its own with the packages the proxy needs made unimportable, the way a --no-deps environment
is: ``sys.modules[name] = None`` makes ``import name`` raise ModuleNotFoundError."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from intentshield import _launch

SRC = str(Path(__file__).resolve().parents[1] / "src")
BLOCKED = ["pydantic", "jsonschema", "dotenv", "mcp", "uvicorn", "fastapi", "starlette", "anyio", "httpx2"]
PRELUDE = f"import sys\nfor name in {BLOCKED!r}:\n    sys.modules[name] = None\n"


def run(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC, "HOME": str(tmp_path), "INTENTSHIELD_PROXY_CONFIG": "",
           "INTENTSHIELD_CONTROL_TOKEN": ""}
    return subprocess.run([sys.executable, "-c", PRELUDE + body], capture_output=True, text=True, env=env, cwd=tmp_path,
                          timeout=60)


def one_line(done: subprocess.CompletedProcess[str], package: str | tuple[str, ...]) -> None:
    assert done.returncode == 2, done.stderr
    assert "Traceback" not in done.stderr and "Traceback" not in done.stdout
    lines = [line for line in done.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    names = (package,) if isinstance(package, str) else package
    assert any(f"'{name}'" in lines[0] for name in names), lines[0]
    assert "pip install intentshield-mcp" in lines[0] and "not installed" in lines[0]


def test_wrap_names_the_missing_package_and_leaves_the_file_alone(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"s": {"command": "echo"}}}))
    before = config.read_bytes()
    done = run(tmp_path, f"from intentshield.__main__ import main\nmain(['wrap', {str(config)!r}, '--allow-ephemeral'])")
    one_line(done, ("jsonschema", "pydantic"))  # the first of the two that the proxy package imports
    assert config.read_bytes() == before


def test_the_dashboard_names_the_missing_package(tmp_path):
    one_line(run(tmp_path, "from intentshield.__main__ import main\nmain(['serve'])"), "uvicorn")


def test_the_dashboard_is_the_default_command_and_says_the_same(tmp_path):
    one_line(run(tmp_path, "from intentshield.__main__ import main\nmain([])"), "uvicorn")


@pytest.mark.parametrize("entry", ["mcp", "mcp_verify", "demo_mcp"])
def test_the_console_commands_that_need_the_proxy_stack_name_a_missing_package(tmp_path, entry):
    body = f"import sys\nsys.argv = ['x', '--help']\nfrom intentshield import _launch\n_launch.{entry}()"
    one_line(run(tmp_path, body), ("python-dotenv", "mcp", "pydantic"))


def test_the_commands_a_no_deps_install_is_for_run_without_the_packages(tmp_path):
    for body in ("from intentshield.__main__ import main\nmain(['doctor'])",
                 "from intentshield.__main__ import main\nmain(['install', 'claude', '--dry-run', '--allow-ephemeral'])",
                 "from intentshield.__main__ import main\nmain(['scan', '--no-connect'])",
                 "from intentshield.__main__ import main\nmain(['--version'])"):
        done = run(tmp_path, body)
        assert "Traceback" not in done.stderr and "needs the package" not in done.stderr, (body, done.stderr)


def test_a_missing_module_that_is_not_a_dependency_keeps_its_traceback():
    assert _launch.missing_package(ModuleNotFoundError("x", name="numpy")) is None
    assert _launch.missing_package(ModuleNotFoundError("x", name="intentshield.nothing")) is None
    assert _launch.missing_package(ModuleNotFoundError("x", name="dotenv")) == "python-dotenv"
    assert _launch.missing_package(ImportError("x")) is None

    def fails() -> None:
        raise ModuleNotFoundError("No module named 'numpy'", name="numpy")

    with pytest.raises(ModuleNotFoundError):
        _launch.guarded(fails)
