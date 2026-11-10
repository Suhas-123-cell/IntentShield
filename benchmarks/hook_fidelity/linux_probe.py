"""Round 8 (lane r8-close): run the ps-free detector's Linux ``/proc`` reader once, inside a local Docker container
with no network.

No harness is launched. The "harness" is a dummy process NAMED like one (a copy of ``bash`` called ``claude``, or a
Python script called ``claude``, ``codex`` or ``gemini``) that starts the hook as its child, the way a harness does
(``sh -c <hook command>``). The hook is this file's ``hook`` subcommand, which reads ``translation._ancestors()`` and
``translation.detect_mode()`` from inside that tree and writes what they read. The ground truth of every case is how
the tree was built (the flag it was started with, the terminal it was given), so, as in the round 7 pty lane, a row
shows that the reader reads the tree it is given, not that the mode is right for a real harness.

    linux_probe.py docker OUT_DIR [--worktree DIR] [--deps DIR]   (host: the docker runs, the unit tests, the meta)
    linux_probe.py matrix FILE                                     (in the container: the nested-tree cases)
    linux_probe.py hidepid FILE                                    (in a container with CAP_SYS_ADMIN: /proc remounted hidepid=2)
    linux_probe.py pid1 FILE HARNESS_FORM HEADLESS                 (in the container: the dummy harness is PID 1)
    linux_probe.py hook --harness H --out FILE                     (the hook process the dummy harness starts)
    linux_probe.py summarize OUT_DIR                               (rows -> table.md and summary.json)
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

IMAGE = "python:3.12-slim"
BIN = "/tmp/bin"
HOOK = "python3 /work/benchmarks/hook_fidelity/linux_probe.py hook"
ROUND = "r8fix"


# --------------------------------------------------------------------------------------------- the hook (inside the tree)
def cmd_hook(args: argparse.Namespace) -> int:
    from intentshield import translation

    started = time.monotonic()
    chain = translation._ancestors()
    mode, how = translation.detect_mode(args.harness, {}, ancestors=chain)
    record = {
        "mode": mode,
        "how": how,
        "source": chain.source,
        "complete": chain.complete,
        "why": chain.why,
        "depth": len(chain),
        "chain": [[tty, cmd[:110]] for tty, cmd in chain],
        "uid": os.getuid(),
        "own_pid": os.getpid(),
        "own_ppid": os.getppid(),
        "read_ms": round((time.monotonic() - started) * 1000, 2),
        "ps_present": shutil.which("ps") is not None,
        "sources_env": os.environ.get(translation.ANCESTRY_ENV),
    }
    Path(args.out).write_text(json.dumps(record))
    return 0


# --------------------------------------------------------------------------------------------- dummy harnesses
NODE_LIKE = """#!/usr/bin/env python3
# a dummy harness: like a node-launched one, its program name is in the SECOND word of its command line. It runs
# its last argument as
# the hook command through ``sh -c`` and waits, and does nothing else.
import subprocess, sys
raise SystemExit(subprocess.run(["sh", "-c", sys.argv[-1]]).returncode)
"""


def make_bins(directory: str = BIN) -> None:
    """``claude`` (a copy of bash: a native-like process whose own flags come first, ``claude -p -c <command>``),
    and ``claude-node``
    style scripts ``claude``/``codex``/``gemini`` under ``<directory>/node``."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    shutil.copy(shutil.which("bash") or "/bin/bash", path / "claude")
    (path / "claude").chmod(0o755)
    node = path / "node"
    node.mkdir(exist_ok=True)
    for name in ("claude", "codex", "gemini"):
        (node / name).write_text(NODE_LIKE)
        (node / name).chmod(0o755)


def hook_command(harness: str, out: str, sources: str | None = None) -> str:
    env = f"INTENTSHIELD_ANCESTRY_SOURCES={shlex.quote(sources)} " if sources is not None else ""
    return f"{env}{HOOK} --harness {harness} --out {shlex.quote(out)}"


def case_argv(case: dict, out: str) -> list[str]:
    """The argv that starts the tree of ``case``: [script -qec] [wrappers] <dummy harness> <flags> <hook command>."""
    harness, form, flag = case["harness"], case["form"], case["headless_flag"]
    inner = f"{hook_command(harness, out, case.get('sources'))}"
    if case.get("nested"):  # the launcher's own shell layers, as ``intentshield`` hook commands have them
        inner = f"timeout 60 sh -c {shlex.quote(inner)}"
    if form == "none":  # no harness among the ancestors
        argv = ["sh", "-c", inner + "; true"]
    elif (
        form == "native"
    ):  # bash copy named claude: ``claude [-p] -c '<command>; true'`` (the ``; true`` keeps bash from exec-ing)
        argv = [f"{BIN}/claude", *(["-p"] if flag else []), "-c", f"sh -c {shlex.quote(inner)}; true"]
    else:  # node-like: ``python3 <dir>/<harness> [flag] '<command>'``
        marks = {"claude": ["-p"], "codex": ["exec"], "gemini": ["-p"]}[harness]
        argv = [f"{BIN}/node/{harness}", *(marks if flag else []), inner]
    if case.get("nested"):
        argv = ["env", "PROBE_NESTED=1", "timeout", "60", *argv]
    return argv


def expected(case: dict) -> tuple[str, str]:
    """(mode, how-fragment) by construction."""
    if case.get("sources") == "ps":
        return "unknown", "could not be read"
    if case.get("hidepid"):
        return "unknown", "could not be read"
    if case["form"] == "none":
        return "headless", "not found among the ancestors"
    if case["headless_flag"]:
        return "headless", "headless flag"
    if case["pty"]:
        return "interactive", "terminal and no headless flag"
    return "headless", "no terminal"


def _agree(got: dict, want_mode: str, want_how: str) -> dict:
    """``mode_equal``: the detected mode is the constructed one; ``agree``: and its ``how`` text names the expected reason."""
    mode_equal = got["mode"] == want_mode
    return {"mode_equal": mode_equal, "agree": mode_equal and want_how in got["how"]}


def run_case(case: dict, workdir: Path) -> dict:
    out = str(workdir / f"hook-{case['id']}.json")
    argv = case_argv(case, out)
    env = {
        k: v for k, v in os.environ.items() if k not in ("INTENTSHIELD_ANCESTRY_SOURCES", "INTENTSHIELD_HARNESS_MODE")
    }
    if case["pty"]:
        # a pty through util-linux ``script``; stdin is held open (a closed one makes script end the session at once)
        full = ["script", "-qec", shlex.join(argv), "/dev/null"]
        proc = subprocess.Popen(
            full, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env
        )
        try:
            proc.wait(timeout=60)
        finally:
            if proc.stdin:
                proc.stdin.close()
    else:
        proc = subprocess.run(
            ["setsid", "-w", *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=60,
        )
    row = {k: case[k] for k in ("id", "harness", "form", "headless_flag", "pty", "nested", "sources") if k in case}
    row["launcher_exit"] = proc.returncode
    try:
        got = json.loads(Path(out).read_text())
    except (OSError, ValueError) as exc:
        row.update(error=f"no hook record: {type(exc).__name__}", agree=False)
        return row
    want_mode, want_how = expected(case)
    row.update(got)
    row.update(expected_mode=want_mode, expected_how=want_how, **_agree(got, want_mode, want_how))
    return row


def matrix_cases() -> list[dict]:
    cases: list[dict] = []

    def add(**kw) -> None:
        kw.setdefault("sources", None)
        kw.setdefault("nested", False)
        kw["id"] = f"c{len(cases):02d}"
        cases.append(kw)

    for form, harness in (("native", "claude"), ("node", "claude"), ("node", "codex"), ("node", "gemini")):
        for flag in (True, False):
            for pty in (True, False):
                add(harness=harness, form=form, headless_flag=flag, pty=pty)
    for harness, form in (("claude", "native"), ("claude", "node"), ("codex", "node"), ("gemini", "node")):
        for flag, pty in ((True, False), (False, True)):  # a deeper tree: an unattended and an attended launch
            add(harness=harness, form=form, headless_flag=flag, pty=pty, nested=True)
    for pty in (True, False):
        add(harness="claude", form="none", headless_flag=False, pty=pty)
    add(
        harness="claude", form="native", headless_flag=False, pty=True, sources="ps"
    )  # the one reader a container may lack
    add(
        harness="claude", form="native", headless_flag=False, pty=True, sources="proc"
    )  # restricted to the Linux reader
    return cases


def cmd_matrix(args: argparse.Namespace) -> int:
    make_bins()
    work = Path("/tmp/probe")
    work.mkdir(exist_ok=True)
    rows = [run_case(case, work) for case in matrix_cases()]
    Path(args.file).write_text("".join(json.dumps({**r, "round": ROUND, "group": "matrix"}) + "\n" for r in rows))
    print(f"{sum(r['agree'] for r in rows)}/{len(rows)} cases agree with construction")
    return 0


def cmd_hidepid(args: argparse.Namespace) -> int:
    """root harness (claude, native-like, -p) -> sh as ``nobody`` -> hook as ``nobody``, with /proc remounted
    hidepid=2: the harness
    process is owned by another user and invisible, so the ancestry cannot be read to the top (the natural unknown-mode path)."""
    make_bins()
    work = Path("/tmp/probe")
    work.mkdir(exist_ok=True)
    os.chmod(work, 0o777)
    mount = subprocess.run(["mount", "-o", "remount,hidepid=2", "/proc"], capture_output=True, text=True)
    row: dict = {
        "group": "hidepid",
        "round": ROUND,
        "mount_exit": mount.returncode,
        "mount_stderr": mount.stderr.strip()[:200],
    }
    if mount.returncode != 0:
        row.update(error="could not remount /proc with hidepid=2", agree=False)
        Path(args.file).write_text(json.dumps(row) + "\n")
        return 0
    out = str(work / "hook-hidepid.json")
    inner = f"setpriv --reuid 65534 --regid 65534 --clear-groups {HOOK} --harness claude --out {shlex.quote(out)}"
    argv = [f"{BIN}/claude", "-p", "-c", f"sh -c {shlex.quote(inner)}; true"]
    done = subprocess.run(["setsid", "-w", *argv], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    case = {
        "id": "hidepid",
        "harness": "claude",
        "form": "native",
        "headless_flag": True,
        "pty": False,
        "hidepid": True,
    }
    row.update({k: case[k] for k in ("id", "harness", "form", "headless_flag", "pty")}, launcher_exit=done.returncode)
    try:
        got = json.loads(Path(out).read_text())
    except (OSError, ValueError) as exc:
        row.update(error=f"no hook record: {type(exc).__name__}: {done.stderr[-200:]}", agree=False)
    else:
        want_mode, want_how = expected(case)
        row.update(got, expected_mode=want_mode, expected_how=want_how, **_agree(got, want_mode, want_how))
    Path(args.file).write_text(json.dumps(row) + "\n")
    return 0


def cmd_pid1(args: argparse.Namespace) -> int:
    """Runs as the container's PID 1 and replaces itself with the dummy harness, so the harness is PID 1 (parent pid 0)."""
    make_bins()
    case = {
        "id": f"pid1-{args.form}-{'p' if args.headless == '1' else 'bare'}",
        "harness": "claude",
        "form": args.form,
        "headless_flag": args.headless == "1",
        "pty": os.isatty(0),
        "sources": None,
        "nested": False,
    }
    out = args.file
    argv = case_argv(case, out)
    os.environ.pop("INTENTSHIELD_ANCESTRY_SOURCES", None)
    os.execvp(argv[0], argv)
    return 1  # pragma: no cover


# --------------------------------------------------------------------------------------------- host side
DOCKER_RUNS = {"n": 0}  # containers started by this invocation (every `docker run`)


def sh(argv: list[str], **kw) -> subprocess.CompletedProcess:
    if argv[:2] == ["docker", "run"]:
        DOCKER_RUNS["n"] += 1
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def docker_base(worktree: Path, deps: Path, out: Path, init: bool = True, extra: list[str] | None = None) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:exec",
        "--memory",
        "1g",
        "--pids-limit",
        "256",
        *(["--init"] if init else []),
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "PYTHONPATH=/deps:/work/src",
        "-e",
        "INTENTSHIELD_PROXY_CONFIG=",
        "-e",
        "INTENTSHIELD_CONTROL_TOKEN=",
        "-e",
        "INTENTSHIELD_INTENT_MODEL_DIR=/tmp/none",
        "-v",
        f"{worktree}:/work:ro",
        "-v",
        f"{deps}:/deps:ro",
        "-v",
        f"{out}:/out",
        *(extra or []),
        IMAGE,
    ]


def cmd_docker(args: argparse.Namespace) -> int:
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    work = Path(args.worktree).resolve()
    deps = Path(args.deps).resolve()
    probe = "/work/benchmarks/hook_fidelity/linux_probe.py"
    base = docker_base(work, deps, out)
    meta: dict = {
        "image": IMAGE,
        "round": ROUND,
        "worktree_commit": sh(["git", "rev-parse", "--short", "HEAD"], cwd=work).stdout.strip(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "network": "none (docker run --network none)",
        "mounts": "worktree read-only at /work, pytest and its pure-Python dependencies read-only at /deps, results at /out",
        "flags": "--read-only --tmpfs /tmp:exec --memory 1g --pids-limit 256",
        "runs": {},
    }
    meta["image_id"] = sh(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"]).stdout.strip()
    meta["image_digest"] = sh(
        ["docker", "image", "inspect", IMAGE, "--format", "{{index .RepoDigests 0}}"]
    ).stdout.strip()
    meta["docker_server"] = sh(
        ["docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"]
    ).stdout.strip()
    meta["uname"] = sh([*base, "uname", "-srm"]).stdout.strip()
    meta["python"] = sh([*base, "python3", "--version"]).stdout.strip()
    meta["ps_in_image"] = sh([*base, "sh", "-c", "command -v ps || echo absent"]).stdout.strip()
    meta["script_in_image"] = sh([*base, "sh", "-c", "command -v script"]).stdout.strip()

    def run(name: str, argv: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
        done = sh(argv, timeout=timeout)
        meta["runs"][name] = {
            "extra_docker_flags": [a for a in argv[: argv.index(IMAGE)] if a in ("-t", "--cap-add", "SYS_ADMIN")]
            + (["--init"] if "--init" in argv else []),
            "command_in_container": argv[argv.index(IMAGE) + 1 :],
            "exit": done.returncode,
        }
        return done

    # 1. the matrix of nested trees
    run("matrix", [*base, "python3", probe, "matrix", "/out/matrix.jsonl"])
    # 2. hidepid=2 (needs CAP_SYS_ADMIN to remount /proc; the default seccomp profile allows mount with it)
    run(
        "hidepid",
        [
            *docker_base(work, deps, out, extra=["--cap-add", "SYS_ADMIN"]),
            "python3",
            probe,
            "hidepid",
            "/out/hidepid.jsonl",
        ],
    )
    # 3. the dummy harness is PID 1 (parent pid 0), without and with a pty (-t)
    rows = []
    for tty in (False, True):
        for form in ("native", "node"):
            for headless in ("1", "0"):
                name = f"pid1-{form}-{'p' if headless == '1' else 'bare'}-{'tty' if tty else 'notty'}"
                fn = f"/out/{name}.json"
                argv = docker_base(work, deps, out, init=False, extra=["-t"] if tty else [])
                done = run(name, [*argv, "python3", probe, "pid1", fn, form, headless])
                try:
                    got = json.loads((out / f"{name}.json").read_text())
                except (OSError, ValueError):
                    rows.append(
                        {
                            "id": name,
                            "group": "pid1",
                            "round": ROUND,
                            "error": "no hook record",
                            "agree": False,
                            "docker_exit": done.returncode,
                        }
                    )
                    continue
                case = {"form": form, "headless_flag": headless == "1", "pty": tty}
                want_mode, want_how = expected(case)
                rows.append(
                    {
                        "id": name,
                        "group": "pid1",
                        "round": ROUND,
                        "harness": "claude",
                        "form": form,
                        "headless_flag": headless == "1",
                        "pty": tty,
                        **got,
                        "expected_mode": want_mode,
                        "expected_how": want_how,
                        **_agree(got, want_mode, want_how),
                    }
                )
                (out / f"{name}.json").unlink()
    (out / "pid1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    # 4. the unit tests of the readers inside the container: with --init (pytest has a parent), and as PID 1 (it does not)
    tests = ["/work/tests/test_translation_ancestry.py", "/work/tests/test_wrap_hook.py"]
    pytest_cmd = [
        "python3",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--noconftest",
        "--rootdir=/work",
        "-rs",
        *tests,
    ]
    done = run("pytest-init", [*base, *pytest_cmd])
    (out / "pytest-linux.txt").write_text(done.stdout + done.stderr)
    done = run("pytest-pid1", [*docker_base(work, deps, out, init=False), *pytest_cmd])
    (out / "pytest-linux-pid1.txt").write_text(done.stdout + done.stderr)
    meta["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["containers_started"] = DOCKER_RUNS["n"]  # every `docker run`, the metadata probes included
    (out / "docker-meta.json").write_text(json.dumps(meta, indent=1))
    return cmd_summarize(argparse.Namespace(out_dir=str(out)))


def _rows(out: Path) -> list[dict]:
    rows: list[dict] = []
    for name in ("matrix", "hidepid", "pid1"):
        path = out / f"{name}.jsonl"
        if path.exists():
            rows += [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return rows


def cmd_summarize(args: argparse.Namespace) -> int:
    out = Path(args.out_dir)
    rows = _rows(out)
    (out / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    lines = [
        "# Linux `/proc` reader in a container (derived by `linux_probe.py summarize` from "
        "`matrix.jsonl`, `hidepid.jsonl`, `pid1.jsonl`)",
        "",
        "Ground truth is how each tree was built, not an independent oracle. "
        "`agree` = the detected mode equals the constructed one and "
        "the `how` text names the expected reason.",
        "",
        "| group | harness (form) | flag | pty | nested | sources | expected | detected | source | complete | depth "
        "| mode equal | agree |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r.get('group')} | {r.get('harness')} ({r.get('form')}) | {'yes' if r.get('headless_flag') else 'no'} | "
            f"{'yes' if r.get('pty') else 'no'} | {'yes' if r.get('nested') else 'no'} | {r.get('sources') or 'default'} | "
            f"{r.get('expected_mode', '-')} | {r.get('mode', r.get('error', '-'))} | {r.get('source', '-')} | "
            f"{r.get('complete', '-')} | "
            f"{r.get('depth', '-')} | {'yes' if r.get('mode_equal') else 'NO'} | {'yes' if r.get('agree') else 'NO'} |"
        )
    summary: dict = {"rows": len(rows), "agree": sum(bool(r.get("agree")) for r in rows), "by_group": {}}
    for g in sorted({r.get("group") for r in rows}):
        sub = [r for r in rows if r.get("group") == g]
        summary["by_group"][g] = {
            "agree": sum(bool(r.get("agree")) for r in sub),
            "n": len(sub),
            "mode_equal": sum(bool(r.get("mode_equal")) for r in sub),
            "sources": sorted({r.get("source", "-") for r in sub}),
            "disagree": [r["id"] for r in sub if not r.get("agree")],
        }
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    (out / "table.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(summary))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("hook")
    p.add_argument("--harness", required=True)
    p.add_argument("--out", required=True)
    for name in ("matrix", "hidepid"):
        sub.add_parser(name).add_argument("file")
    p = sub.add_parser("pid1")
    p.add_argument("file")
    p.add_argument("form", choices=("native", "node"))
    p.add_argument("headless", choices=("0", "1"))
    p = sub.add_parser("docker")
    p.add_argument("out_dir")
    p.add_argument("--worktree", default=str(ROOT))
    p.add_argument("--deps", required=True)
    sub.add_parser("summarize").add_argument("out_dir")
    args = parser.parse_args(argv)
    return {
        "hook": cmd_hook,
        "matrix": cmd_matrix,
        "hidepid": cmd_hidepid,
        "pid1": cmd_pid1,
        "docker": cmd_docker,
        "summarize": cmd_summarize,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
