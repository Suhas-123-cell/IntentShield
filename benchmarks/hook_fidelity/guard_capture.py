#!/usr/bin/env python3
"""Byte capture of third-party guard hooks, run inside a deny-default macOS sandbox.

    guard_capture.py selftest  --scratch DIR                 # prove the sandbox: no network, no write outside DIR, no home read
    guard_capture.py capture   --scratch DIR --out FILE.jsonl [--guard ID ...]

What it does. For each guard in ``SPECS`` it runs the guard's OWN hook entry point (the command the guard's shipped hook
configuration registers) on fixture stdin payloads and records the exact stdout bytes, stderr bytes, exit code and wall time.
The payloads are text only: a "flagged" payload is a Bash tool call such as ``rm -rf ./hf-fixture-dir`` or ``cat .env``; no
guard executes it, and nothing here ever runs the flagged command.

Containment (every guard process): ``sandbox-exec`` with a deny-default profile that allows

* process exec and fork, sysctl reads, the mach lookups a node, python or bash process needs;
* file READS of system paths, the interpreter installs, the guard's own clone and the scratch directory (not the home directory);
* file WRITES only under the scratch directory (and /dev/null);
* NO network at all (``(deny network*)``, loopback included).

``selftest`` runs probes under the same profile and records that each was refused. HOME, TMPDIR and the working directory of
a guard process are inside the scratch directory; the environment is a short allow-list, with no key or token.

A guard that needs a binary this machine cannot build offline, or a service, is recorded as NOT-CAPTURED with the reason.
This file imports nothing from IntentShield.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRATCH_ROOT = (os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity"))
CLONES = Path(SCRATCH_ROOT) / "corpus"
NODE_DIR = Path.home() / ".nvm/versions/node/v20.20.2"
TIMEOUT_S = 60

# ---------------------------------------------------------------------------------------------------------------
# Sandbox


def profile_for(scratch: Path, readable: list[Path]) -> str:
    """The deny-default profile. Reads are limited to system paths, the listed directories and the scratch directory."""
    system_read = [
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/private/etc",
        "/private/var/db",
        "/dev",
        "/opt/homebrew",
        "/private/var/select",
    ]
    reads = '(literal "/") ' + " ".join(f'(subpath "{p}")' for p in [*system_read, *map(str, readable), str(scratch)])
    return "\n".join(
        [
            "(version 1)",
            "(deny default)",
            "(allow process-exec*)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            "(allow signal (target self))",
            "(allow ipc-posix-shm)",
            "(allow file-read-metadata)",
            f"(allow file-read* {reads})",
            f'(allow file-write* (subpath "{scratch}") (literal "/dev/null") (literal "/dev/dtracehelper"))',
            "(deny network*)",
            "",
        ]
    )


def clean_env(scratch: Path, extra: dict[str, str] | None = None, path_dirs: list[str] | None = None) -> dict[str, str]:
    path = ":".join([*(path_dirs or []), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    env = {
        "PATH": path,
        "HOME": str(scratch / "home"),
        "TMPDIR": str(scratch / "tmp"),
        "LANG": "en_US.UTF-8",
        "USER": "hfuser",
        "LOGNAME": "hfuser",
        "SHELL": "/bin/bash",
        "NO_COLOR": "1",
    }
    env.update(extra or {})
    return env


def run_sandboxed(
    argv: list[str],
    stdin: bytes,
    scratch: Path,
    readable: list[Path],
    env: dict[str, str],
    cwd: Path | None = None,
    timeout: int = TIMEOUT_S,
) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    for sub in ("home", "tmp", "work"):
        (scratch / sub).mkdir(exist_ok=True)
    # GNU-style mktemp: macOS mktemp ignores TMPDIR for a bare call, and the user temp dir is not writable in the sandbox
    shim = scratch / "shim"
    shim.mkdir(exist_ok=True)
    mk = shim / "mktemp"
    mk.write_text(
        '#!/bin/sh\nif [ "$#" -eq 0 ]; then exec /usr/bin/mktemp "${TMPDIR:-/tmp}/tmp.XXXXXXXXXX"; fi\nexec /usr/bin/mktemp "$@"\n'
    )
    mk.chmod(0o755)
    env = {**env, "PATH": f"{shim}:{env.get('PATH', '')}"}
    profile = scratch / "profile.sb"
    profile.write_text(profile_for(scratch, readable))
    # sandbox-exec resets TMPDIR to the user temp dir (not writable here), so TMPDIR is set again inside the sandbox
    cmd = ["/usr/bin/sandbox-exec", "-f", str(profile), "/usr/bin/env", f"TMPDIR={scratch / 'tmp'}", *argv]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, cwd=str(cwd or scratch / "work"), env=env, timeout=timeout)
        out, err, code, timed_out = proc.stdout, proc.stderr, proc.returncode, False
    except subprocess.TimeoutExpired as exc:
        out, err, code, timed_out = exc.stdout or b"", exc.stderr or b"", None, True
    return {"stdout": out, "stderr": err, "exit_code": code, "timed_out": timed_out, "wall_s": round(time.monotonic() - t0, 3)}


def selftest(scratch: Path) -> dict:
    """Probes under the capture profile. Each must FAIL (be refused) for the sandbox to count as holding."""
    outside = Path(SCRATCH_ROOT) / "guard-replay-canary.txt"
    outside.unlink(missing_ok=True)
    home_probe = Path.home() / ".zshrc"
    env = clean_env(scratch)
    probes = {
        "write_outside_scratch": (["/bin/sh", "-c", f"echo x > {outside}"], lambda r: not outside.exists()),
        "write_inside_scratch": (
            ["/bin/sh", "-c", f"echo x > {scratch}/work/ok.txt"],
            lambda r: (scratch / "work/ok.txt").exists(),
        ),
        "read_home_file": (["/bin/sh", "-c", f"head -c 1 {home_probe}"], lambda r: r["exit_code"] != 0 and not r["stdout"]),
        "network_loopback": (["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", "9"], lambda r: r["exit_code"] != 0),
        "network_external": (["/usr/bin/curl", "-sS", "--max-time", "4", "https://example.com"], lambda r: r["exit_code"] != 0),
    }
    results = {}
    for name, (argv, held) in probes.items():
        r = run_sandboxed(argv, b"", scratch, [], env)
        results[name] = {
            "exit_code": r["exit_code"],
            "stderr": r["stderr"].decode("utf-8", "replace")[:160],
            "held": bool(held(r)),
        }
    # inside-scratch write is expected to SUCCEED; the others must be refused
    results["write_inside_scratch"]["held"] = results["write_inside_scratch"]["held"]
    outside.unlink(missing_ok=True)
    return results


# ---------------------------------------------------------------------------------------------------------------
# Payloads (shapes written from the vendors' hook documentation, as stubhook.py's tables are)

CWD = "/work/hf-fixture"


def payload(harness: str, tool: str, tool_input: dict, **extra) -> dict:
    """The stdin JSON a harness hands a PreToolUse-style hook. Fields beyond tool name and input are the documented common ones."""
    if harness == "claude":
        base = {
            "session_id": "hf-session",
            "transcript_path": "/work/transcript.jsonl",
            "cwd": CWD,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "toolu_hf1",
        }
    elif harness == "codex":
        base = {
            "session_id": "hf-session",
            "turn_id": "hf-turn",
            "transcript_path": None,
            "cwd": CWD,
            "hook_event_name": "PreToolUse",
            "model": "stub-model",
            "permission_mode": "default",
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "call_hf1",
        }
    elif harness == "gemini":
        base = {
            "session_id": "hf-session",
            "transcript_path": "/work/transcript.json",
            "cwd": CWD,
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-11-01T00:00:00.000Z",
            "tool_name": tool,
            "tool_input": tool_input,
        }
    elif harness == "cursor":
        base = {
            "conversation_id": "hf-conv",
            "generation_id": "hf-gen",
            "hook_event_name": "beforeShellExecution",
            "model": "auto",
            "cursor_version": "1.7.0",
            "workspace_roots": [CWD],
            "user_email": None,
            "transcript_path": None,
            **({"command": tool_input.get("command", ""), "cwd": CWD} if tool == "Bash" else {}),
        }
    elif harness == "cursor-pre":  # Cursor's preToolUse event (tool_name Shell), the other documented shell-gate shape
        base = {
            "conversation_id": "hf-conv",
            "generation_id": "hf-gen",
            "hook_event_name": "preToolUse",
            "model": "auto",
            "cursor_version": "1.7.0",
            "workspace_roots": [CWD],
            "cwd": CWD,
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "hf-tool-1",
            "user_email": None,
            "transcript_path": None,
        }
    else:
        raise ValueError(harness)
    base.update(extra)
    return base


# the three fixtures of the task: a benign-but-flagged destructive command, a benign-but-flagged secret read, a benign call
RM = "rm -rf ./hf-fixture-dir"
CAT_ENV = "cat .env"
BENIGN = "echo hello-hf-fixture"

SHELL_TOOL = {"claude": "Bash", "codex": "Bash", "gemini": "run_shell_command", "cursor": "Bash", "cursor-pre": "Shell"}


def shell_scenarios(harness: str, extra: list[tuple[str, str]] | None = None) -> list[tuple[str, dict]]:
    tool = SHELL_TOOL[harness]
    items = [("flagged-rm", RM), ("flagged-env-read", CAT_ENV), ("benign", BENIGN), *(extra or [])]
    return [(name, payload(harness, tool, {"command": cmd})) for name, cmd in items]


# ---------------------------------------------------------------------------------------------------------------
# Guard specs. Every entry lists the entry-point argv, the readable directories beyond the clone, and the scenarios.


def _clone(name: str) -> Path:
    return CLONES / name / "repo"


def _git_head(path: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def specs() -> list[dict]:
    node = str(NODE_DIR / "bin" / "node")
    out: list[dict] = []

    # ---- cc-safe-setup: hooks/hooks.json registers the core hooks as inline shell commands (run as `sh -c <command>`); the
    # example scripts are registered as `bash <path>`.
    repo = _clone("cc-safe-setup")
    core = json.loads((repo / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"]
    inline = {}
    for i, group in enumerate(core):
        for hook in group["hooks"]:
            inline[i] = (group["matcher"], hook["command"])
    entries = []
    # core hook 0 = recursive rm, 1 = destructive git, 2 = credential in command (Bash); the secret-file Write|Edit guard is index 3
    for idx, label in ((0, "core-rm-guard"), (1, "core-git-guard"), (2, "core-credential-in-command")):
        entries.append(
            {
                "entry": label,
                "argv": ["/bin/sh", "-c", inline[idx][1]],
                "harnesses": ["claude"],
                "extra": [("flagged-git-reset", "git reset --hard HEAD~1")] if idx == 1 else [],
            }
        )
    for script, label, env in (
        ("secret-file-read-guard.sh", "example-secret-file-read-guard", {}),
        ("powershell-remove-item-guard.sh", "example-powershell-remove-item-guard (ask by default)", {}),
        ("memory-write-guard.sh", "example-memory-write-guard (ask, opt-in)", {"CC_MEMORY_WRITE_APPROVAL": "ask"}),
        ("mcp-tool-guard.sh", "example-mcp-tool-guard (ask, opt-in)", {"CC_MCP_AUTOMATION_GUARD": "ask"}),
    ):
        entries.append(
            {
                "entry": label,
                "argv": ["/bin/bash", str(repo / "examples" / script)],
                "harnesses": ["claude"],
                "env": env,
                "extra": [("flagged-powershell-remove", "Remove-Item -Recurse -Force ./hf-fixture-dir")]
                if "powershell" in script
                else [],
                "tools": [
                    ("flagged-read-env-tool", "Read", {"file_path": ".env"}),
                    ("flagged-memory-write", "Write", {"file_path": "/work/.claude/projects/x/memory/MEMORY.md", "content": "x"}),
                    ("flagged-mcp-tool", "mcp__db__run_query", {"query": "DROP TABLE hf_fixture"}),
                ],
            }
        )
    # failure path the guard documents: no JSON reader on PATH -> warning on stderr, then allow
    entries.append(
        {
            "entry": "core-rm-guard / no jq, python3 or node on PATH (documented fail-open)",
            "argv": ["/bin/sh", "-c", inline[0][1]],
            "harnesses": ["claude"],
            "path_dirs": [],
            "no_tools": True,
            "only": ["flagged-rm"],
            "note": "PATH is /usr/bin:/bin; on this machine /usr/bin/jq exists, so the run uses a PATH shim dir that hides jq",
        }
    )
    out.append({"id": "cc-safe-setup", "clone": repo, "entries": entries})

    # ---- safety-net: node dist/bin/cc-safety-net.js hook --<host>
    repo = _clone("safety-net")
    entries = []
    for harness, flag in (("claude", "--coding-cli"), ("codex", "--codex"), ("cursor", "--cursor"), ("gemini", "--gemini-cli")):
        entries.append(
            {
                "entry": f"cc-safety-net hook {flag}",
                "argv": [node, str(repo / "dist/bin/cc-safety-net.js"), "hook", flag],
                "harnesses": [harness],
                "extra": [("flagged-git-reset", "git reset --hard HEAD~1")],
            }
        )
    out.append({"id": "safety-net", "clone": repo, "entries": entries, "node": True})

    # ---- railway-guard
    repo = _clone("railway-guard")
    entries = [
        {
            "entry": "hooks/railway-guard.sh",
            "argv": ["/bin/bash", str(repo / "hooks/railway-guard.sh")],
            "harnesses": ["claude"],
            "extra": [
                ("flagged-railway-delete", "railway delete"),
                ("flagged-railway-redeploy-staging", "railway redeploy -e staging"),
                ("flagged-railway-redeploy-production", "railway redeploy -e production"),
            ],
        }
    ]
    out.append({"id": "railway-guard", "clone": repo, "entries": entries})

    # ---- axonflow-codex: scripts/pre-tool-check.sh. Needs an AxonFlow policy server for a policy verdict; there is none in a
    # no-network sandbox, so the captures are the guard's own paths that need none: an unreachable endpoint (documented
    # fail-open) and the guard's local free-tier throttle (its own exit-2 deny path, driven by a state file in HOME).
    repo = _clone("axonflow-codex")
    script = ["/bin/bash", str(repo / "scripts/pre-tool-check.sh")]
    base_env = {"AXONFLOW_TELEMETRY": "off", "AXONFLOW_ENDPOINT": "http://127.0.0.1:9", "AXONFLOW_TIMEOUT_SECONDS": "2"}
    out.append(
        {
            "id": "axonflow-codex",
            "clone": repo,
            "entries": [
                {
                    "entry": "pre-tool-check.sh / policy server unreachable (documented fail-open)",
                    "argv": script,
                    "harnesses": ["codex"],
                    "env": base_env,
                    "tools": [],
                    "extra": [],
                },
                {
                    "entry": "pre-tool-check.sh / local free-tier throttle active (guard's exit-2 deny path)",
                    "argv": script,
                    "harnesses": ["codex"],
                    "env": base_env,
                    "home_files": {".cache/axonflow/throttle-until": "9999999999 free_tier_limit\n"},
                },
            ],
        }
    )

    # ---- gemini-intrupt-hook: python3 hook.py. Its approval service is a network API: with no key it fails closed (deny); with a
    # key and an unreachable service it also denies; with AEGMIS_FORWARD_ALL=false a low-risk call is allowed locally.
    repo = _clone("gemini-intrupt-hook")
    hook = ["/opt/homebrew/bin/python3", "-I", str(repo / "hook.py")]
    out.append(
        {
            "id": "gemini-intrupt-hook",
            "clone": repo,
            "entries": [
                {
                    "entry": "hook.py / default env, no AEGMIS_API_KEY",
                    "argv": hook,
                    "harnesses": ["gemini"],
                    "extra": [("flagged-workspace-wipe", "rm -rf .")],
                    "tools": [("non-gated-tool", "read_file", {"file_path": "README.md"})],
                },
                {
                    "entry": "hook.py / AEGMIS_FORWARD_ALL=false (local risk filter)",
                    "argv": hook,
                    "harnesses": ["gemini"],
                    "env": {"AEGMIS_FORWARD_ALL": "false"},
                    "extra": [("flagged-workspace-wipe", "rm -rf .")],
                },
                {
                    "entry": "hook.py / key set, approval service unreachable",
                    "argv": hook,
                    "harnesses": ["gemini"],
                    "env": {
                        "AEGMIS_API_KEY": "sk_org_org_hf_deadbeef",
                        "AEGMIS_BASE_URL": "http://127.0.0.1:9",
                        "AEGMIS_FORWARD_ALL": "true",
                        "AEGMIS_TIMEOUT": "5",
                        "AEGMIS_POLL_INTERVAL": "1",
                    },
                    "only": ["flagged-rm", "benign"],
                },
            ],
        }
    )

    # ---- block-no-verify: TypeScript, no dist in the clone. Compiled with tsc into the scratch build dir (type errors only: no
    # @types/node installed; the emitted JS is what runs), @polyhook/sdk 0.1.4 from the earlier pack, shell-quote 1.8.3 (the
    # repo asks ^1.9.0; tokenizer differences are possible).
    repo = _clone("block-no-verify")
    build = Path(SCRATCH_ROOT) / "guard-replay" / "block-no-verify" / "build"
    entries = []
    for harness in ("claude", "cursor", "cursor-pre", "gemini"):
        entries.append(
            {
                "entry": "dist/cli.js (polyhook SDK)",
                "argv": [node, str(build / "dist/cli.js")],
                "harnesses": [harness],
                "extra": [("flagged-no-verify", "git commit --no-verify -m hf-fixture")],
                "readable": [build],
                "note": "built from source with tsc; shell-quote 1.8.3 instead of ^1.9.0",
            }
        )
    out.append({"id": "block-no-verify", "clone": repo, "entries": entries, "node": True})

    # ---- guards recorded as NOT-CAPTURED, with the reason checked on this machine
    return out + not_captured()


def not_captured() -> list[dict]:
    return [
        {
            "id": "dcg",
            "clone": _clone("dcg"),
            "not_captured": "Rust binary; `cargo metadata --offline --locked` fails (crates not in the local registry cache), so it cannot be built without network; no prebuilt binary on this machine",
        },
        {
            "id": "tool-gate-hook",
            "clone": _clone("tool-gate-hook"),
            "not_captured": "Rust binary; `cargo metadata --offline --locked` fails (crates not in the local registry cache); no prebuilt binary on this machine",
        },
        {
            "id": "ggshield",
            "clone": _clone("ggshield"),
            "not_captured": "Python package whose imports (pygitguardian, sigstore, marshmallow-dataclass and others) are not installed here, and whose secret scan needs the GitGuardian API (no key, no network); installing the dependency tree was not done",
            "probe": ["pygitguardian", "sigstore"],
        },
        {
            "id": "hol-guard",
            "clone": _clone("hol-guard"),
            "not_captured": "Python package whose imports (sigstore, mcp, keyring, rich and others) are not installed here; its hook also reaches a local daemon; installing the dependency tree was not done",
            "probe": ["sigstore", "mcp"],
        },
    ]


def build_inputs(entry: dict, harness: str) -> list[tuple[str, dict]]:
    """(scenario name, stdin payload) for one entry and harness."""
    items = shell_scenarios(harness, entry.get("extra"))
    if entry.get("tools"):
        items += [(name, payload(harness, tool, tool_input)) for name, tool, tool_input in entry["tools"]]
    if entry.get("only"):
        items = [item for item in items if item[0] in entry["only"]]
    return items


def scrub_bytes(data: bytes) -> bytes:
    """Scratch and home paths replaced by placeholders (the repo convention); everything else is verbatim."""
    for old, new in ((SCRATCH_ROOT, "<scratch>"), (os.path.realpath(SCRATCH_ROOT), "<scratch>"), (str(Path.home()), "<home>")):
        data = data.replace(old.encode(), new.encode())
    return data


def probe_missing(modules: list[str], scratch: Path) -> list[str]:
    """Which of ``modules`` cannot be imported by the system python3 (run in the sandbox, with -I)."""
    missing = []
    for module in modules:
        r = run_sandboxed(["/opt/homebrew/bin/python3", "-I", "-c", f"import {module}"], b"", scratch, [], clean_env(scratch))
        if r["exit_code"] != 0:
            missing.append(module)
    return missing


def capture_guard(spec: dict, scratch_root: Path, records: list[dict]) -> None:
    clone = spec["clone"]
    commit = _git_head(clone)
    if spec.get("not_captured"):
        probe = probe_missing(spec.get("probe", []), scratch_root / spec["id"] / "probe") if spec.get("probe") else []
        records.append(
            {
                "guard": spec["id"],
                "guard_commit": commit,
                "status": "NOT-CAPTURED",
                "reason": spec["not_captured"],
                "probe_modules_missing": probe,
            }
        )
        return
    for entry_index, entry in enumerate(spec["entries"]):
        for harness in entry["harnesses"]:
            for name, stdin in build_inputs(entry, harness):
                run_scratch = scratch_root / spec["id"] / "out" / f"e{entry_index}-{harness}-{name}"
                if run_scratch.exists():
                    shutil.rmtree(run_scratch)
                run_scratch.mkdir(parents=True)
                path_dirs = entry.get("path_dirs", [str(NODE_DIR / "bin")] if spec.get("node") else [])
                env = clean_env(run_scratch, entry.get("env"), path_dirs)
                readable = [clone] + ([NODE_DIR] if spec.get("node") else []) + [Path(p) for p in entry.get("readable", [])]
                if entry.get("no_tools"):
                    shim = run_scratch / "nojq-bin"
                    shim.mkdir()
                    for tool in (
                        "awk",
                        "cat",
                        "tr",
                        "sed",
                        "grep",
                        "printf",
                        "basename",
                        "echo",
                        "sh",
                        "bash",
                        "cut",
                        "head",
                        "wc",
                        "date",
                    ):
                        real = shutil.which(tool, path="/usr/bin:/bin")
                        if real:
                            (shim / tool).symlink_to(real)
                    env["PATH"] = str(shim)
                    readable = readable + [shim]
                # The workspace of the fixture: a .env that holds only a benign marker, so a guard that reads it sees no real secret.
                (run_scratch / "work").mkdir(exist_ok=True)
                (run_scratch / "work" / ".env").write_text("HF_FIXTURE_MARKER=not-a-secret\n")
                (run_scratch / "home" / ".claude").mkdir(parents=True, exist_ok=True)
                for rel, text in entry.get("home_files", {}).items():
                    target = run_scratch / "home" / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(text)
                # the payload's cwd is a real directory (some guards fail closed on a missing one): the run's work directory
                stdin = json.loads(json.dumps(stdin).replace(CWD, str(run_scratch / "work")))
                result = run_sandboxed(entry["argv"], json.dumps(stdin).encode(), run_scratch, readable, env)
                result["stdout"], result["stderr"] = scrub_bytes(result["stdout"]), scrub_bytes(result["stderr"])
                stdin = json.loads(scrub_bytes(json.dumps(stdin).encode()))
                records.append(
                    {
                        "guard": spec["id"],
                        "guard_commit": commit,
                        "entry": entry["entry"],
                        "harness_shape": harness,
                        "scenario": name,
                        "stdin": stdin,
                        "argv": [
                            scrub_bytes((a if len(a) < 200 else a[:200] + "...(truncated)").encode()).decode()
                            for a in entry["argv"]
                        ],
                        "env_added": entry.get("env", {}),
                        "note": entry.get("note", ""),
                        "stdout_b64": base64.b64encode(result["stdout"]).decode(),
                        "stderr_b64": base64.b64encode(result["stderr"]).decode(),
                        "stdout": result["stdout"].decode("utf-8", "replace"),
                        "stderr": result["stderr"].decode("utf-8", "replace"),
                        "exit_code": result["exit_code"],
                        "timed_out": result["timed_out"],
                        "wall_s": result["wall_s"],
                        "sandbox": "sandbox-exec deny-default; no network; writes only under scratch; home unreadable",
                    }
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("selftest")
    p1.add_argument("--scratch", type=Path, required=True)
    p2 = sub.add_parser("capture")
    p2.add_argument("--scratch", type=Path, required=True)
    p2.add_argument("--out", type=Path, required=True)
    p2.add_argument("--guard", action="append", default=[])
    args = parser.parse_args(argv)
    scratch = args.scratch.resolve()
    if not str(scratch).startswith(SCRATCH_ROOT):
        print(f"scratch must be under {SCRATCH_ROOT}", file=sys.stderr)
        return 2
    if args.cmd == "selftest":
        results = selftest(scratch / "selftest")
        print(json.dumps(results, indent=1))
        return 0 if all(r["held"] for r in results.values()) else 1
    records: list[dict] = []
    for spec in specs():
        if args.guard and spec["id"] not in args.guard:
            continue
        capture_guard(spec, scratch, records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("a") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    print(f"{len(records)} captures appended to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
