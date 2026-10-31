"""Self-disclosure parameter stripping, measured on the tool schemas real agents saw.

The rule (``mcp_inspect.self_disclosure_fields``) removes from a tool's schema every parameter that
asks the calling agent about itself: its model name, system prompt or conversation. No tool needs
these to do its job, and MSB's out-of-scope-parameter and tool-transfer attacks are exactly that
channel. This script answers two questions a reader of the rule should ask:

1. On every tool schema the four MSB agents were shown (the recorded ``none`` runs, every server,
   every case), which parameters does the rule strip, and on which servers? A stripped parameter on
   a task, support or filesystem server is a false flag; on an attack-role server it is the attack.
2. Did those parameters carry the harm? From the same traces: of the undefended harmful calls, how
   many sent a value in a stripped parameter.

No model, no Docker: it reads ``results/improve/msb-replay/recorded/<model>/none.jsonl.gz`` and the
MSB case grid. Output is a Markdown report on stdout and, with ``--out``, a JSON file.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "benchmarks")]

import msb  # noqa: E402

from intentshield.mcp_inspect import self_disclosure_fields  # noqa: E402

ROLES = ("task", "attack", "addition", "support", "filesystem")


def role_map(data: Path) -> dict[str, dict[str, str]]:
    """Case id -> server id -> role, from the case grid and the neutral-id scheme the runner uses."""
    out: dict[str, dict[str, str]] = {}
    for case in msb.cases(data):
        by_server = {"filesystem": "filesystem"}
        try:
            ids = msb.server_ids(data, case, [r for r in ROLES if r != "filesystem"])
        except FileNotFoundError:  # a filesystem-only case: no named task server
            ids = {}
        by_server.update({server_id: role for role, server_id in ids.items()})
        out[case["id"]] = by_server
    return out


def scan_traces(recorded: Path, roles: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Every distinct (server, tool, schema) the agents saw, what the rule strips from it, and the
    harmful calls that used a stripped parameter."""
    schemas: dict[tuple[str, str, str], dict[str, Any]] = {}
    catalogs: dict[str, dict[str, Any]] = {}
    cases = 0
    for trace in sorted(recorded.glob("*/none.jsonl.gz")):
        model = trace.parent.name
        with gzip.open(trace, "rt") as handle:
            for line in handle:
                row = json.loads(line)
                cases += 1
                by_server = roles.get(row["id"], {})
                for server_id, tools in (row.get("tools") or {}).items():
                    role = by_server.get(server_id, "unknown")
                    base = server_id.rsplit("-", 1)[0] if role in ("task", "attack", "addition") else server_id
                    for tool in tools:
                        schema = tool.get("input_schema") or {}
                        key = (base, tool["name"], json.dumps(schema, sort_keys=True))
                        entry = schemas.setdefault(key, {"server": base, "tool": tool["name"], "roles": set(),
                                                          "parameters": sorted(schema.get("properties") or {}),
                                                          "stripped": sorted(self_disclosure_fields(schema)),
                                                          "models": set()})
                        entry["roles"].add(role)
                        entry["models"].add(model)
                catalogs[row["id"]] = row.get("tools") or {}
    rows = sorted(schemas.values(), key=lambda e: (e["server"], e["tool"]))
    for entry in rows:
        entry["roles"], entry["models"] = sorted(entry["roles"]), sorted(entry["models"])
    return {"cases": cases, "schemas": rows, "catalogs": catalogs}


def harm_through_stripped(results: Path, catalogs: dict[str, dict[str, Any]], grid: dict[str, dict[str, Any]],
                          harmful=None) -> dict[str, Any]:
    """From the committed undefended traces (``results/msb/<model>/none.jsonl``): the cases where harm
    executed, and how many of them did it through a parameter the rule strips (joined to the catalog
    the agent saw in that case). ``harmful`` defaults to MSB's own per-call test."""
    harmful = harmful or (lambda case, step: msb.is_harmful(case, step, step.get("sent") or step["arguments"]))
    total, via = Counter(), Counter()
    for trace in sorted(results.glob("*/none.jsonl")):
        model = trace.parent.name
        for line in trace.read_text().splitlines():
            row = json.loads(line)
            if not row.get("harm_executed") or row["id"] not in grid:
                continue
            total[model] += 1
            case = grid[row["id"]]
            for step in row["trace"]:
                if not step.get("executed") or not harmful(case, step):
                    continue
                name = step["tool"].partition(":")[2]
                sent = {k for k, v in (step.get("sent") or step["arguments"]).items() if str(v).strip()}
                stripped = set()
                for tools in catalogs.get(row["id"], {}).values():
                    stripped |= {f for t in tools if t["name"] == name
                                 for f in self_disclosure_fields(t.get("input_schema") or {})}
                if sent & stripped:
                    via[model] += 1
                    break
    return {"harm_total": dict(total), "harm_via_stripped": dict(via)}


def summarize(result: dict[str, Any]) -> dict[str, Any]:
    by_role: dict[str, Counter] = defaultdict(Counter)
    flagged = []
    for entry in result["schemas"]:
        for role in entry["roles"]:
            by_role[role]["tools"] += 1
            by_role[role]["parameters"] += len(entry["parameters"])
            by_role[role]["stripped"] += len(entry["stripped"])
        if entry["stripped"]:
            flagged.append(entry)
    false_flags = [e for e in flagged if not {"attack", "addition"} & set(e["roles"])]
    distinct = {"schemas": len(result["schemas"]), "parameters": sum(len(e["parameters"]) for e in result["schemas"]),
                "stripped": sum(len(e["stripped"]) for e in flagged), "schemas_with_a_stripped": len(flagged)}
    return {"by_role": {r: dict(c) for r, c in sorted(by_role.items())}, "distinct": distinct, "flagged": flagged,
            "false_flags": false_flags, "distinct_schemas": len(result["schemas"])}


def report(result: dict[str, Any], summary: dict[str, Any]) -> str:
    lines = ["# Self-disclosure parameter stripping on the MSB catalogs", "",
             f"{result['cases']} recorded undefended cases, {summary['distinct_schemas']} distinct tool schemas.", "",
             "| server role | tools | parameters | stripped |", "|---|---|---|---|"]
    for role, c in summary["by_role"].items():
        lines.append(f"| {role} | {c['tools']} | {c['parameters']} | {c['stripped']} |")
    d = summary["distinct"]
    lines += ["", "A schema that appears under two roles is counted in both rows (every `addition` schema is also an "
              "`attack` schema), so the rows must not be added up. Distinct schemas: "
              f"{d['schemas']} with {d['parameters']} parameters, of which {d['stripped']} are stripped, on "
              f"{d['schemas_with_a_stripped']} schemas."]
    lines += ["", "## Every stripped parameter", "", "| server | tool | parameter(s) | role(s) |", "|---|---|---|---|"]
    for e in summary["flagged"]:
        lines.append(f"| {e['server']} | {e['tool']} | {', '.join(e['stripped'])} | {', '.join(e['roles'])} |")
    lines += ["", f"False flags (stripped on a task, support or filesystem server): {len(summary['false_flags'])}", "",
              "## Undefended harmful calls that sent a value in a stripped parameter", "",
              "| agent | harmful calls | via a stripped parameter |", "|---|---|---|"]
    for model, total in sorted(result["harm_total"].items()):
        lines.append(f"| {model} | {total} | {result['harm_via_stripped'].get(model, 0)} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--recorded", type=Path, default=ROOT / "results" / "improve" / "msb-replay" / "recorded")
    parser.add_argument("--data", type=Path, default=ROOT / "artifacts" / "data" / "MSB")
    parser.add_argument("--results", type=Path, default=ROOT / "results" / "msb")
    parser.add_argument("--out", type=Path, default=None, help="write the JSON result here too")
    args = parser.parse_args(argv)
    result = scan_traces(args.recorded, role_map(args.data))
    grid = {case["id"]: case for case in msb.cases(args.data)}
    result.update(harm_through_stripped(args.results, result.pop("catalogs"), grid))
    summary = summarize(result)
    print(report(result, summary), end="")
    if args.out:
        args.out.write_text(json.dumps({"result": result, "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
