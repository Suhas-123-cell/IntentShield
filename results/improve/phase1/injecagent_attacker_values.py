"""Phase 1: does InjecAgent's attacker instruction itself name a value provenance can trace?
(injection_eval --provenance scores the whole tool response, which also holds the user's own data.)"""
import collections, json
from pathlib import Path
from intentshield.mcp_inspect import authority_values, scan_output

data = Path("artifacts/data/InjecAgent/data")
for setting in ("dh_base", "ds_base"):
    seen, c = set(), collections.Counter()
    for case in json.loads((data / f"test_cases_{setting}.json").read_text()):
        if case["Tool Response"] in seen:
            continue
        seen.add(case["Tool Response"])
        attacker = authority_values(case["Attacker Instruction"])
        missed = not scan_output(case["Tool Response"])
        c["rows"] += 1; c["rules_missed"] += missed
        c["missed_attacker_value_traceable"] += missed and bool(attacker)
        c["missed_no_attacker_value"] += missed and not attacker
    print(setting, dict(c))
