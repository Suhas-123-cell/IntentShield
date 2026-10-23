"""The documented real-world incidents in benchmarks/real_incidents.py stay caught by the guard."""
from __future__ import annotations

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "real_incidents", Path(__file__).resolve().parent.parent / "benchmarks" / "real_incidents.py")
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)


def test_whatsapp_description_poisoning_quarantines_the_tool():
    quar = ri.catalog_quarantine(ri.WHATSAPP)
    assert "facts:get_fact_of_the_day" in quar
    assert {"hidden_directive", "concealment"} <= set(quar["facts:get_fact_of_the_day"])


def test_sharelock_split_quarantines_both_tools():
    quar = ri.catalog_quarantine(ri.SHARELOCK)
    assert set(quar) == {"notes:read_note", "notes:format_note"}
    assert all("split_external_send" in v for v in quar.values())


def test_github_injected_output_is_flagged():
    assert "instruction_override" in ri.scan_output(ri.GITHUB_OUTPUT)


def test_postmark_implementation_backdoor_is_not_visible_to_structural_scans():
    # Honest limitation: nothing in the tool's agent-visible text is malicious.
    clean = {k: v for k, v in ri.POSTMARK.items() if not k.startswith("_")}
    assert ri.catalog_quarantine([clean]) == {}
    # But the real outgoing call carries a recipient the user never named.
    call = ri.POSTMARK["_actual_call"]["arguments"]
    undeclared = ri.authority_values(call) - ri.authority_values({"to": "user@example.com"}) - {"receipt"}
    assert ri.ATTACKER_EMAIL in undeclared
