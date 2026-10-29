from pathlib import Path

from intentshield.models import ToolCall
from intentshield.service import IntentShieldService


def test_an_unregistered_tool_gets_fail_closed_signals_and_no_assessment(tmp_path: Path):
    service = IntentShieldService.default(tmp_path / "signals.db")
    call = ToolCall(tool_name="nope:unknown", arguments={"to": "x@example.com"}, schema_hash="x" * 64)
    signals, assessment = service._security_assessment("Send the report", call)
    assert assessment is None
    assert (signals.injection_score, signals.intent_alignment, signals.risk_score) == (1.0, 0.0, 1.0)
