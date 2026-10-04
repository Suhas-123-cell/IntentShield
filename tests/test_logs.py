import json
import logging

from intentshield.logs import JsonFormatter


def test_json_formatter_includes_extra_fields_and_valid_json():
    record = logging.LogRecord("intentshield.x", logging.INFO, __file__, 1, "policy decision", (), None)
    record.run_id = "run-1"
    record.decision = "BLOCK"
    line = JsonFormatter().format(record)
    entry = json.loads(line)
    assert entry["msg"] == "policy decision"
    assert entry["run_id"] == "run-1" and entry["decision"] == "BLOCK"
    assert entry["level"] == "INFO" and "ts" in entry


def test_decisions_are_logged_without_arguments(tmp_path, caplog):
    from intentshield.policy import PolicyConfig
    from intentshield.service import IntentShieldService
    from intentshield.storage import Storage

    service = IntentShieldService(
        Storage(tmp_path / "log.db"),
        PolicyConfig(allowed_tools={"read_inbox"}, allowed_resources={"inbox"}),
    )
    with caplog.at_level(logging.INFO, logger="intentshield.service"):
        service.execute_scenario("Read my two most recent inbox messages", "benign")
    records = [r for r in caplog.records if r.getMessage() == "policy decision"]
    assert records and records[0].decision in {"ALLOW", "REVIEW", "BLOCK"}
    assert not hasattr(records[0], "arguments")
