from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest
from pydantic import ValidationError

from intentshield.models import Decision, ReasonCode, ToolCall
from intentshield.models import PolicyContext
from intentshield.policy import PolicyConfig
from intentshield.policy import PolicyEngine
from intentshield.service import IntentShieldService
from intentshield.storage import Storage
from intentshield.tools import SimulatedEmailTools, build_registry


@pytest.fixture
def service(tmp_path: Path) -> IntentShieldService:
    email = SimulatedEmailTools()
    registry = build_registry(email)
    config = PolicyConfig(
        allowed_tools=set(registry), allowed_resources={"inbox", "outbox"},
        allowed_destinations=["*@example.com"], call_budget=4,
        injection_block_threshold=0.75, minimum_intent_alignment=0.6,
        approval_ttl_seconds=60,
    )
    return IntentShieldService(Storage(tmp_path / "test.db"), config, registry, email)


def run(service: IntentShieldService, intent: str = "Read my inbox") -> str:
    return service.create_run(intent)


def test_benign_read_is_allowed_with_trusted_scores(service: IntentShieldService):
    result = service.evaluate_and_execute(run(service), "Read my inbox", service.scenario_call("benign"))
    assert result.decision is Decision.ALLOW
    assert result.executed is True
    assert result.reason_codes == [ReasonCode.ALLOW_POLICY_SATISFIED]
    assert result.injection_score < service.config.injection_block_threshold
    assert result.intent_alignment >= service.config.minimum_intent_alignment
    assert service.email_tools.execution_count == 1


def test_policy_consumes_security_agent_block_as_an_independent_veto(
    service: IntentShieldService,
):
    call = service.scenario_call("benign")
    outcome = service.policy.evaluate(PolicyContext(
        run_id="run-agent-veto",
        user_intent="Read my inbox",
        call=call,
        injection_score=0.1,
        intent_alignment=1.0,
        security_disposition="BLOCK",
    ))

    assert outcome.decision is Decision.BLOCK
    assert outcome.reason_codes == [ReasonCode.BLOCK_SECURITY_AGENTS]


def test_untrusted_call_cannot_forge_security_signals():
    with pytest.raises(ValidationError):
        ToolCall.model_validate({
            "tool_name": "read_inbox", "arguments": {},
            "injection_score": 0, "intent_alignment": 1,
        })


def test_injection_and_negated_intent_never_execute(service: IntentShieldService):
    attack = service.evaluate_and_execute(run(service), "Read my inbox", service.scenario_call("injection"))
    assert attack.reason_codes == [ReasonCode.BLOCK_INJECTION_DETECTED]
    negated = service.evaluate_and_execute(
        run(service, "Do not read my inbox"), "Do not read my inbox", service.scenario_call("benign")
    )
    assert negated.reason_codes == [ReasonCode.BLOCK_INTENT_MISMATCH]
    assert service.email_tools.execution_count == 0
    assert service.email_tools.outbox == []


def test_review_approval_is_bound_to_exact_call_and_key(service: IntentShieldService):
    run_id = run(service, "Send Alice a status email")
    call = service.scenario_call("review")
    review = service.evaluate_and_execute(run_id, "Send Alice a status email", call)
    assert review.decision is Decision.REVIEW
    assert review.approval_id
    assert service.storage.decide_approval(review.approval_id, "APPROVED")

    tampered = call.model_copy(deep=True)
    tampered.approval_id = review.approval_id
    tampered.idempotency_key = "different-key"
    denied = service.evaluate_and_execute(run_id, "Send Alice a status email", tampered)
    assert denied.reason_codes == [ReasonCode.BLOCK_APPROVAL_MISMATCH]
    schema_tampered = call.model_copy(update={
        "approval_id": review.approval_id,
        "schema_hash": "different-schema",
    })
    denied_schema = service.evaluate_and_execute(run_id, "Send Alice a status email", schema_tampered)
    assert denied_schema.reason_codes == [ReasonCode.BLOCK_APPROVAL_MISMATCH]
    assert service.email_tools.execution_count == 0


def test_approved_call_executes_once_and_approval_reuse_blocks(service: IntentShieldService):
    review = service.execute_scenario("Send Alice a status email", "review")
    approval = service.storage.get_approval(review.approval_id)
    approved = service.decide_approval(review.approval_id, True)
    assert approved.decision is Decision.ALLOW
    assert approved.executed is True
    assert service.storage.get_approval(review.approval_id)["status"] == "CONSUMED"
    assert service.storage.get_run(review.run_id)["call_count"] == 1
    assert len(service.email_tools.outbox) == 1

    replay_attempt = ToolCall.model_validate_json(approval["call_json"]).model_copy(
        update={"approval_id": review.approval_id}
    )
    denied = service.evaluate_and_execute(review.run_id, "Send Alice a status email", replay_attempt)
    assert denied.reason_codes == [ReasonCode.BLOCK_APPROVAL_CONSUMED]
    assert len(service.email_tools.outbox) == 1


def test_completed_idempotent_call_replays_only_after_fresh_approval(service: IntentShieldService):
    run_id = run(service, "Send Alice a status email")
    call = service.scenario_call("review")
    first_review = service.evaluate_and_execute(run_id, "ignored", call)
    first = service.decide_approval(first_review.approval_id, True)
    assert first.executed is True

    second_review = service.evaluate_and_execute(run_id, "ignored", call)
    assert second_review.decision is Decision.REVIEW
    replay = service.decide_approval(second_review.approval_id, True)
    assert replay.reason_codes == [ReasonCode.ALLOW_IDEMPOTENT_REPLAY]
    assert replay.replayed is True
    assert replay.executed is False
    assert len(service.email_tools.outbox) == 1

def test_expired_approval_cannot_execute(service: IntentShieldService):
    review = service.execute_scenario("Send Alice a status email", "review")
    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with service.storage.connect() as db:
        db.execute("UPDATE approvals SET expires_at=? WHERE id=?", (expired_at, review.approval_id))
    with pytest.raises(ValueError, match="expired"):
        service.decide_approval(review.approval_id, True)
    assert service.email_tools.execution_count == 0


def test_persisted_call_budget_allows_four_and_blocks_fifth(service: IntentShieldService):
    run_id = run(service)
    results = [
        service.evaluate_and_execute(run_id, "Read my inbox", service.scenario_call("benign"))
        for _ in range(5)
    ]
    assert [result.decision for result in results] == [
        Decision.ALLOW, Decision.ALLOW, Decision.ALLOW, Decision.ALLOW, Decision.BLOCK
    ]
    assert results[-1].reason_codes == [ReasonCode.BLOCK_CALL_BUDGET_EXCEEDED]
    assert service.storage.get_run(run_id)["call_count"] == 5
    assert service.email_tools.execution_count == 4


def test_schema_scope_and_prohibited_guards(service: IntentShieldService):
    read = service.scenario_call("benign")
    drift = read.model_copy(update={"schema_hash": "outdated"})
    assert service.evaluate_and_execute(run(service), "Read inbox", drift).reason_codes == [
        ReasonCode.BLOCK_SCHEMA_DRIFT
    ]

    send = service.scenario_call("review")
    outside = send.model_copy(deep=True)
    outside.arguments["to"] = "alice@outside.test"
    assert service.evaluate_and_execute(run(service, "Email Alice"), "Email Alice", outside).reason_codes == [
        ReasonCode.BLOCK_DESTINATION_OUT_OF_SCOPE
    ]

    service.config.prohibited_tools.add("read_inbox")
    assert service.evaluate_and_execute(run(service), "Read inbox", read).reason_codes == [
        ReasonCode.BLOCK_TOOL_PROHIBITED
    ]
    assert service.email_tools.execution_count == 0


def test_destination_scope_requires_explicit_nonempty_scalar(service: IntentShieldService):
    send = service.scenario_call("review")
    for invalid in (None, "", "   ", ["alice@example.com"]):
        call = send.model_copy(deep=True)
        if invalid is None:
            call.arguments.pop("to")
        else:
            call.arguments["to"] = invalid
        result = service.evaluate_and_execute(
            run(service, "Email Alice"), "Email Alice", call
        )
        assert result.reason_codes == [ReasonCode.BLOCK_DESTINATION_OUT_OF_SCOPE]

    service.config.allowed_destinations = ["*"]
    missing = send.model_copy(deep=True)
    missing.arguments.pop("to")
    assert service.evaluate_and_execute(
        run(service, "Email Alice"), "Email Alice", missing
    ).reason_codes == [ReasonCode.BLOCK_DESTINATION_OUT_OF_SCOPE]


def test_idempotency_changed_fingerprint_conflicts(service: IntentShieldService):
    review = service.execute_scenario("Send Alice", "review")
    approval = service.storage.get_approval(review.approval_id)
    original_call = ToolCall.model_validate_json(approval["call_json"])
    service.decide_approval(review.approval_id, True)

    changed = ToolCall(
        tool_name="send_email", schema_hash=service.registry["send_email"].schema_hash,
        arguments={"resource": "outbox", "to": "bob@example.com", "subject": "Other", "body": "Other"},
        idempotency_key=original_call.idempotency_key,
    )
    denied = service.evaluate_and_execute(run(service, "Send Bob"), "Send Bob", changed)
    assert denied.reason_codes == [ReasonCode.BLOCK_IDEMPOTENCY_CONFLICT]
    assert len(service.email_tools.outbox) == 1


def test_idempotency_reservation_has_single_winner(service: IntentShieldService):
    run_id = run(service)
    with ThreadPoolExecutor(max_workers=6) as pool:
        states = list(pool.map(
            lambda _: service.storage.reserve_idempotency("same-key", "same-fingerprint", run_id),
            range(6),
        ))
    labels = [state for state, _ in states]
    assert labels.count("RESERVED") == 1
    assert labels.count("IN_PROGRESS") == 5


def test_uncertain_mutation_is_never_retried_automatically(service: IntentShieldService):
    side_effects: list[str] = []

    def timeout_after_side_effect(_parsed):
        side_effects.append("sent")
        raise TimeoutError("provider timed out after accepting the message")

    service.registry["send_email"] = replace(
        service.registry["send_email"], executor=timeout_after_side_effect
    )
    service.policy = PolicyEngine(service.config, service.registry)
    run_id = run(service, "Send Alice a status email")
    call = service.scenario_call("review")

    first_review = service.evaluate_and_execute(run_id, "ignored", call)
    first_attempt = service.decide_approval(first_review.approval_id, True)
    assert first_attempt.reason_codes == [ReasonCode.BLOCK_EXECUTION_IN_DOUBT]
    assert side_effects == ["sent"]

    second_review = service.evaluate_and_execute(run_id, "ignored", call)
    assert second_review.decision is Decision.REVIEW
    second_attempt = service.decide_approval(second_review.approval_id, True)
    assert second_attempt.reason_codes == [ReasonCode.BLOCK_EXECUTION_IN_DOUBT]
    assert side_effects == ["sent"]

    with service.storage.connect() as db:
        reservation = db.execute(
            "SELECT status,error_json FROM idempotency_reservations WHERE idempotency_key=?",
            (call.idempotency_key,),
        ).fetchone()
    assert reservation["status"] == "IN_DOUBT"
    assert "TimeoutError" in reservation["error_json"]
    assert service.storage.get_run(run_id)["status"] == "BLOCK"


def test_concurrent_events_and_approval_decision_are_atomic(service: IntentShieldService):
    run_id = run(service)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda index: service.storage.add_event(run_id, "CONCURRENT", {"index": index}),
            range(40),
        ))
    events = service.storage.list_events(run_id)
    sequences = [event["sequence"] for event in events]
    assert sequences == list(range(1, 42))

    review = service.execute_scenario("Send Alice", "review")
    approval = service.storage.get_approval(review.approval_id)
    payload = {"approval_id": review.approval_id, "status": "APPROVED"}
    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = list(pool.map(
            lambda _: service.storage.decide_approval_with_event(
                review.approval_id, "APPROVED", approval["run_id"], payload
            ),
            range(8),
        ))
    assert winners.count(True) == 1
    audit = service.storage.list_events(approval["run_id"])
    assert sum(event["kind"] == "APPROVAL_DECIDED" for event in audit) == 1
    assert [event["sequence"] for event in audit] == list(range(1, len(audit) + 1))


def test_concurrent_distinct_approvals_both_become_terminal(service: IntentShieldService):
    for trial in range(5):
        entered = Event()
        release = Event()
        side_effects: list[int] = []

        def controlled_executor(parsed):
            side_effects.append(trial)
            entered.set()
            assert release.wait(timeout=2)
            return {"message_id": f"race-{trial}", "status": "sent"}

        service.registry["send_email"] = replace(
            service.registry["send_email"], executor=controlled_executor
        )
        service.policy = PolicyEngine(service.config, service.registry)
        run_id = run(service, "Send Alice a status email")
        call = service.scenario_call("review")
        first_review = service.evaluate_and_execute(run_id, "ignored", call)
        second_review = service.evaluate_and_execute(run_id, "ignored", call)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(service.decide_approval, first_review.approval_id, True)
            assert entered.wait(timeout=2)
            second_future = pool.submit(service.decide_approval, second_review.approval_id, True)
            second_result = second_future.result(timeout=2)
            release.set()
            first_result = first_future.result(timeout=2)

        assert first_result.executed is True
        assert second_result.reason_codes == [ReasonCode.BLOCK_IDEMPOTENCY_IN_PROGRESS]
        assert side_effects == [trial]
        statuses = {
            service.storage.get_approval(first_review.approval_id)["status"],
            service.storage.get_approval(second_review.approval_id)["status"],
        }
        assert statuses == {"CONSUMED"}


def test_rejection_sets_final_block_status_and_metrics_are_current(service: IntentShieldService):
    service.execute_scenario("Read inbox", "benign")
    review = service.execute_scenario("Send Alice", "review")
    rejected = service.decide_approval(review.approval_id, False)
    service.execute_scenario("Read inbox", "injection")

    assert rejected.reason_codes == [ReasonCode.BLOCK_APPROVAL_REJECTED]
    assert service.storage.get_run(review.run_id)["status"] == "BLOCK"
    metrics = service.storage.metrics()
    assert metrics["runs"] == 3
    assert sum(metrics["decisions"].values()) <= metrics["runs"]
    assert metrics["decisions"] == {"ALLOW": 1, "REVIEW": 0, "BLOCK": 2}


def test_runs_and_events_persist_across_storage_instances(service: IntentShieldService):
    result = service.execute_scenario("Read inbox", "benign")
    reopened = Storage(service.storage.path)
    assert reopened.get_run(result.run_id)["status"] == "ALLOW"
    assert [event["kind"] for event in reopened.list_events(result.run_id)] == [
        "RUN_CREATED", "TOOL_CALL_PROPOSED", "POLICY_DECISION", "TOOL_EXECUTED"
    ]


def test_existing_database_schema_is_migrated(tmp_path: Path):
    import sqlite3

    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE runs (id TEXT PRIMARY KEY,user_intent TEXT NOT NULL,scenario TEXT,status TEXT NOT NULL,created_at TEXT NOT NULL,completed_at TEXT)"
        )
    migrated = Storage(path)
    with migrated.connect() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(runs)")}
    assert "call_count" in columns


def test_policy_config_rejects_typos_overlaps_and_catch_all_destinations():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PolicyConfig(call_budjet=3)
    with pytest.raises(ValidationError, match="allowed and prohibited"):
        PolicyConfig(allowed_tools={"send_email"}, prohibited_tools={"send_email"})
    with pytest.raises(ValidationError, match="catch-all"):
        PolicyConfig(allowed_destinations=["*"])
    PolicyConfig(allowed_destinations=["*@example.com"])
