from intentshield.models import Decision, PolicyContext, ToolCall
from intentshield.policy import PolicyConfig, PolicyEngine
from intentshield.tools import build_registry

REGISTRY = build_registry()


def evaluate(tool: str, args: dict, alignment: float, lenient: bool) -> Decision:
    spec = REGISTRY[tool]
    config = PolicyConfig(
        allowed_tools=set(REGISTRY), allowed_resources={"inbox", "outbox"},
        allowed_destinations=["*@example.com"], lenient_reads=lenient,
    )
    call = ToolCall(tool_name=tool, arguments=args, schema_hash=spec.schema_hash,
                    idempotency_key="k" if spec.mutation else None)
    return PolicyEngine(config, REGISTRY).evaluate(PolicyContext(
        run_id="r", user_intent="pay my bill", call=call,
        injection_score=0.02, intent_alignment=alignment,
    )).decision


READ = ("read_inbox", {"resource": "inbox", "limit": 2})
SEND = ("send_email", {"resource": "outbox", "to": "a@example.com", "subject": "s", "body": "b"})


def test_ungrounded_read_is_blocked_by_default_and_allowed_when_lenient():
    assert evaluate(*READ, alignment=0.3, lenient=False) is Decision.BLOCK
    assert evaluate(*READ, alignment=0.3, lenient=True) is Decision.ALLOW


def test_lenient_reads_never_relaxes_mutations_or_negation():
    assert evaluate(*SEND, alignment=0.3, lenient=True) is Decision.BLOCK
    assert evaluate(*READ, alignment=0.0, lenient=True) is Decision.BLOCK
