from intentshield.detector import compute_security_signals
from intentshield.models import ToolCall


def alignment(intent: str, tool: str) -> float:
    call = ToolCall(tool_name=tool, arguments={}, schema_hash="x" * 64)
    return compute_security_signals(intent, call).intent_alignment


def test_camel_case_tool_names_are_tokenized():
    assert alignment("Show me the details of the GitHub user octocat", "GitHubGetUserDetails") >= 0.8


def test_camel_case_mutation_still_rejects_read_only_intent():
    assert alignment("Show me my recent emails", "GmailSendEmail") < 0.6


def test_negation_still_blocks_camel_case_tools():
    assert alignment("Do not send any email", "GmailSendEmail") < 0.1
