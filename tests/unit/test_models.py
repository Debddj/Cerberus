from cerberus.proxy.models import EventDecision, ToolCallEvent


def test_event_decision_enum_values():
    """Verify that EventDecision includes all required policy decision outcomes."""
    assert EventDecision.ALLOW.value == "allow"
    assert EventDecision.FLAG.value == "flag"
    assert EventDecision.CHALLENGE.value == "challenge"
    assert EventDecision.BLOCK.value == "block"
    assert EventDecision.QUARANTINE.value == "quarantine"


def test_event_decision_challenge_resolution():
    """Verify CHALLENGE decision can be constructed from string and compared."""
    decision = EventDecision("challenge")
    assert decision == EventDecision.CHALLENGE
    assert decision.value == "challenge"


def test_tool_call_event_defaults():
    """Verify ToolCallEvent initializes with correct defaults and fields."""
    event = ToolCallEvent(
        session_id="sess-01",
        agent_id="agent-01",
        tool_name="read_file",
        tool_server="fs",
    )
    assert event.session_id == "sess-01"
    assert event.agent_id == "agent-01"
    assert event.tool_name == "read_file"
    assert event.tool_server == "fs"
    assert event.trust_level == "unverified"
    assert event.risk_score is None
    assert event.risk_factors == []


def test_tool_call_event_challenge_serialization():
    """Verify ToolCallEvent with CHALLENGE decision serializes and deserializes cleanly."""
    event = ToolCallEvent(
        session_id="s-test",
        agent_id="a-test",
        tool_name="sensitive_exec",
        tool_server="sys",
        decision=EventDecision.CHALLENGE,
        decision_reason="Requires operator challenge resolution",
    )
    data = event.model_dump()
    assert data["decision"] == "challenge"
    restored = ToolCallEvent.model_validate(data)
    assert restored.decision == EventDecision.CHALLENGE
    assert restored.decision_reason == "Requires operator challenge resolution"
