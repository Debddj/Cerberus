from unittest.mock import AsyncMock

import pytest

from cerberus.config import settings
from cerberus.proxy.models import EventDecision
from cerberus.proxy.server import CerberusProxyEngine


@pytest.mark.asyncio
async def test_session_contamination_quarantine(tmp_path, monkeypatch):
    # Complete test isolation: prevent reading or writing global workspace audit files
    test_log = str(tmp_path / "test_audit.jsonl")
    test_baselines = str(tmp_path / "baselines")
    test_pins = str(tmp_path / "pins.db")
    monkeypatch.setattr(settings, "log_path", test_log)
    monkeypatch.setattr(settings, "encrypt_logs", False)
    monkeypatch.setattr(settings, "log_encryption_key", "")
    monkeypatch.setattr(settings, "baselines_dir", test_baselines)
    monkeypatch.setattr(settings, "pins_db_path", test_pins)

    engine = CerberusProxyEngine()

    session_id = "session-tainted-1"
    agent_id = "agent-secure"

    # Call 1: Normal benign tool call (ALLOW)
    event1, _ = await engine.process_tool_call(
        session_id=session_id,
        agent_id=agent_id,
        tool_name="read_file",
        tool_server="fs",
        parameters={"path": "main.py"},
    )
    assert event1.decision == EventDecision.ALLOW
    assert session_id not in engine.contaminated_sessions
    assert len(engine.agent_allowed_events[agent_id]) == 1
    assert len(engine.agent_if_buffers[agent_id]) == 1
    assert len(engine.running_scaler.buffers["param_size"]) == 1
    assert engine.transformer_training_sequences.get(session_id) == ["read_file"]

    # Call 2: Flagged call (EventDecision.FLAG)
    original_enforce = engine.enforcer.enforce
    engine.enforcer.enforce = AsyncMock(return_value=EventDecision.FLAG)

    event2, _ = await engine.process_tool_call(
        session_id=session_id,
        agent_id=agent_id,
        tool_name="suspicious_probe",
        tool_server="fs",
        parameters={"cmd": "whoami"},
    )
    assert event2.decision == EventDecision.FLAG
    # Verify session is marked contaminated
    assert session_id in engine.contaminated_sessions
    # Verify flagged call is NOT appended to agent_allowed_events or agent_if_buffers
    assert len(engine.agent_allowed_events[agent_id]) == 1
    assert len(engine.agent_if_buffers[agent_id]) == 1
    # Verify running scaler was NOT updated with flagged call parameters
    assert len(engine.running_scaler.buffers["param_size"]) == 1
    # Verify Markov transition was NOT recorded for this call
    assert "suspicious_probe" not in engine.markov_scorer.transitions.get("read_file", {})
    # Verify session sequence was purged from transformer_training_sequences
    assert session_id not in engine.transformer_training_sequences

    # Call 3: Subsequent call in the contaminated session (even with ALLOW decision)
    engine.enforcer.enforce = AsyncMock(return_value=EventDecision.ALLOW)
    event3, _ = await engine.process_tool_call(
        session_id=session_id,
        agent_id=agent_id,
        tool_name="write_file",
        tool_server="fs",
        parameters={"path": "output.txt"},
    )
    assert event3.decision == EventDecision.ALLOW
    # Despite ALLOW decision, contaminated session quarantine prevents state updates:
    assert len(engine.agent_allowed_events[agent_id]) == 1
    assert len(engine.agent_if_buffers[agent_id]) == 1
    # Verify running scaler was NOT updated from contaminated session
    assert len(engine.running_scaler.buffers["param_size"]) == 1
    assert "write_file" not in engine.markov_scorer.transitions.get("suspicious_probe", {})
    assert session_id not in engine.transformer_training_sequences

    # Call 4: Another session (clean) should not be affected
    clean_session = "session-clean-2"
    event4, _ = await engine.process_tool_call(
        session_id=clean_session,
        agent_id=agent_id,
        tool_name="read_file",
        tool_server="fs",
        parameters={"path": "safe.py"},
    )
    assert event4.decision == EventDecision.ALLOW
    assert clean_session not in engine.contaminated_sessions
    assert clean_session in engine.transformer_training_sequences
    assert len(engine.agent_allowed_events[agent_id]) == 2
    assert len(engine.agent_if_buffers[agent_id]) == 2
    # Clean session ALLOW updates running scaler
    assert len(engine.running_scaler.buffers["param_size"]) == 2

    # Clean up
    engine.enforcer.enforce = original_enforce
