from cerberus.narrative.reconstructor import NarrativeReconstructor
from cerberus.proxy.models import ToolCallEvent


def test_narrative_reconstruction():
    events = [
        ToolCallEvent(
            session_id="s1", agent_id="a1", tool_name="read_file", tool_server="srv", risk_score=0.1
        ),
        ToolCallEvent(
            session_id="s1",
            agent_id="a1",
            tool_name="http_post",
            tool_server="srv",
            destination_domain="bad.com",
            risk_score=0.95,
        ),
    ]
    narrative = NarrativeReconstructor.reconstruct(events)
    assert "RECONNAISSANCE" in narrative
    assert "EXFILTRATION" in narrative
