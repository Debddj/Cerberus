from cerberus.scanner.scope_analyzer import ScopeAnalyzer
from sandbox.traffic.attacks.privilege_escalation import get_privilege_escalation_event


def test_e2e_privilege_escalation():
    event = get_privilege_escalation_event()
    allowed = {"read_ticket", "send_email"}
    assert not ScopeAnalyzer.is_in_scope(event.tool_name, allowed)
