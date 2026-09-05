from cerberus.scanner.scope_analyzer import ScopeAnalyzer


def test_scope_analyzer_learn_mode():
    analyzer = ScopeAnalyzer(mode="learn")

    # Undeclared agent is allowed but not enforced
    verdict = analyzer.check_scope("agent-new", "any_tool")
    assert verdict.allowed is True
    assert verdict.enforced is False
    assert "Learn mode" in verdict.reason

    # Register scope
    analyzer.register_scope("agent-1", {"read_file", "list_dir"}, enforced=False)
    v_in = analyzer.check_scope("agent-1", "read_file")
    assert v_in.allowed is True
    assert v_in.enforced is False

    v_out = analyzer.check_scope("agent-1", "http_post")
    assert v_out.allowed is True
    assert v_out.enforced is False


def test_scope_analyzer_strict_mode():
    analyzer = ScopeAnalyzer(mode="strict")

    # Undeclared agent blocked in strict mode
    verdict = analyzer.check_scope("agent-new", "any_tool")
    assert verdict.allowed is False
    assert verdict.enforced is True
    assert "Strict mode" in verdict.reason


def test_scope_analyzer_promotion():
    analyzer = ScopeAnalyzer(mode="learn")
    analyzer.register_scope("agent-1", {"read_file"}, enforced=False)

    v_before = analyzer.check_scope("agent-1", "http_post")
    assert v_before.allowed is True

    # Promote to enforced after baseline warm + policy approval
    analyzer.promote_to_enforced("agent-1")
    v_after = analyzer.check_scope("agent-1", "http_post")
    assert v_after.allowed is False
    assert v_after.enforced is True
