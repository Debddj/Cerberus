from cerberus.policy.synthesizer import PolicySynthesizer


def test_synthesize_rego():
    rego = PolicySynthesizer.synthesize_rego("coding-01", {"read_file", "write_file"}, "2026-09-03")
    assert "package cerberus.agent.coding_01" in rego
    assert '"read_file"' in rego
    assert '"write_file"' in rego
