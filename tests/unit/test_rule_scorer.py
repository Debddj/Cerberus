from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from cerberus.proxy.models import RuleFeatures


def test_rule_based_exfiltration_pattern():
    features = RuleFeatures(
        tool_name="http_post",
        param_size_bytes=15000,
        param_entropy=7.2,
        response_size_bytes=0,
        time_since_previous_ms=50,
        sequence_position=2,
        destination_novelty=0.95,
        tool_novelty=0.9,
        destination_domain="evil.com",
        prev_tools=["read_file"],
    )
    score, factors = RuleBasedScorer.score(features)
    assert score >= 0.90
    assert len(factors) >= 1
