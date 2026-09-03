from sandbox.traffic.attacks.cold_start_attack import get_cold_start_event
from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from cerberus.behavioral.features import FeatureExtractor

def test_e2e_cold_start_defense():
    event = get_cold_start_event()
    _, _, rule_f = FeatureExtractor.extract_all(event, [], 0, 0, {})
    score, _ = RuleBasedScorer.score(rule_f)
    assert score >= 0.80 # Pre-baseline heuristics catch novel destination egress
