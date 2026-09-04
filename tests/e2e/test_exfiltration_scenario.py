from cerberus.behavioral.features import FeatureExtractor
from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from sandbox.traffic.attacks.injection_exfil import get_toxic_flow_sequence


def test_e2e_toxic_flow():
    events = get_toxic_flow_sequence()
    # 3rd event is http_post after reading private repo
    exfil = events[2]
    _, _, rule_f = FeatureExtractor.extract_all(exfil, ["read_private_repo"], 1, 0, {})
    score, _ = RuleBasedScorer.score(rule_f)
    assert score >= 0.90
