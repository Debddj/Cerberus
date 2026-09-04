from cerberus.behavioral.scorers.markov import MarkovScorer
from cerberus.proxy.models import MarkovFeatures


def test_markov_transition_scoring():
    scorer = MarkovScorer()
    for _ in range(50):
        scorer.update("read_file", "write_file")

    # Normal transition -> low surprise
    feat_norm = MarkovFeatures(tool_name="write_file", server_name="srv", prev_tool_1="read_file")
    score_norm, _ = scorer.score(feat_norm)

    # Rare transition -> high surprise
    feat_rare = MarkovFeatures(tool_name="http_post", server_name="srv", prev_tool_1="read_file")
    score_rare, _factors = scorer.score(feat_rare)

    assert score_rare > score_norm
    assert 0.0 <= score_rare <= 1.0
