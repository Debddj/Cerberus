from cerberus.behavioral.scorers.markov import MarkovScorer
from cerberus.proxy.models import MarkovFeatures
from sandbox.traffic.attacks.markov_mimicry import get_mimicry_sequence


def test_e2e_markov_mimicry():
    _seq = get_mimicry_sequence()
    scorer = MarkovScorer()
    scorer.update("read_file", "write_file")

    # The structure itself will look normal to Markov
    feat = MarkovFeatures(tool_name="write_file", server_name="srv", prev_tool_1="read_file")
    score, _ = scorer.score(feat)
    assert score < 0.50  # Mimicry succeeds against structure, requires continuous/content layer
