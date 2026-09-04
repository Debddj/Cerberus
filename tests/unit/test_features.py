from cerberus.behavioral.features import FeatureExtractor, shannon_entropy
from cerberus.proxy.models import ToolCallEvent


def test_entropy_computation():
    assert shannon_entropy(b"") == 0.0
    low_ent = shannon_entropy(b"aaaaaaaaaaaa")
    high_ent = shannon_entropy(b"a8f934x!9128zL")
    assert high_ent > low_ent


def test_feature_segregation():
    event = ToolCallEvent(
        session_id="s1",
        agent_id="a1",
        tool_name="read_file",
        tool_server="file-server",
        parameters={"test": "val"},
    )
    markov, if_feat, _rule = FeatureExtractor.extract_all(event, ["prev_t"], 5, 0, {})
    assert markov.tool_name == "read_file"
    assert markov.prev_tool_1 == "prev_t"
    assert hasattr(if_feat, "param_entropy_z")
    assert hasattr(if_feat, "destination_novelty")
