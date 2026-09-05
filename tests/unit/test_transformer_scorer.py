from cerberus.behavioral.scorers.transformer import SequenceTransformerScorer


def test_sequence_transformer_scoring():
    scorer = SequenceTransformerScorer()

    normal_traces = [
        ["read_file", "write_file", "run_tests"],
        ["read_file", "read_file", "write_file"],
        ["read_file", "write_file", "run_tests"],
    ]
    scorer.fit(normal_traces)
    assert scorer.is_fitted

    # Test normal trace
    norm_score, _ = scorer.score(["read_file", "write_file", "run_tests"])
    assert norm_score < 0.50

    # Test anomalous exfiltration trace with unseen sequence
    anom_score, _ = scorer.score(["read_file", "unknown_tool", "http_post"])
    assert anom_score > norm_score
