import sys

from cerberus.behavioral.scorers.transformer import SequenceTransformerScorer


def test_transformer_numpy_next_token_prediction():
    # 1. Verify zero PyTorch dependency
    assert "torch" not in sys.modules

    scorer = SequenceTransformerScorer(embedding_dim=16, hidden_dim=32)
    assert not scorer.is_fitted

    # Verify score on empty or short sequence returns neutral 0.0
    score, factors = scorer.score(["read_file"])
    assert score == 0.0
    assert factors == []

    # 2. Fit on canonical tool sequences
    sequences = [
        ["read_file", "write_file", "test_runner"],
        ["read_file", "write_file", "test_runner"],
        ["read_file", "write_file", "test_runner"],
        ["read_file", "write_file", "git_commit"],
    ]
    scorer.fit(sequences, epochs=25)
    assert scorer.is_fitted
    assert "read_file" in scorer.vocab
    assert "write_file" in scorer.vocab

    # 3. Score a normal learned transition sequence
    normal_seq = ["read_file", "write_file", "test_runner"]
    normal_score, _normal_factors = scorer.score(normal_seq)
    # Expected: low anomaly score on learned sequences
    assert normal_score < 0.50

    # 4. Score an abnormal sequence containing unseen transitions and novel tools
    anomalous_seq = ["read_file", "network_exfil", "drop_database"]
    anom_score, anom_factors = scorer.score(anomalous_seq)
    # Expected: elevated score (> 0.65) and factor reported
    assert anom_score > normal_score
    assert anom_score >= 0.65
    assert len(anom_factors) > 0
    assert "Neural Sequence Anomaly" in anom_factors[0]

    # Verify torch was still never imported
    assert "torch" not in sys.modules
