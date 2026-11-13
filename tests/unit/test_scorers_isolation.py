import numpy as np

from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.proxy.models import IsolationForestFeatures


def test_isolation_scorer_fitting_and_scoring():
    scorer = IsolationForestScorer()
    assert not scorer.is_fitted

    dummy_features = IsolationForestFeatures(
        param_size_bytes_z=0.0,
        param_entropy_z=0.0,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=0.0,
        session_duration_ms_z=0.0,
        sequence_position_z=0.0,
        destination_novelty=0.0,
        tool_novelty=0.0,
    )

    # 1. Unfitted scorer returns neutral 0.0 score and no factors
    score, factors = scorer.score(dummy_features)
    assert score == 0.0
    assert factors == []

    # 2. Fit on 30 normal baseline vectors around 0.0
    rng = np.random.default_rng(42)
    normal_vectors = rng.normal(loc=0.0, scale=0.5, size=(30, 8))
    scorer.fit(normal_vectors)
    assert scorer.is_fitted

    # 3. Score a normal feature vector
    normal_feat = IsolationForestFeatures(
        param_size_bytes_z=0.1,
        param_entropy_z=-0.1,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=0.2,
        session_duration_ms_z=0.1,
        sequence_position_z=0.1,
        destination_novelty=0.0,
        tool_novelty=0.0,
    )
    n_score, n_factors = scorer.score(normal_feat)
    assert n_score < 0.60
    assert n_factors == []

    # 4. Score an extreme multivariate anomalous vector
    anom_feat = IsolationForestFeatures(
        param_size_bytes_z=4.5,
        param_entropy_z=4.8,
        response_size_bytes_z=4.0,
        time_since_previous_ms_z=4.5,
        session_duration_ms_z=4.9,
        sequence_position_z=4.9,
        destination_novelty=1.0,
        tool_novelty=1.0,
    )
    a_score, a_factors = scorer.score(anom_feat)
    assert a_score > n_score
    assert a_score >= 0.70
    assert len(a_factors) > 0
    assert "Multivariate feature anomaly" in a_factors[0]
