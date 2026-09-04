import numpy as np
import pytest

try:
    import sklearn
except ImportError:
    sklearn = None

from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.proxy.models import IsolationForestFeatures


def test_isolation_forest_anomaly():
    if sklearn is None:
        pytest.skip("scikit-learn is not installed in current environment")

    rng = np.random.default_rng(42)
    scorer = IsolationForestScorer()
    normal_data = rng.normal(0.0, 1.0, size=(100, 8))
    scorer.fit(normal_data)
    assert scorer.is_fitted

    normal_feat = IsolationForestFeatures(
        param_size_bytes_z=0.0,
        param_entropy_z=0.0,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=0.0,
        session_duration_ms_z=0.0,
        sequence_position_z=0.0,
        destination_novelty=0.0,
        tool_novelty=0.0,
    )
    normal_score, _ = scorer.score(normal_feat)

    outlier_feat = IsolationForestFeatures(
        param_size_bytes_z=6.5,
        param_entropy_z=4.2,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=-1.2,
        session_duration_ms_z=2.0,
        sequence_position_z=1.0,
        destination_novelty=1.0,
        tool_novelty=1.0,
    )
    outlier_score, _factors = scorer.score(outlier_feat)
    assert outlier_score > 0.50
    assert outlier_score > normal_score
