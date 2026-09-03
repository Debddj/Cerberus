import pytest
import numpy as np

try:
    import sklearn
except ImportError:
    sklearn = None

from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.proxy.models import IsolationForestFeatures

def test_isolation_forest_anomaly():
    if sklearn is None:
        pytest.skip("scikit-learn is not installed in current environment")

    scorer = IsolationForestScorer()
    normal_data = np.random.normal(0.0, 1.0, size=(100, 8))
    scorer.fit(normal_data)
    assert scorer.is_fitted
    
    outlier_feat = IsolationForestFeatures(
        param_size_bytes_z=6.5,
        param_entropy_z=4.2,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=-1.2,
        session_duration_ms_z=2.0,
        sequence_position_z=1.0,
        destination_novelty=1.0,
        tool_novelty=1.0
    )
    score, factors = scorer.score(outlier_feat)
    assert score > 0.60
