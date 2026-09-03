import numpy as np
try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None

from cerberus.proxy.models import IsolationForestFeatures

class IsolationForestScorer:
    """Detects multi-dimensional numeric/continuous anomalies on z-scaled features."""
    
    def __init__(self):
        if IsolationForest is not None:
            self.model = IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=42
            )
        else:
            self.model = None
        self.is_fitted = False

    def fit(self, X: np.ndarray):
        if self.model is not None and len(X) >= 20:
            self.model.fit(X)
            self.is_fitted = True

    def score(self, features: IsolationForestFeatures) -> tuple[float, list[str]]:
        if not self.is_fitted or self.model is None:
            # Baseline not warm yet or sklearn absent: return neutral score
            return 0.0, []
            
        vec = np.array([[
            features.param_size_bytes_z,
            features.param_entropy_z,
            features.response_size_bytes_z,
            features.time_since_previous_ms_z,
            features.session_duration_ms_z,
            features.sequence_position_z,
            features.destination_novelty,
            features.tool_novelty
        ]])
        
        raw_score = self.model.decision_function(vec)[0]
        normalized_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
        
        factors = []
        if normalized_score > 0.70:
            factors.append(
                "Multivariate feature anomaly: Vector is an outlier across payload entropy, size, and novelty"
            )
        return normalized_score, factors
