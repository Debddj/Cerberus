from cerberus.behavioral.ensemble import EnsembleScorer

def test_ensemble_combination():
    ensemble = EnsembleScorer()
    score, _ = ensemble.combine(0.2, 0.3, 0.4, [], [], [])
    assert 0.25 <= score <= 0.35

def test_circuit_breaker():
    ensemble = EnsembleScorer()
    score, factors = ensemble.combine(0.95, 0.1, 0.1, ["High threat"], [], [])
    assert score >= 0.90
    assert any("Circuit Breaker" in f for f in factors)
