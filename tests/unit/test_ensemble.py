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


def test_ensemble_4_scorer_combination():
    ensemble = EnsembleScorer(w_rule=0.2, w_markov=0.2, w_isolation=0.3, w_transformer=0.3)
    score, factors = ensemble.combine(
        rule_score=0.2,
        markov_score=0.3,
        isolation_score=0.4,
        transformer_score=0.5,
        rule_factors=["rule_factor"],
        markov_factors=["markov_factor"],
        isolation_factors=["iso_factor"],
        transformer_factors=["trans_factor"],
    )
    # 0.2*0.2 + 0.2*0.3 + 0.3*0.4 + 0.3*0.5 = 0.04 + 0.06 + 0.12 + 0.15 = 0.37
    assert 0.35 <= score <= 0.40
    assert len(factors) == 4
