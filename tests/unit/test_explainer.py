from cerberus.behavioral.explainer import ScoreExplainer


def test_score_explainer():
    text = ScoreExplainer.explain(0.85, ["Rare transition", "Entropy spike"], True)
    assert "Risk Score 0.85" in text
    assert "WARM" in text
    assert "Entropy spike" in text
