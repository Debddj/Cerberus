class EnsembleScorer:
    """Combines Rule-Based, Markov, and Isolation Forest scores into a final decision metric."""

    def __init__(self, w_rule: float = 0.3, w_markov: float = 0.3, w_isolation: float = 0.4):
        self.w_rule = w_rule
        self.w_markov = w_markov
        self.w_isolation = w_isolation

    def combine(
        self,
        rule_score: float,
        markov_score: float,
        isolation_score: float,
        rule_factors: list[str],
        markov_factors: list[str],
        isolation_factors: list[str],
    ) -> tuple[float, list[str]]:

        all_factors = rule_factors + markov_factors + isolation_factors

        # High threat circuit breaker: If any single engine detects extreme threat, escalate
        if rule_score >= 0.90 or markov_score >= 0.90 or isolation_score >= 0.90:
            final_score = max(rule_score, markov_score, isolation_score)
            all_factors.append("Circuit Breaker: High-confidence anomaly from individual engine")
            return final_score, all_factors

        weighted = (
            self.w_rule * rule_score
            + self.w_markov * markov_score
            + self.w_isolation * isolation_score
        )
        return round(min(1.0, max(0.0, weighted)), 3), all_factors
