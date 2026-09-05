from typing import Any


class EnsembleScorer:
    """Combines Rule-Based, Markov, Isolation Forest, and Sequence Transformer scores
    into a final decision metric."""

    def __init__(
        self,
        w_rule: float = 0.2,
        w_markov: float = 0.2,
        w_isolation: float = 0.3,
        w_transformer: float = 0.3,
    ):
        self.w_rule = w_rule
        self.w_markov = w_markov
        self.w_isolation = w_isolation
        self.w_transformer = w_transformer

    def combine(
        self,
        rule_score: float,
        markov_score: float,
        isolation_score: float,
        transformer_score: Any = 0.0,
        rule_factors: list[str] | None = None,
        markov_factors: list[str] | None = None,
        isolation_factors: list[str] | None = None,
        transformer_factors: list[str] | None = None,
    ) -> tuple[float, list[str]]:
        actual_rule_factors: list[str]
        actual_markov_factors: list[str]
        actual_isolation_factors: list[str]
        actual_transformer_factors: list[str]
        actual_transformer_score: float

        # Backward-compatibility for 3-scorer calls: combine(r, m, i, r_f, m_f, i_f)
        if isinstance(transformer_score, list):
            actual_rule_factors = list(transformer_score)
            actual_markov_factors = list(rule_factors) if rule_factors is not None else []
            actual_isolation_factors = list(markov_factors) if markov_factors is not None else []
            actual_transformer_score = 0.0
            actual_transformer_factors = []
            is_legacy = True
        else:
            actual_transformer_score = float(transformer_score)
            actual_rule_factors = list(rule_factors) if rule_factors is not None else []
            actual_markov_factors = list(markov_factors) if markov_factors is not None else []
            actual_isolation_factors = (
                list(isolation_factors) if isolation_factors is not None else []
            )
            actual_transformer_factors = (
                list(transformer_factors) if transformer_factors is not None else []
            )
            is_legacy = False

        all_factors: list[str] = (
            actual_rule_factors
            + actual_markov_factors
            + actual_isolation_factors
            + actual_transformer_factors
        )

        # Circuit Breaker: Explicit heuristic rule violations (>= 0.75) or extreme ML
        # statistical outliers (>= 0.90) escalate to the max individual score.
        if (
            rule_score >= 0.75
            or markov_score >= 0.90
            or isolation_score >= 0.90
            or actual_transformer_score >= 0.90
        ):
            final_score = max(rule_score, markov_score, isolation_score, actual_transformer_score)
            all_factors.append("Circuit Breaker: High-confidence anomaly from individual engine")
            return final_score, all_factors

        # Compute weighted sum
        if is_legacy:
            weighted = 0.3 * rule_score + 0.3 * markov_score + 0.4 * isolation_score
        else:
            weighted = (
                self.w_rule * rule_score
                + self.w_markov * markov_score
                + self.w_isolation * isolation_score
                + self.w_transformer * actual_transformer_score
            )
        return round(min(1.0, max(0.0, weighted)), 3), all_factors
