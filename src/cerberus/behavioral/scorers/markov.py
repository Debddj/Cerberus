import math

from cerberus.proxy.models import MarkovFeatures


class MarkovScorer:
    """Tracks sequence transitions between tools with sigmoid-squashed surprise scoring."""

    def __init__(self):
        # transition_matrix: {from_tool: {to_tool: count}}
        self.transitions: dict[str, dict[str, int]] = {}

    def update(self, prev_tool: str, curr_tool: str):
        if prev_tool not in self.transitions:
            self.transitions[prev_tool] = {}
        row = self.transitions[prev_tool]
        row[curr_tool] = row.get(curr_tool, 0) + 1

    @staticmethod
    def squash_surprise(
        raw_surprise: float, midpoint: float = 6.0, steepness: float = 0.6
    ) -> float:
        """Applies sigmoid squashing: maps (-inf, +inf) -> (0, 1) cleanly."""
        try:
            return 1.0 / (1.0 + math.exp(-steepness * (raw_surprise - midpoint)))
        except OverflowError:
            return 1.0 if raw_surprise > midpoint else 0.0

    def score(self, features: MarkovFeatures) -> tuple[float, list[str]]:
        if not features.prev_tool_1:
            return 0.0, []

        prev = features.prev_tool_1
        curr = features.tool_name

        if prev not in self.transitions:
            # First time seeing this transition source
            return 0.5, [f"Unseen transition source tool: {prev}"]

        row = self.transitions[prev]
        total_transitions = sum(row.values())
        observed_count = row.get(curr, 0)

        # Laplace smoothing
        prob = (observed_count + 1) / (total_transitions + len(row) + 1)
        raw_surprise = -math.log2(prob)
        squashed_score = self.squash_surprise(raw_surprise)

        factors = []
        if squashed_score > 0.70:
            factors.append(
                f"Rare tool transition: '{curr}' following '{prev}' (surprise: {raw_surprise:.2f} bits)"
            )

        return squashed_score, factors
