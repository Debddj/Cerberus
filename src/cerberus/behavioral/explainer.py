class ScoreExplainer:
    """Formats score breakdowns and attributions into human-readable SOC summaries."""

    @staticmethod
    def explain(final_score: float, factors: list[str], baseline_warm: bool) -> str:
        status_str = "WARM" if baseline_warm else "COLD (Heuristic mode)"
        lines = [
            f"Cerberus Behavioral Verdict: Risk Score {final_score:.2f}",
            f"Baseline Status: {status_str}",
            "Contributing Attribution Factors:",
        ]
        if not factors:
            lines.append("  - No significant drift or risk indicators detected.")
        else:
            for f in factors:
                lines.append(f"  * {f}")
        return "\n".join(lines)
