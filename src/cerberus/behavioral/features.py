import json
import math
from collections import Counter

from cerberus.proxy.models import (
    IsolationForestFeatures,
    MarkovFeatures,
    RuleFeatures,
    ToolCallEvent,
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


class FeatureExtractor:
    """Extracts segregated categorical (Markov) and continuous (Isolation Forest) features."""

    @staticmethod
    def extract_entropy(parameters: dict) -> float:
        raw_bytes = json.dumps(parameters, sort_keys=True).encode("utf-8")
        return shannon_entropy(raw_bytes)

    @staticmethod
    def calculate_novelty(times_seen: int, decay_factor: float = 5.0) -> float:
        return 1.0 - (times_seen / (times_seen + decay_factor))

    @classmethod
    def extract_all(
        cls,
        event: ToolCallEvent,
        prev_tools: list[str],
        tool_seen_count: int,
        dest_seen_count: int,
        z_stats: dict[str, tuple[float, float]],  # name -> (mean, std)
    ) -> tuple[MarkovFeatures, IsolationForestFeatures, RuleFeatures]:

        # Prefer pre-computed values from the event, fall back to calculation if zero
        param_bytes = event.parameter_size_bytes
        entropy = event.parameter_entropy
        if param_bytes == 0 and event.parameters:
            param_bytes = len(json.dumps(event.parameters, sort_keys=True).encode("utf-8"))
            entropy = cls.extract_entropy(event.parameters)

        tool_novelty = cls.calculate_novelty(tool_seen_count)
        dest_novelty = cls.calculate_novelty(dest_seen_count) if event.destination_domain else 0.0

        # 1. Markov Features (Strictly Categorical)
        markov = MarkovFeatures(
            tool_name=event.tool_name,
            server_name=event.tool_server,
            prev_tool_1=prev_tools[-1] if len(prev_tools) >= 1 else None,
            prev_tool_2=prev_tools[-2] if len(prev_tools) >= 2 else None,
            prev_tool_3=prev_tools[-3] if len(prev_tools) >= 3 else None,
        )

        # 2. Isolation Forest Features (Strictly Continuous, Z-Score Scaled)
        def z(val: float, key: str) -> float:
            mean, std = z_stats.get(key, (0.0, 1.0))
            return (val - mean) / (std if std != 0 else 1.0)

        isolation = IsolationForestFeatures(
            param_size_bytes_z=z(float(param_bytes), "param_size"),
            param_entropy_z=z(entropy, "entropy"),
            response_size_bytes_z=z(event.response_size_bytes or 0.0, "response_size"),
            time_since_previous_ms_z=z(event.time_since_previous_ms or 0.0, "time_diff"),
            session_duration_ms_z=z(event.session_duration_ms, "duration"),
            sequence_position_z=z(float(event.sequence_position), "seq_pos"),
            destination_novelty=dest_novelty,
            tool_novelty=tool_novelty,
        )

        # 3. Rule Features (Hybrid for immediate pre-baseline rules)
        rule = RuleFeatures(
            tool_name=event.tool_name,
            param_size_bytes=float(param_bytes),
            param_entropy=entropy,
            response_size_bytes=float(event.response_size_bytes or 0.0),
            time_since_previous_ms=event.time_since_previous_ms or 0.0,
            sequence_position=event.sequence_position,
            destination_novelty=dest_novelty,
            tool_novelty=tool_novelty,
            destination_domain=event.destination_domain,
            prev_tools=prev_tools,
        )

        return markov, isolation, rule
