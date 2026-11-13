import json
import logging
import math
from collections import Counter

from cerberus.proxy.models import (
    IsolationForestFeatures,
    MarkovFeatures,
    RuleFeatures,
    ToolCallEvent,
)

logger = logging.getLogger("cerberus.features")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return max(0.0, -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values()))


class FeatureExtractor:
    """Extracts segregated categorical (Markov) and continuous (Isolation Forest) features."""

    @staticmethod
    def extract_entropy(parameters: dict) -> float:
        raw_bytes = json.dumps(parameters, sort_keys=True).encode("utf-8")
        return shannon_entropy(raw_bytes)

    @staticmethod
    def calculate_novelty(times_seen: int, decay_factor: float = 5.0) -> float:
        safe_seen = max(0, times_seen)
        safe_decay = max(1e-6, decay_factor)
        return max(0.0, min(1.0, 1.0 - (safe_seen / (safe_seen + safe_decay))))

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
            logger.warning(
                "FeatureExtractor: parameter_size_bytes is 0; calculating on event.parameters "
                "which may already be redacted!"
            )
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

        # 2. Isolation Forest Features (Strictly Continuous, Z-Score Scaled & Clamped to [-5.0, 5.0])
        def z(val: float, key: str) -> float:
            mean, std = z_stats.get(key, (0.0, 1.0))
            if not math.isfinite(val) or not math.isfinite(mean):
                return 0.0
            effective_std = std if (std is not None and math.isfinite(std) and std > 1e-6) else 1.0
            score = (val - mean) / effective_std
            if not math.isfinite(score):
                return 0.0
            return max(-5.0, min(5.0, score))

        duration_scaled = math.log10(
            min(max(0.0, float(event.session_duration_ms or 0.0)) / 1000.0, 86400.0) + 1.0
        )
        seq_pos_scaled = math.log2(min(max(0, int(event.sequence_position or 0)), 1000) + 1)

        isolation = IsolationForestFeatures(
            param_size_bytes_z=z(float(param_bytes), "param_size"),
            param_entropy_z=z(entropy, "entropy"),
            response_size_bytes_z=z(event.response_size_bytes or 0.0, "response_size"),
            time_since_previous_ms_z=z(event.time_since_previous_ms or 0.0, "time_diff"),
            session_duration_ms_z=z(duration_scaled, "duration"),
            sequence_position_z=z(seq_pos_scaled, "seq_pos"),
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
