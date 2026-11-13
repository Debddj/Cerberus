from cerberus.behavioral.features import FeatureExtractor, shannon_entropy
from cerberus.proxy.models import ToolCallEvent


def test_entropy_computation():
    assert shannon_entropy(b"") == 0.0
    low_ent = shannon_entropy(b"aaaaaaaaaaaa")
    high_ent = shannon_entropy(b"a8f934x!9128zL")
    assert high_ent > low_ent


def test_feature_segregation():
    event = ToolCallEvent(
        session_id="s1",
        agent_id="a1",
        tool_name="read_file",
        tool_server="file-server",
        parameters={"test": "val"},
    )
    markov, if_feat, _rule = FeatureExtractor.extract_all(event, ["prev_t"], 5, 0, {})
    assert markov.tool_name == "read_file"
    assert markov.prev_tool_1 == "prev_t"
    assert hasattr(if_feat, "param_entropy_z")
    assert hasattr(if_feat, "destination_novelty")


def test_bounded_sequence_and_duration_drift():
    # Long running session: 500 calls, 2 hours (7,200,000 ms)
    event = ToolCallEvent(
        session_id="long-session",
        agent_id="agent-worker",
        tool_name="process_item",
        tool_server="data-server",
        parameters={"item_id": 123},
        session_duration_ms=7_200_000.0,
        sequence_position=500,
    )

    # Simulated warmed baseline statistics for log-scaled features:
    # duration median ~1800s (log10(1801) ≈ 3.25), scale ~0.50
    # seq_pos median ~100 calls (log2(101) ≈ 6.66), scale ~1.50
    z_stats = {
        "duration": (3.25, 0.50),
        "seq_pos": (6.66, 1.50),
    }

    _, if_feat, _ = FeatureExtractor.extract_all(event, [], 10, 0, z_stats)

    # Verify z-scores are bounded in [-5.0, 5.0]
    assert -5.0 <= if_feat.session_duration_ms_z <= 5.0
    assert -5.0 <= if_feat.sequence_position_z <= 5.0

    # Under warmed baseline, 2 hours / 500 calls does not trigger runaway false alarm (abs(z) < 3.0)
    assert abs(if_feat.session_duration_ms_z) < 3.0
    assert abs(if_feat.sequence_position_z) < 3.0

    # Test extreme outlier clamping: 100 days duration, 50,000 calls
    extreme_event = ToolCallEvent(
        session_id="extreme-session",
        agent_id="agent-worker",
        tool_name="process_item",
        tool_server="data-server",
        session_duration_ms=8_640_000_000.0,
        sequence_position=50000,
    )
    # With unwarmed stats that would blow up without clamping
    extreme_stats = {
        "duration": (0.0, 0.1),
        "seq_pos": (0.0, 0.1),
    }
    _, if_extreme, _ = FeatureExtractor.extract_all(extreme_event, [], 10, 0, extreme_stats)
    assert if_extreme.session_duration_ms_z == 5.0
    assert if_extreme.sequence_position_z == 5.0


def test_raw_vs_redacted_entropy_integrity():
    import json

    from cerberus.proxy.redactor import SecretRedactor

    raw_params = {
        "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
        "description": "High entropy secret key payload",
    }
    # 1. Feature extraction on raw parameters
    param_entropy = FeatureExtractor.extract_entropy(raw_params)
    param_bytes = len(json.dumps(raw_params, sort_keys=True).encode("utf-8"))

    # 2. Secret Redaction
    redacted_params, redacted_fields = SecretRedactor.redact_dict(raw_params)

    # Construct event adhering to invariant
    event = ToolCallEvent(
        session_id="s_sec",
        agent_id="a_sec",
        tool_name="auth_service",
        tool_server="auth-server",
        parameters=redacted_params,
        parameter_size_bytes=param_bytes,
        parameter_entropy=param_entropy,
        redacted_fields=redacted_fields,
    )

    # Verify event.parameters has redacted secret
    assert event.parameters["api_key"] == "[REDACTED_SECRET]"
    assert "api_key" in event.redacted_fields

    # Verify entropy reflects the raw high-entropy secret, not the "[REDACTED_SECRET]" string
    assert event.parameter_entropy > 4.0
    redacted_entropy = FeatureExtractor.extract_entropy(redacted_params)
    assert event.parameter_entropy > redacted_entropy


def test_negative_sequence_position_and_duration_resilience():
    """Verify that negative session durations and sequence positions evaluate gracefully to bounded z-scores without crashing."""
    # 1. Event with negative sequence position (-5) and negative duration (-5000.0 ms)
    event_neg = ToolCallEvent(
        session_id="neg_sess",
        agent_id="test_agent",
        tool_name="read_file",
        tool_server="file-server",
        parameters={"test": "val"},
        session_duration_ms=-5000.0,
        sequence_position=-5,
    )

    z_stats = {
        "duration": (0.0, 1.0),
        "seq_pos": (0.0, 1.0),
    }

    _markov, if_feat, _rule = FeatureExtractor.extract_all(
        event=event_neg,
        prev_tools=[],
        tool_seen_count=1,
        dest_seen_count=0,
        z_stats=z_stats,
    )

    # Negative inputs clamped to 0 -> log10(0 + 1) = 0.0, log2(0 + 1) = 0.0
    # Z-scores against neutral (0.0, 1.0) must evaluate to 0.0
    assert if_feat.session_duration_ms_z == 0.0
    assert if_feat.sequence_position_z == 0.0
    assert -5.0 <= if_feat.session_duration_ms_z <= 5.0
    assert -5.0 <= if_feat.sequence_position_z <= 5.0

    # 2. Test with warmed non-zero stats
    warmed_stats = {
        "duration": (2.0, 0.5),  # mean=2.0, std=0.5 -> (0.0 - 2.0)/0.5 = -4.0
        "seq_pos": (6.0, 1.0),  # mean=6.0, std=1.0 -> (0.0 - 6.0)/1.0 = -6.0 -> clamped to -5.0
    }
    _, if_warmed, _ = FeatureExtractor.extract_all(
        event=event_neg,
        prev_tools=[],
        tool_seen_count=5,
        dest_seen_count=0,
        z_stats=warmed_stats,
    )
    assert if_warmed.session_duration_ms_z == -4.0
    assert if_warmed.sequence_position_z == -5.0  # Clamped at lower bound


def test_novelty_and_z_score_defensive_math():
    """Verify that calculate_novelty and z-score calculations handle edge-case inputs defensively."""
    # Negative seen counts should not divide by zero or yield negative novelty
    assert FeatureExtractor.calculate_novelty(-5) == 1.0
    assert FeatureExtractor.calculate_novelty(-100) == 1.0
    assert FeatureExtractor.calculate_novelty(0) == 1.0
    assert FeatureExtractor.calculate_novelty(5) == 0.5

    # Event with negative counts and pathological stats
    event = ToolCallEvent(
        session_id="patho_sess",
        agent_id="test_agent",
        tool_name="read_file",
        tool_server="file-server",
        session_duration_ms=0.0,
        sequence_position=0,
    )
    patho_stats = {
        "duration": (0.0, 0.0),  # Zero standard deviation
        "seq_pos": (0.0, -1.0),  # Negative standard deviation
    }
    _, if_feat, _ = FeatureExtractor.extract_all(
        event=event,
        prev_tools=[],
        tool_seen_count=-5,
        dest_seen_count=-1,
        z_stats=patho_stats,
    )
    assert -5.0 <= if_feat.session_duration_ms_z <= 5.0
    assert -5.0 <= if_feat.sequence_position_z <= 5.0
    assert if_feat.tool_novelty == 1.0
