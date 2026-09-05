from cerberus.behavioral.baseline_store import BaselineStore
from cerberus.behavioral.scorers.transformer import SequenceTransformerScorer


def test_baseline_store_create_load_snapshot(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-x"

    matrix = {"tool_a": {"tool_b": 10, "tool_c": 2}}
    scaler_stats = {"time_ms": {"count": 10, "mean": 100.0, "M2": 500.0}}

    tf = SequenceTransformerScorer()
    tf.fit([["tool_a", "tool_b", "tool_c"]])

    snap = store.create_snapshot(
        agent_id=agent_id,
        calls_count=50,
        transition_matrix=matrix,
        if_model=None,
        transformer_model=tf,
        scaling_params=scaler_stats,
    )

    assert snap.snapshot_id == "snap_1"
    assert snap.is_active is True

    # Test load_snapshot
    loaded = store.load_snapshot(agent_id, "snap_1")
    assert loaded is not None
    assert loaded["transition_matrix"] == matrix
    assert loaded["scaling_params"] == scaler_stats
    assert loaded["transformer_state"]["is_fitted"] is True


def test_baseline_store_stability_gating(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-y"

    matrix1 = {"read_file": {"write_file": 10}}
    store.create_snapshot(agent_id, calls_count=20, transition_matrix=matrix1)

    # 1. Minor shift should be allowed
    matrix_minor = {"read_file": {"write_file": 10, "stat": 1}}
    valid, reason = store.validate_stability(agent_id, matrix_minor, max_divergence=0.5)
    assert valid is True
    assert "Stability verified" in reason

    # 2. Drastic shift (e.g. read_file completely transitions to network_post)
    matrix_poison = {"read_file": {"network_post": 100}}
    valid, reason = store.validate_stability(agent_id, matrix_poison, max_divergence=0.4)
    assert valid is False
    assert "boiling-frog" in reason
