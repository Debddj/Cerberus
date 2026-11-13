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


def test_anchor_baseline_tracking(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-anchor"

    matrix1 = {"read_file": {"write_file": 100}}
    snap1 = store.create_snapshot(agent_id, calls_count=50, transition_matrix=matrix1)
    baseline = store.get_baseline(agent_id)

    assert baseline.anchor_snapshot_id == "snap_1"
    assert baseline.active_snapshot_id == "snap_1"
    assert snap1.snapshot_id == "snap_1"

    # Creating a second snapshot should NOT overwrite anchor_snapshot_id
    matrix2 = {"read_file": {"write_file": 90, "stat": 10}}
    snap2 = store.create_snapshot(agent_id, calls_count=100, transition_matrix=matrix2)

    assert baseline.anchor_snapshot_id == "snap_1"
    assert baseline.active_snapshot_id == "snap_2"
    assert snap2.snapshot_id == "snap_2"


def test_boiling_frog_anchor_budget_exceeded(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-frog"

    # Initial anchor snapshot M_0: 100% read -> write
    matrix_0 = {"read": {"write": 100}}
    store.create_snapshot(agent_id, calls_count=50, transition_matrix=matrix_0)
    baseline = store.get_baseline(agent_id)
    assert baseline.anchor_snapshot_id == "snap_1"

    # Perform incremental boiling-frog shift: 0.04 per iteration
    # Step TVD = 0.04 <= 0.50 always passes step check
    # But after 11 iterations (cumulative TVD = 0.44 > 0.40), cumulative check rejects
    rejected_at = None
    for k in range(1, 16):
        cand_matrix = {"read": {"write": 100 - 4 * k, "network_post": 4 * k}}
        valid, reason = store.validate_stability(agent_id, cand_matrix, max_divergence=0.50)
        if not valid:
            rejected_at = k
            assert "Cumulative baseline drift rejected" in reason
            assert "boiling-frog" in reason
            break
        # Create snapshot to advance active snapshot
        store.create_snapshot(agent_id, calls_count=50 + 10 * k, transition_matrix=cand_matrix)

    assert rejected_at == 11


def test_anchor_drift_env_override(tmp_path, monkeypatch):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-env"

    matrix_anchor = {"read": {"write": 100}}
    store.create_snapshot(agent_id, calls_count=50, transition_matrix=matrix_anchor)

    # Shift of 0.25 (step TVD 0.25 <= 0.50)
    matrix_candidate = {"read": {"write": 75, "network_post": 25}}

    # With default 0.40 anchor budget, this should pass
    valid, _ = store.validate_stability(agent_id, matrix_candidate, max_divergence=0.50)
    assert valid is True

    # With CERBERUS_TVD_ANCHOR_MAX_DRIFT=0.20, it should be rejected by cumulative check
    monkeypatch.setenv("CERBERUS_TVD_ANCHOR_MAX_DRIFT", "0.20")
    valid_env, reason = store.validate_stability(agent_id, matrix_candidate, max_divergence=0.50)
    assert valid_env is False
    assert "Cumulative baseline drift rejected" in reason
    assert "boiling-frog" in reason


def test_anchor_reanchoring_on_promotion(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    agent_id = "agent-promote"

    matrix1 = {"read": {"write": 100}}
    store.create_snapshot(agent_id, calls_count=50, transition_matrix=matrix1)
    baseline = store.get_baseline(agent_id)
    assert baseline.anchor_snapshot_id == "snap_1"

    # Create snap_2 with substantial legitimate shift
    matrix2 = {"read": {"write": 60, "exec": 40}}
    store.create_snapshot(agent_id, calls_count=100, transition_matrix=matrix2)
    assert baseline.anchor_snapshot_id == "snap_1"

    # Promoting snap_2 as anchor resets anchor_snapshot_id to snap_2
    promoted = store.promote_snapshot(agent_id, "snap_2", make_anchor=True)
    assert promoted is True
    assert baseline.anchor_snapshot_id == "snap_2"
    assert baseline.active_snapshot_id == "snap_2"

    # Now matrix2 validated against anchor (which is snap_2) has TVD 0.0
    valid, reason = store.validate_stability(agent_id, matrix2, max_divergence=0.50)
    assert valid is True
    assert "Stability verified" in reason
