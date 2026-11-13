"""Tests for evaluation baseline warm-up and Isolation Forest buffer aggregation."""

import numpy as np

from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.models import IsolationForestFeatures
from cerberus.proxy.server import CerberusProxyEngine


def test_agent_if_buffers_aggregation(tmp_path=None):
    """Verify that feature vectors from agent_if_buffers are aggregated across multiple agents
    and successfully fit the IsolationForestScorer once the sample threshold (>= 20) is met.
    """
    if tmp_path is not None:
        audit_logger = AuditLogger(log_path=str(tmp_path / "test_eval_audit.jsonl"))
        engine = CerberusProxyEngine(audit_logger=audit_logger)
    else:
        engine = CerberusProxyEngine()

    # Verify initial unfitted state
    assert not engine.isolation_scorer.is_fitted
    assert len(engine.agent_if_buffers) == 0

    # Populate 8-dimensional feature vectors across 4 archetypes (6 vectors each = 24 total, >= 20)
    archetypes = ["coding-01", "data-01", "support-01", "triage-01"]
    for arch_idx, arch in enumerate(archetypes):
        for i in range(6):
            # 8 continuous features matching IsolationForestFeatures:
            # [param_size, entropy, resp_size, time_diff, duration, seq_pos, dest_nov, tool_nov]
            vec = [float(arch_idx * 0.1 + i * 0.02) for _ in range(8)]
            engine.agent_if_buffers[arch].append(vec)

    # Replicate buffer aggregation logic from evaluation/run_evaluation.py:61
    all_if_vectors = [vec for buf in engine.agent_if_buffers.values() for vec in buf]
    assert len(all_if_vectors) == 24
    assert len(all_if_vectors) >= 20
    assert len(engine.agent_if_buffers["coding-01"]) == 6
    assert len(engine.agent_if_buffers["triage-01"]) == 6

    # Verify warmup fitting logic on aggregated vectors
    if all_if_vectors and not engine.isolation_scorer.is_fitted:
        engine.isolation_scorer.fit(np.array(all_if_vectors))

    # Assert model is genuinely fitted without mocks
    assert engine.isolation_scorer.is_fitted
    assert engine.isolation_scorer.model is not None
    assert hasattr(engine.isolation_scorer.model, "estimators_")
    assert len(engine.isolation_scorer.model.estimators_) == 100

    # Assert genuine scoring inference works without errors
    sample_feat = IsolationForestFeatures(
        param_size_bytes_z=0.1,
        param_entropy_z=0.1,
        response_size_bytes_z=0.0,
        time_since_previous_ms_z=0.1,
        session_duration_ms_z=0.1,
        sequence_position_z=0.1,
        destination_novelty=0.0,
        tool_novelty=0.0,
    )
    score, factors = engine.isolation_scorer.score(sample_feat)
    assert 0.0 <= score <= 1.0
    assert isinstance(factors, list)


def test_agent_if_buffers_sub_threshold_guard(tmp_path=None):
    """Verify that when accumulated vectors are below the sample threshold (< 20),
    the IsolationForestScorer safely guards against premature fitting and remains unfitted.
    """
    if tmp_path is not None:
        audit_logger = AuditLogger(log_path=str(tmp_path / "test_sub_audit.jsonl"))
        engine = CerberusProxyEngine(audit_logger=audit_logger)
    else:
        engine = CerberusProxyEngine()

    # Populate only 3 vectors across two agents (< 20)
    engine.agent_if_buffers["coding-01"].append([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8])
    engine.agent_if_buffers["coding-01"].append([0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    engine.agent_if_buffers["data-01"].append([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2])

    all_if_vectors = [vec for buf in engine.agent_if_buffers.values() for vec in buf]
    assert len(all_if_vectors) == 3
    assert len(all_if_vectors) < 20

    scorer = IsolationForestScorer()
    assert not scorer.is_fitted
    scorer.fit(np.array(all_if_vectors))
    # Scorer must remain unfitted due to len(X) < 20 guard in isolation.py:32
    assert not scorer.is_fitted
