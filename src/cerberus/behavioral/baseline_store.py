import json
import logging
import os
import shutil
import tempfile
from datetime import UTC, datetime
from typing import Any

try:
    import joblib
except ImportError:
    import pickle as joblib

import numpy as np

from cerberus.proxy.models import AgentBaseline, BaselineSnapshot

logger = logging.getLogger("cerberus.baseline_store")


def _atomic_write_json(target_path: str, data: Any) -> None:
    dirname = os.path.dirname(target_path)
    os.makedirs(dirname, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=dirname, delete=False, encoding="utf-8") as tf:
        json.dump(data, tf, indent=2)
        temp_name = tf.name
    shutil.move(temp_name, target_path)


def _atomic_write_joblib(target_path: str, obj: Any) -> None:
    dirname = os.path.dirname(target_path)
    os.makedirs(dirname, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=dirname, delete=False) as tf:
        temp_name = tf.name
    joblib.dump(obj, temp_name)
    shutil.move(temp_name, target_path)


def compute_tvd(matrix_a: dict[str, dict[str, int]], matrix_b: dict[str, dict[str, int]]) -> float:
    """Computes row-wise maximum Total Variation Distance (TVD) between two Markov transition matrices.

    TVD(A, B) = max_{u} 0.5 * sum_{v} |P_A(v|u) - P_B(v|u)|
    """
    max_tvd = 0.0
    all_from_tools = set(matrix_a.keys()).union(set(matrix_b.keys()))
    for from_tool in all_from_tools:
        row_a = matrix_a.get(from_tool, {})
        row_b = matrix_b.get(from_tool, {})
        total_a = sum(row_a.values()) or 1
        total_b = sum(row_b.values()) or 1

        all_to_tools = set(row_a.keys()).union(set(row_b.keys()))
        tvd = 0.5 * sum(
            abs((row_a.get(t, 0) / total_a) - (row_b.get(t, 0) / total_b)) for t in all_to_tools
        )
        max_tvd = max(max_tvd, tvd)
    return max_tvd


class BaselineStore:
    """Manages versioned baseline snapshots and stability gating to prevent boiling-frog poisoning."""

    def __init__(self, base_dir: str = "baselines"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self.baselines: dict[str, AgentBaseline] = {}

    def get_baseline(self, agent_id: str) -> AgentBaseline:
        if agent_id not in self.baselines:
            self.baselines[agent_id] = AgentBaseline(
                agent_id=agent_id,
                created_at=datetime.now(UTC),
                last_updated=datetime.now(UTC),
            )
        return self.baselines[agent_id]

    def validate_stability(
        self,
        agent_id: str,
        new_transition_matrix: dict[str, dict[str, int]],
        max_divergence: float = 0.5,
    ) -> tuple[bool, str]:
        """Anti-poisoning stability gate: enforces dual gating against step divergence
        and cumulative drift from frozen anchor baseline (boiling-frog guard)."""
        baseline = self.get_baseline(agent_id)
        if not baseline.active_snapshot_id or not baseline.snapshots:
            return True, "Initial baseline - no prior snapshot to compare"

        active_snap = next(
            (s for s in baseline.snapshots if s.snapshot_id == baseline.active_snapshot_id), None
        )
        if not active_snap or not os.path.exists(active_snap.transition_matrix_path):
            return True, "Active snapshot file missing, permitting update"

        try:
            with open(active_snap.transition_matrix_path, "r", encoding="utf-8") as f:
                old_matrix = json.load(f)

            # 1. Step-wise divergence check against active snapshot
            step_tvd = compute_tvd(old_matrix, new_transition_matrix)
            if step_tvd > max_divergence:
                return (
                    False,
                    f"Baseline shift rejected: TVD {step_tvd:.3f} exceeds threshold {max_divergence:.3f} (boiling-frog guard)",
                )

            # 2. Cumulative drift check against frozen anchor baseline
            from cerberus.config import settings

            env_drift = os.environ.get("CERBERUS_TVD_ANCHOR_MAX_DRIFT")
            if env_drift is not None:
                try:
                    anchor_max_drift = float(env_drift)
                except ValueError:
                    anchor_max_drift = getattr(settings, "tvd_anchor_max_drift", 0.40)
            else:
                anchor_max_drift = getattr(settings, "tvd_anchor_max_drift", 0.40)

            anchor_snap_id = baseline.anchor_snapshot_id or (
                baseline.snapshots[0].snapshot_id if baseline.snapshots else None
            )
            if anchor_snap_id:
                anchor_snap = next(
                    (s for s in baseline.snapshots if s.snapshot_id == anchor_snap_id), None
                )
                if anchor_snap and os.path.exists(anchor_snap.transition_matrix_path):
                    with open(anchor_snap.transition_matrix_path, "r", encoding="utf-8") as f:
                        anchor_matrix = json.load(f)
                    anchor_tvd = compute_tvd(anchor_matrix, new_transition_matrix)
                    if anchor_tvd > anchor_max_drift:
                        return (
                            False,
                            f"Cumulative baseline drift rejected: Anchor TVD {anchor_tvd:.3f} exceeds drift budget {anchor_max_drift:.3f} (boiling-frog guard)",
                        )

            return True, f"Stability verified (max TVD: {step_tvd:.3f})"
        except Exception as e:
            logger.warning(f"Error checking baseline stability: {e}")
            return False, f"Stability check failed (fail-closed on error): {e}"

    def create_snapshot(
        self,
        agent_id: str,
        calls_count: int,
        transition_matrix: dict[str, dict[str, int]],
        if_model: Any = None,
        transformer_model: Any = None,
        scaling_params: Any = None,
    ) -> BaselineSnapshot:
        baseline = self.get_baseline(agent_id)
        snap_id = f"snap_{len(baseline.snapshots) + 1}"
        agent_dir = os.path.join(self.base_dir, agent_id)
        os.makedirs(agent_dir, exist_ok=True)

        tm_path = os.path.join(agent_dir, f"{snap_id}_markov.json")
        if_path = os.path.join(agent_dir, f"{snap_id}_if.joblib")
        scale_path = os.path.join(agent_dir, f"{snap_id}_scale.json")
        tf_path = os.path.join(agent_dir, f"{snap_id}_transformer.json")

        # Atomic persistence of components
        _atomic_write_json(tm_path, transition_matrix)

        if if_model is not None and hasattr(joblib, "dump"):
            _atomic_write_joblib(if_path, if_model)

        if scaling_params is not None:
            _atomic_write_json(scale_path, scaling_params)

        if transformer_model is not None:
            tf_data = {
                "vocab": getattr(transformer_model, "vocab", {}),
                "inv_vocab": {
                    str(k): v for k, v in getattr(transformer_model, "inv_vocab", {}).items()
                },
                "W_embed": getattr(transformer_model, "W_embed", np.array([])).tolist(),
                "W_enc": getattr(transformer_model, "W_enc", np.array([])).tolist(),
                "W_dec": getattr(transformer_model, "W_dec", np.array([])).tolist(),
                "baseline_reconstruction_error": getattr(
                    transformer_model, "baseline_reconstruction_error", 0.5
                ),
                "is_fitted": getattr(transformer_model, "is_fitted", False),
            }
            _atomic_write_json(tf_path, tf_data)

        snapshot = BaselineSnapshot(
            snapshot_id=snap_id,
            calls_in_snapshot=calls_count,
            transition_matrix_path=tm_path,
            isolation_forest_path=if_path,
            scaling_params_path=scale_path,
            transformer_path=tf_path if transformer_model is not None else "",
            is_active=True,
        )

        for s in baseline.snapshots:
            s.is_active = False

        baseline.snapshots.append(snapshot)
        baseline.active_snapshot_id = snap_id
        if baseline.anchor_snapshot_id is None:
            baseline.anchor_snapshot_id = snap_id
        baseline.is_warm = calls_count >= baseline.warm_threshold_calls
        baseline.last_updated = datetime.now(UTC)
        return snapshot

    def promote_snapshot(self, agent_id: str, snapshot_id: str, make_anchor: bool = True) -> bool:
        """Promote an existing snapshot to active. Optionally sets it as the frozen anchor."""
        baseline = self.get_baseline(agent_id)
        found = False
        for s in baseline.snapshots:
            if s.snapshot_id == snapshot_id:
                s.is_active = True
                found = True
            else:
                s.is_active = False
        if found:
            baseline.active_snapshot_id = snapshot_id
            if make_anchor:
                baseline.anchor_snapshot_id = snapshot_id
            baseline.last_updated = datetime.now(UTC)
        return found

    def set_anchor_snapshot(self, agent_id: str, snapshot_id: str) -> bool:
        """Explicitly update the frozen anchor snapshot for an agent (administrative re-anchoring)."""
        baseline = self.get_baseline(agent_id)
        found = any(s.snapshot_id == snapshot_id for s in baseline.snapshots)
        if found:
            baseline.anchor_snapshot_id = snapshot_id
            baseline.last_updated = datetime.now(UTC)
        return found

    def load_snapshot(self, agent_id: str, snapshot_id: str | None = None) -> dict[str, Any] | None:
        """Loads and restores artifacts for a given snapshot."""
        baseline = self.get_baseline(agent_id)
        snap_id = snapshot_id or baseline.active_snapshot_id
        if not snap_id:
            return None

        snap = next((s for s in baseline.snapshots if s.snapshot_id == snap_id), None)
        if not snap:
            return None

        result: dict[str, Any] = {"snapshot": snap}

        # 1. Markov transition matrix
        if os.path.exists(snap.transition_matrix_path):
            with open(snap.transition_matrix_path, "r", encoding="utf-8") as f:
                result["transition_matrix"] = json.load(f)

        # 2. Isolation forest
        if os.path.exists(snap.isolation_forest_path):
            try:
                result["if_model"] = joblib.load(snap.isolation_forest_path)
            except Exception as e:
                logger.warning(f"Failed to load IF model: {e}")
                result["if_model"] = None

        # 3. Scaling params
        if os.path.exists(snap.scaling_params_path):
            try:
                with open(snap.scaling_params_path, "r", encoding="utf-8") as f:
                    result["scaling_params"] = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load scaling params: {e}")
                result["scaling_params"] = None

        # 4. Transformer state
        if snap.transformer_path and os.path.exists(snap.transformer_path):
            try:
                with open(snap.transformer_path, "r", encoding="utf-8") as f:
                    result["transformer_state"] = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load transformer state: {e}")
                result["transformer_state"] = None

        return result
