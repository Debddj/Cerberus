import os
import json
try:
    import joblib
except ImportError:
    import pickle as joblib

from cerberus.proxy.models import AgentBaseline, BaselineSnapshot
from datetime import datetime, timezone

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
                created_at=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc)
            )
        return self.baselines[agent_id]

    def create_snapshot(self, agent_id: str, calls_count: int, transition_matrix: dict, if_model) -> BaselineSnapshot:
        baseline = self.get_baseline(agent_id)
        snap_id = f"snap_{len(baseline.snapshots) + 1}"
        agent_dir = os.path.join(self.base_dir, agent_id)
        os.makedirs(agent_dir, exist_ok=True)
        
        tm_path = os.path.join(agent_dir, f"{snap_id}_markov.json")
        if_path = os.path.join(agent_dir, f"{snap_id}_if.joblib")
        scale_path = os.path.join(agent_dir, f"{snap_id}_scale.json")
        
        with open(tm_path, "w", encoding="utf-8") as f:
            json.dump(transition_matrix, f)
        if if_model is not None:
            if hasattr(joblib, "dump"):
                joblib.dump(if_model, if_path)
            
        snapshot = BaselineSnapshot(
            snapshot_id=snap_id,
            calls_in_snapshot=calls_count,
            transition_matrix_path=tm_path,
            isolation_forest_path=if_path,
            scaling_params_path=scale_path,
            is_active=True
        )
        
        for s in baseline.snapshots:
            s.is_active = False
            
        baseline.snapshots.append(snapshot)
        baseline.active_snapshot_id = snap_id
        baseline.is_warm = calls_count >= baseline.warm_threshold_calls
        return snapshot
