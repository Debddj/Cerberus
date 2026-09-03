from cerberus.behavioral.baseline_store import BaselineStore

def test_baseline_snapshot_versioning(tmp_path):
    store = BaselineStore(base_dir=str(tmp_path))
    snap1 = store.create_snapshot("agent-01", 50, {"a": {"b": 1}}, None)
    assert snap1.snapshot_id == "snap_1"
    assert not store.get_baseline("agent-01").is_warm
    
    snap2 = store.create_snapshot("agent-01", 120, {"a": {"b": 2}}, None)
    assert snap2.snapshot_id == "snap_2"
    assert store.get_baseline("agent-01").is_warm
