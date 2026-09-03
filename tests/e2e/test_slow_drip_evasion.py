from sandbox.traffic.attacks.slow_drip_exfil import get_slow_drip_events

def test_e2e_slow_drip_accumulation():
    events = get_slow_drip_events()
    total_bytes = sum(e.parameter_size_bytes for e in events)
    assert total_bytes > 1500
    assert len(events) == 15
