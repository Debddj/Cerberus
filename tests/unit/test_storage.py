import pytest

from cerberus.storage.backend import InMemoryBackend, get_storage_backend


@pytest.mark.asyncio
async def test_in_memory_backend_events():
    backend = InMemoryBackend(max_history_per_key=10)
    for i in range(5):
        await backend.record_event(
            session_id="sess_1",
            agent_id="agent_a",
            event_data={"tool": f"call_{i}", "index": i},
        )

    history = await backend.get_session_history("sess_1", limit=3)
    assert len(history) == 3
    assert history[-1]["tool"] == "call_4"

    agent_hist = await backend.get_agent_history("agent_a", limit=10)
    assert len(agent_hist) == 5

    sessions = await backend.get_active_sessions()
    assert "sess_1" in sessions

    agents = await backend.get_active_agents()
    assert "agent_a" in agents

    health = await backend.health_check()
    assert health["status"] == "healthy"
    assert health["active_sessions"] == 1
    assert health["active_agents"] == 1

    await backend.close()


@pytest.mark.asyncio
async def test_in_memory_backend_welford_stats():
    backend = InMemoryBackend()
    v1 = [10.0, 20.0]
    mean, var, count = await backend.update_running_stats("agent_b", v1)
    assert count == 1
    assert mean == [10.0, 20.0]

    v2 = [20.0, 40.0]
    mean, var, count = await backend.update_running_stats("agent_b", v2)
    assert count == 2
    assert mean == [15.0, 30.0]
    assert var[0] > 0.0 and var[1] > 0.0

    await backend.close()


@pytest.mark.asyncio
async def test_in_memory_backend_rate_limiting():
    backend = InMemoryBackend()
    agent = "rate_limited_agent"
    limit = 3

    # First 3 should pass
    for _ in range(limit):
        allowed = await backend.check_rate_limit(agent, limit=limit, window_seconds=60)
        assert allowed is True

    # 4th should be rejected
    rejected = await backend.check_rate_limit(agent, limit=limit, window_seconds=60)
    assert rejected is False

    await backend.close()


def test_get_storage_backend_factory():
    backend_default = get_storage_backend(None)
    assert isinstance(backend_default, InMemoryBackend)

    backend_empty = get_storage_backend("")
    assert isinstance(backend_empty, InMemoryBackend)
