import abc
import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any

from cerberus.config import settings

logger = logging.getLogger("cerberus.storage")


class StateBackend(abc.ABC):
    """Abstract interface for distributed or local state storage in Cerberus."""

    @abc.abstractmethod
    async def record_event(
        self, session_id: str, agent_id: str, event_data: dict[str, Any]
    ) -> None:
        """Record an audit event."""

    @abc.abstractmethod
    async def get_session_history(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve recent events for a given session."""

    @abc.abstractmethod
    async def get_agent_history(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve recent events for an agent across sessions."""

    @abc.abstractmethod
    async def get_active_sessions(self) -> list[str]:
        """Return list of active session IDs."""

    @abc.abstractmethod
    async def get_active_agents(self) -> list[str]:
        """Return list of active agent IDs."""

    @abc.abstractmethod
    async def update_running_stats(
        self, agent_id: str, feature_vector: list[float]
    ) -> tuple[list[float], list[float], int]:
        """Atomically update running mean, variance, and count via Welford algorithm."""

    @abc.abstractmethod
    async def check_rate_limit(self, agent_id: str, limit: int, window_seconds: int = 60) -> bool:
        """Return True if within rate limit, False if exceeded."""

    @abc.abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Check backend health status."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release underlying connections and resources."""


class InMemoryBackend(StateBackend):
    """Zero-dependency local in-memory backend for development and single-process deployments."""

    def __init__(self, max_history_per_key: int = 1000):
        self.max_history = max_history_per_key
        self._session_events: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.max_history)
        )
        self._agent_events: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.max_history)
        )
        self._rate_limits: dict[str, deque[float]] = defaultdict(deque)
        # Agent running stats: (count, mean_list, M2_list)
        self._stats: dict[str, tuple[int, list[float], list[float]]] = {}
        self._lock = asyncio.Lock()

    async def record_event(
        self, session_id: str, agent_id: str, event_data: dict[str, Any]
    ) -> None:
        async with self._lock:
            self._session_events[session_id].append(event_data)
            self._agent_events[agent_id].append(event_data)

    async def get_session_history(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        async with self._lock:
            events = list(self._session_events[session_id])
            return events[-limit:]

    async def get_agent_history(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        async with self._lock:
            events = list(self._agent_events[agent_id])
            return events[-limit:]

    async def get_active_sessions(self) -> list[str]:
        async with self._lock:
            return list(self._session_events.keys())

    async def get_active_agents(self) -> list[str]:
        async with self._lock:
            return list(self._agent_events.keys())

    async def update_running_stats(
        self, agent_id: str, feature_vector: list[float]
    ) -> tuple[list[float], list[float], int]:
        async with self._lock:
            if agent_id not in self._stats:
                dim = len(feature_vector)
                count = 1
                mean = list(feature_vector)
                m2 = [0.0] * dim
                self._stats[agent_id] = (count, mean, m2)
                variance = [1.0] * dim
                return mean, variance, count

            count, mean, m2 = self._stats[agent_id]
            count += 1
            new_mean = list(mean)
            new_m2 = list(m2)

            for i, x in enumerate(feature_vector):
                delta = x - mean[i]
                new_mean[i] += delta / count
                delta2 = x - new_mean[i]
                new_m2[i] += delta * delta2

            self._stats[agent_id] = (count, new_mean, new_m2)
            variance = [val / (count - 1) if count > 1 else 1.0 for val in new_m2]
            return new_mean, variance, count

    async def check_rate_limit(self, agent_id: str, limit: int, window_seconds: int = 60) -> bool:
        if limit <= 0:
            return True
        now = time.time()
        cutoff = now - window_seconds
        async with self._lock:
            window = self._rate_limits[agent_id]
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "backend": "in_memory",
            "active_sessions": len(self._session_events),
            "active_agents": len(self._agent_events),
        }

    async def close(self) -> None:
        async with self._lock:
            self._session_events.clear()
            self._agent_events.clear()
            self._rate_limits.clear()
            self._stats.clear()


class RedisBackend(StateBackend):
    """Production Redis backend with L1 in-memory session cache for sub-millisecond Tier 1 routing."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(redis_url, decode_responses=True)
        except ImportError:
            raise ImportError("redis package required for RedisBackend. Install via 'uv add redis'")

        # L1 In-Memory cache for low-latency session sticky hits
        self._l1_cache = InMemoryBackend(max_history_per_key=100)

        # Atomic Lua script for Welford algorithm
        self._welford_script = """
        local key = KEYS[1]
        local x_vals_json = ARGV[1]
        local x_vals = cjson.decode(x_vals_json)
        local raw = redis.call('GET', key)
        local count = 0
        local mean = {}
        local m2 = {}

        if raw then
            local data = cjson.decode(raw)
            count = data.count
            mean = data.mean
            m2 = data.m2
        else
            for i = 1, #x_vals do
                mean[i] = 0.0
                m2[i] = 0.0
            end
        end

        count = count + 1
        for i = 1, #x_vals do
            local x = x_vals[i]
            local delta = x - mean[i]
            mean[i] = mean[i] + (delta / count)
            local delta2 = x - mean[i]
            m2[i] = m2[i] + (delta * delta2)
        end

        local result = {count = count, mean = mean, m2 = m2}
        redis.call('SET', key, cjson.encode(result))
        return cjson.encode(result)
        """

    async def record_event(
        self, session_id: str, agent_id: str, event_data: dict[str, Any]
    ) -> None:
        await self._l1_cache.record_event(session_id, agent_id, event_data)
        try:
            raw = json.dumps(event_data)
            pipeline = self._redis.pipeline()
            pipeline.rpush(f"session:{session_id}:events", raw)
            pipeline.ltrim(f"session:{session_id}:events", -1000, -1)
            pipeline.rpush(f"agent:{agent_id}:events", raw)
            pipeline.ltrim(f"agent:{agent_id}:events", -1000, -1)
            pipeline.sadd("active_sessions", session_id)
            pipeline.sadd("active_agents", agent_id)
            await pipeline.execute()
        except Exception as e:
            logger.warning(f"Redis record_event failed, fell back to L1: {e}")

    async def get_session_history(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        l1_hits = await self._l1_cache.get_session_history(session_id, limit)
        if len(l1_hits) >= limit:
            return l1_hits
        try:
            items = await self._redis.lrange(f"session:{session_id}:events", -limit, -1)
            return [json.loads(x) for x in items]
        except Exception as e:
            logger.warning(f"Redis get_session_history failed: {e}")
            return l1_hits

    async def get_agent_history(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        l1_hits = await self._l1_cache.get_agent_history(agent_id, limit)
        if len(l1_hits) >= limit:
            return l1_hits
        try:
            items = await self._redis.lrange(f"agent:{agent_id}:events", -limit, -1)
            return [json.loads(x) for x in items]
        except Exception as e:
            logger.warning(f"Redis get_agent_history failed: {e}")
            return l1_hits

    async def get_active_sessions(self) -> list[str]:
        try:
            members = await self._redis.smembers("active_sessions")
            return list(members)
        except Exception:
            return await self._l1_cache.get_active_sessions()

    async def get_active_agents(self) -> list[str]:
        try:
            members = await self._redis.smembers("active_agents")
            return list(members)
        except Exception:
            return await self._l1_cache.get_active_agents()

    async def update_running_stats(
        self, agent_id: str, feature_vector: list[float]
    ) -> tuple[list[float], list[float], int]:
        try:
            res_str = await self._redis.eval(
                self._welford_script, 1, f"agent:{agent_id}:welford", json.dumps(feature_vector)
            )
            data = json.loads(res_str)
            count = data["count"]
            mean = data["mean"]
            m2 = data["m2"]
            variance = [val / (count - 1) if count > 1 else 1.0 for val in m2]
            return mean, variance, count
        except Exception as e:
            logger.warning(f"Redis update_running_stats fallback to L1: {e}")
            return await self._l1_cache.update_running_stats(agent_id, feature_vector)

    async def check_rate_limit(self, agent_id: str, limit: int, window_seconds: int = 60) -> bool:
        if limit <= 0:
            return True
        now = time.time()
        cutoff = now - window_seconds
        key = f"ratelimit:{agent_id}"
        try:
            pipeline = self._redis.pipeline()
            pipeline.zremrangebyscore(key, 0, cutoff)
            pipeline.zcard(key)
            _, count = await pipeline.execute()
            if count >= limit:
                return False
            pipeline = self._redis.pipeline()
            pipeline.zadd(key, {str(now): now})
            pipeline.expire(key, window_seconds + 5)
            await pipeline.execute()
            return True
        except Exception as e:
            logger.warning(f"Redis check_rate_limit fallback to L1: {e}")
            return await self._l1_cache.check_rate_limit(agent_id, limit, window_seconds)

    async def health_check(self) -> dict[str, Any]:
        try:
            await self._redis.ping()
            sessions = await self.get_active_sessions()
            agents = await self.get_active_agents()
            return {
                "status": "healthy",
                "backend": "redis",
                "redis_url": self.redis_url,
                "active_sessions": len(sessions),
                "active_agents": len(agents),
            }
        except Exception as e:
            return {
                "status": "degraded",
                "backend": "redis",
                "error": str(e),
            }

    async def close(self) -> None:
        await self._l1_cache.close()
        try:
            await self._redis.aclose()
        except Exception as e:
            logger.debug(f"Redis aclose error: {e}")


def get_storage_backend(redis_url: str | None = None) -> StateBackend:
    """Factory creating appropriate storage backend."""
    url = redis_url if redis_url is not None else settings.redis_url
    if url and url.strip():
        try:
            return RedisBackend(url.strip())
        except Exception as e:
            logger.error(
                f"Failed to initialize RedisBackend at {url}, falling back to InMemoryBackend: {e}"
            )
            return InMemoryBackend()
    return InMemoryBackend()
