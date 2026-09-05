from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from collections import defaultdict, deque

from cerberus.config import settings

logger = logging.getLogger("cerberus.auth")


class HMACAuthenticator:
    """Issues and verifies HMAC-SHA256 identity tokens for agents."""

    def __init__(self, secret_key: str | None = None):
        self.secret_key = (secret_key or settings.hmac_secret_key).strip()
        if not self.secret_key:
            # Auto-generate local secret key if unconfigured
            self.secret_key = self._get_or_create_key()

    def _get_or_create_key(self) -> str:
        key_file = "cerberus_hmac.key"
        if os.path.exists(key_file):
            with open(key_file, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        generated = secrets.token_hex(32)
        try:
            with open(key_file, "w", encoding="utf-8") as f:
                f.write(generated)
            logger.info("Generated new HMAC authentication secret at %s", key_file)
        except Exception as e:
            logger.warning("Could not persist HMAC key file: %s", e)
        return generated

    def issue_token(self, agent_id: str, ttl_seconds: int = 86400) -> str:
        """Issue an HMAC-signed token with timestamp and expiry."""
        now = int(time.time())
        exp = now + ttl_seconds
        payload = f"{agent_id}.{now}.{exp}"
        signature = hmac.new(
            self.secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        raw_token = f"{payload}.{signature}"
        return base64.urlsafe_b64encode(raw_token.encode("utf-8")).decode("ascii")

    def verify_token(self, token: str) -> tuple[bool, str, str]:
        """Verify token authenticity and freshness.

        Returns:
            (is_valid, agent_id, reason)
        """
        if not token:
            return False, "", "Missing authentication token"

        try:
            decoded = base64.urlsafe_b64decode(token.strip().encode("ascii")).decode("utf-8")
            parts = decoded.split(".")
            if len(parts) != 4:
                return False, "", "Malformed token structure"

            agent_id, ts_str, exp_str, signature = parts
            exp = int(exp_str)

            # Recompute expected signature
            payload = f"{agent_id}.{ts_str}.{exp_str}"
            expected_sig = hmac.new(
                self.secret_key.encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                return False, agent_id, "Invalid HMAC signature"

            if time.time() > exp:
                return False, agent_id, "Token expired"

            return True, agent_id, "Token verified"

        except Exception as e:
            return False, "", f"Token verification error: {e}"


class TenantRateLimiter:
    """Sliding-window per-tenant call rate limiter."""

    def __init__(self, default_limit: int | None = None):
        self.default_limit = default_limit or settings.rate_limit_per_minute
        # agent_id -> deque of timestamps in seconds
        self._call_history: dict[str, deque[float]] = defaultdict(deque)

    def check_rate_limit(
        self, agent_id: str, custom_limit: int | None = None
    ) -> tuple[bool, int, float]:
        """Check if an agent call is within rate quota.

        Returns:
            (allowed, remaining_quota, reset_seconds)
        """
        limit = custom_limit or self.default_limit
        now = time.time()
        window_start = now - 60.0
        q = self._call_history[agent_id]

        # Evict timestamps older than 60s
        while q and q[0] < window_start:
            q.popleft()

        if len(q) >= limit:
            oldest = q[0]
            reset_seconds = max(0.0, 60.0 - (now - oldest))
            return False, 0, round(reset_seconds, 2)

        q.append(now)
        remaining = max(0, limit - len(q))
        return True, remaining, 0.0
