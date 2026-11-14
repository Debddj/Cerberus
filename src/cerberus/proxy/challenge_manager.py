from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Sequence
from enum import Enum
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from cerberus.config import settings
from cerberus.proxy.models import EventDecision, ToolCallEvent

logger = logging.getLogger("cerberus.challenge_manager")


class ChallengeError(Exception):
    """Base exception for challenge-related failures."""


class ChallengeNotFoundError(ChallengeError):
    """Raised when a challenge ID cannot be located."""


class ChallengeExpiredError(ChallengeError):
    """Raised when an operation is attempted on an expired challenge."""


class InvalidChallengeStateError(ChallengeError):
    """Raised when an operation is invalid for current challenge state."""


class StepUpAuthError(ChallengeError):
    """Raised when step-up authentication or bearer auth verification fails."""


class ChallengeStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ChallengeRequest(BaseModel):
    """Encapsulates a human operator challenge for intercepted tool calls."""

    challenge_id: str
    event_id: str
    session_id: str
    agent_id: str
    tool_name: str
    tool_server: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_score: float | None = None
    risk_factors: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    timeout_seconds: float = 60.0
    status: ChallengeStatus = ChallengeStatus.PENDING
    resolved_by: str | None = None
    resolution_reason: str | None = None
    resolved_at: float | None = None
    decision: EventDecision | None = None
    step_up_token: str | None = None

    @property
    def is_expired(self) -> bool:
        return self.status == ChallengeStatus.EXPIRED or time.time() >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "tool_server": self.tool_server,
            "risk_score": self.risk_score,
            "risk_factors": list(self.risk_factors),
            "timestamp": self.created_at,
            "expires_at": self.expires_at,
            "timeout_seconds": self.timeout_seconds,
            "status": self.status.value,
            "parameters": self.parameters,
            "resolved_by": self.resolved_by,
            "resolution_reason": self.resolution_reason,
            "resolved_at": self.resolved_at,
            "decision": self.decision.value if self.decision else None,
            "step_up_token": self.step_up_token,
        }


class StepUpTokenManager:
    """Issues and verifies HMAC-SHA256 step-up authorization tokens for operator actions."""

    def __init__(
        self,
        secret_key: str | None = None,
        allowed_bearer_tokens: Sequence[str] | set[str] | None = None,
    ):
        self.secret_key = (secret_key or settings.hmac_secret_key or secrets.token_hex(32)).strip()
        self.allowed_bearer_tokens: set[str] = {
            t.strip() for t in (allowed_bearer_tokens or []) if t and t.strip()
        }
        if settings.admin_api_token and settings.admin_api_token.strip():
            self.allowed_bearer_tokens.add(settings.admin_api_token.strip())

        # Anti-replay: track single-use consumed step-up tokens
        self._consumed_tokens: set[str] = set()

    def issue_token(
        self,
        challenge_id: str,
        operator_id: str = "operator",
        action: str = "approve",
        ttl_seconds: float = 300,
    ) -> str:
        """Issue an HMAC-signed step-up approval token cryptographically bound to a challenge."""
        now = int(time.time())
        exp = int(now + ttl_seconds)
        nonce = secrets.token_hex(8)
        payload = f"{challenge_id}:{operator_id}:{action}:{now}:{exp}:{nonce}"
        sig = hmac.new(
            self.secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        raw = f"{payload}:{sig}"
        return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")

    def verify_token(
        self,
        token: str,
        expected_challenge_id: str | None = None,
        expected_action: str | None = "approve",
    ) -> tuple[bool, dict[str, Any], str]:
        """Verify step-up token validity, signature, expiry, binding, and replay status."""
        if not token or not token.strip():
            return False, {}, "Missing step-up token"

        clean_token = token.strip()
        if clean_token in self._consumed_tokens:
            return False, {}, "Step-up token has already been consumed (replay attack detected)"

        try:
            raw = base64.urlsafe_b64decode(clean_token.encode("ascii")).decode("utf-8")
            parts = raw.split(":")
            if len(parts) != 7:
                return False, {}, "Malformed step-up token structure"

            challenge_id, operator_id, action, ts_str, exp_str, nonce, signature = parts
            exp = int(float(exp_str))
            timestamp = int(float(ts_str))

            # Recompute and compare signature in constant time
            payload = f"{challenge_id}:{operator_id}:{action}:{ts_str}:{exp_str}:{nonce}"
            expected_sig = hmac.new(
                self.secret_key.encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                return False, {}, "Invalid HMAC-SHA256 signature on step-up token"

            if time.time() > exp:
                return False, {}, "Step-up token expired"

            if expected_challenge_id and challenge_id != expected_challenge_id:
                return (
                    False,
                    {},
                    f"Token bound to challenge '{challenge_id}', mismatch with '{expected_challenge_id}'",
                )

            if expected_action and action != expected_action:
                return (
                    False,
                    {},
                    f"Token bound to action '{action}', mismatch with expected '{expected_action}'",
                )

            payload_data = {
                "challenge_id": challenge_id,
                "operator_id": operator_id,
                "action": action,
                "timestamp": timestamp,
                "expires_at": exp,
                "nonce": nonce,
            }
            return True, payload_data, "Token verified successfully"

        except Exception as e:
            return False, {}, f"Step-up token decoding error: {e}"

    def consume_token(self, token: str) -> None:
        """Mark a token as consumed to prevent replay attacks."""
        if token and token.strip():
            self._consumed_tokens.add(token.strip())

    def is_token_consumed(self, token: str) -> bool:
        return bool(token and token.strip() in self._consumed_tokens)

    def verify_bearer_token(self, bearer_token: str | None) -> bool:
        """Verify operator bearer authorization header against registered administrative keys."""
        if not bearer_token or not bearer_token.strip():
            return False
        clean = bearer_token.strip()
        if clean.lower().startswith("bearer "):
            clean = clean[7:].strip()
        for allowed in self.allowed_bearer_tokens:
            if hmac.compare_digest(clean, allowed):
                return True
        return False

    def validate_approval_credentials(
        self,
        challenge_id: str,
        step_up_token: str | None = None,
        bearer_token: str | None = None,
    ) -> tuple[bool, str, str]:
        """Validate operator authorization via bearer token or HMAC step-up token.

        Returns:
            (is_valid, authorized_identity, failure_reason)
        """
        # 1. First check bearer authorization if supplied
        if bearer_token and self.verify_bearer_token(bearer_token):
            return True, "admin:bearer", "Authorized via administrator bearer credential"

        # 2. Check HMAC-signed step-up token
        if step_up_token:
            valid, data, msg = self.verify_token(
                token=step_up_token,
                expected_challenge_id=challenge_id,
                expected_action="approve",
            )
            if valid:
                return True, data.get("operator_id", "operator"), "Authorized via step-up token"
            return False, "", msg

        return (
            False,
            "",
            "Operator approval requires a valid HMAC-signed step-up token or bearer authorization",
        )


class WebhookDispatcher:
    """Dispatches asynchronous webhooks for CHALLENGE events with HMAC-SHA256 signature headers."""

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
        webhook_format: Literal["generic", "slack"] | str = "generic",
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ):
        self.webhook_url = webhook_url.strip() if webhook_url else None
        self.webhook_secret = webhook_secret.strip() if webhook_secret else None
        self.webhook_format = webhook_format.lower().strip()
        self.timeout_seconds = timeout_seconds
        self._custom_client = client

    def format_payload(
        self, challenge: ChallengeRequest, event_type: str = "challenge.created"
    ) -> dict[str, Any]:
        """Format event payload for Slack or generic JSON recipients."""
        is_slack = self.webhook_format == "slack" or (
            self.webhook_url and "slack.com" in self.webhook_url
        )
        if is_slack:
            return self.build_slack_payload(challenge)
        return self.build_generic_payload(challenge, event_type=event_type)

    def build_generic_payload(
        self, challenge: ChallengeRequest, event_type: str = "challenge.created"
    ) -> dict[str, Any]:
        """Standard JSON webhook payload with challenge metadata and step-up token."""
        return {
            "event": event_type,
            "challenge_id": challenge.challenge_id,
            "event_id": challenge.event_id,
            "session_id": challenge.session_id,
            "agent_id": challenge.agent_id,
            "tool_name": challenge.tool_name,
            "tool_server": challenge.tool_server,
            "parameters": challenge.parameters,
            "risk_score": challenge.risk_score,
            "risk_factors": list(challenge.risk_factors),
            "step_up_token": challenge.step_up_token,
            "timeout_seconds": challenge.timeout_seconds,
            "expires_at": challenge.expires_at,
            "created_at": challenge.created_at,
            "status": challenge.status.value,
        }

    def build_slack_payload(self, challenge: ChallengeRequest) -> dict[str, Any]:
        """Rich Slack Block Kit payload with alert header and challenge details."""
        risk_str = f"{challenge.risk_score:.2f}" if challenge.risk_score is not None else "N/A"
        factors_str = ", ".join(challenge.risk_factors) if challenge.risk_factors else "None"
        params_str = json.dumps(challenge.parameters, indent=2, sort_keys=True)
        if len(params_str) > 1000:
            params_str = params_str[:997] + "..."

        return {
            "text": (
                f"⚠️ Cerberus Step-Up Auth Challenge: Tool '{challenge.tool_name}' "
                f"invoked by agent '{challenge.agent_id}' requires operator approval."
            ),
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ Cerberus Step-Up Auth Challenge",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Challenge ID:*\n`{challenge.challenge_id}`"},
                        {"type": "mrkdwn", "text": f"*Agent ID:*\n`{challenge.agent_id}`"},
                        {
                            "type": "mrkdwn",
                            "text": f"*Tool:*\n`{challenge.tool_name}` ({challenge.tool_server})",
                        },
                        {"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk_str}`"},
                        {"type": "mrkdwn", "text": f"*Risk Factors:*\n{factors_str}"},
                        {
                            "type": "mrkdwn",
                            "text": f"*Timeout:*\n`{int(challenge.timeout_seconds)}s`",
                        },
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Approval Step-Up Token:*\n`{challenge.step_up_token or 'N/A'}`",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Parameters:*\n```{params_str}```",
                    },
                },
            ],
        }

    def sign_payload(self, payload_bytes: bytes) -> dict[str, str]:
        """Sign webhook payload with HMAC-SHA256 headers."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "Cerberus-Webhook-Dispatcher/1.0",
        }
        if self.webhook_secret:
            timestamp = str(int(time.time()))
            # Standard signature over raw body bytes
            signature = hmac.new(
                self.webhook_secret.encode("utf-8"),
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Cerberus-Signature"] = f"sha256={signature}"
            headers["X-Cerberus-Timestamp"] = timestamp
        return headers

    @staticmethod
    def verify_signature(
        payload_bytes: bytes,
        signature_header: str,
        secret: str,
        timestamp_header: str | None = None,
        max_age_seconds: float = 300.0,
    ) -> tuple[bool, str]:
        """Cryptographically verify an incoming HMAC-SHA256 webhook signature header."""
        if not signature_header or not signature_header.strip():
            return False, "Missing signature header"
        if not secret or not secret.strip():
            return False, "Missing verification secret"

        # Check timestamp freshness if provided
        if timestamp_header:
            try:
                ts = float(timestamp_header.strip())
                if abs(time.time() - ts) > max_age_seconds:
                    return (
                        False,
                        f"Timestamp drift exceeds maximum allowable window ({max_age_seconds}s)",
                    )
            except ValueError:
                return False, "Malformed timestamp header"

        clean_sig = signature_header.strip()
        if clean_sig.startswith("sha256="):
            clean_sig = clean_sig[7:].strip()

        expected_sig = hmac.new(
            secret.strip().encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(clean_sig, expected_sig):
            return False, "HMAC-SHA256 signature verification failed"

        return True, "Signature verified successfully"

    async def dispatch(
        self,
        challenge: ChallengeRequest,
        event_type: str = "challenge.created",
    ) -> bool:
        """Deliver the webhook event to the configured external webhook URL."""
        if not self.webhook_url:
            logger.debug("No webhook URL configured; skipping external dispatch")
            return False

        payload_dict = self.format_payload(challenge, event_type=event_type)
        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        headers = self.sign_payload(payload_bytes)

        try:
            if self._custom_client:
                resp = await self._custom_client.post(
                    self.webhook_url,
                    content=payload_bytes,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.post(
                        self.webhook_url,
                        content=payload_bytes,
                        headers=headers,
                    )
            if resp.is_success:
                logger.info(
                    "Successfully dispatched challenge webhook to %s for %s",
                    self.webhook_url,
                    challenge.challenge_id,
                )
                return True
            else:
                logger.warning(
                    "Webhook target %s returned HTTP status %d: %s",
                    self.webhook_url,
                    resp.status_code,
                    resp.text,
                )
                return False
        except Exception as e:
            logger.error("Failed to dispatch challenge webhook to %s: %s", self.webhook_url, e)
            return False


class ChallengeManager:
    """Coordinates operator challenge lifecycles, webhooks, step-up auth, and fail-closed timeouts."""

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
        webhook_format: Literal["generic", "slack"] | str = "generic",
        default_timeout: float = 60.0,
        bearer_tokens: Sequence[str] | set[str] | None = None,
        token_secret: str | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        self.default_timeout = (
            default_timeout
            if default_timeout is not None
            else getattr(settings, "challenge_timeout_seconds", 60.0)
        )
        self.challenges: dict[str, ChallengeRequest] = {}
        self._futures: dict[str, asyncio.Future[EventDecision]] = {}

        self.token_manager = StepUpTokenManager(
            secret_key=token_secret or settings.hmac_secret_key,
            allowed_bearer_tokens=bearer_tokens,
        )
        self.dispatcher = WebhookDispatcher(
            webhook_url=webhook_url or getattr(settings, "challenge_webhook_url", None),
            webhook_secret=webhook_secret or getattr(settings, "challenge_webhook_secret", None),
            webhook_format=webhook_format
            or getattr(settings, "challenge_webhook_format", "generic"),
            client=client,
        )

    def issue_step_up_token(
        self,
        challenge_id: str,
        action: str = "approve",
        ttl_seconds: float = 300,
    ) -> str:
        """Issue an HMAC-signed step-up token for authorizing a challenge."""
        return self.token_manager.issue_token(
            challenge_id=challenge_id,
            action=action,
            ttl_seconds=ttl_seconds,
        )

    @property
    def challenges_dict(self) -> dict[str, dict[str, Any]]:
        """Dictionary representation of all challenges for backwards compatibility with engine."""
        self.sweep_expired()
        return {cid: c.to_dict() for cid, c in self.challenges.items()}

    def sweep_expired(self) -> list[str]:
        """Deterministically mark and fail-closed any challenges past their timeout."""
        now = time.time()
        expired_ids = []
        for cid, chg in self.challenges.items():
            if chg.status == ChallengeStatus.PENDING and now >= chg.expires_at:
                chg.status = ChallengeStatus.EXPIRED
                chg.decision = EventDecision.BLOCK
                chg.resolved_by = "system:timeout"
                chg.resolution_reason = (
                    f"Challenge timed out after {chg.timeout_seconds}s (deterministic fail-closed)"
                )
                chg.resolved_at = now
                if cid in self._futures and not self._futures[cid].done():
                    self._futures[cid].set_result(EventDecision.BLOCK)
                expired_ids.append(cid)
        return expired_ids

    def create_challenge(
        self,
        event: ToolCallEvent | dict[str, Any],
        timeout_seconds: float | None = None,
        auto_dispatch: bool = True,
    ) -> ChallengeRequest:
        """Create a new human challenge, issue step-up token, and initiate webhook dispatch."""
        now = time.time()
        effective_timeout = (
            float(timeout_seconds) if timeout_seconds is not None else float(self.default_timeout)
        )
        expires_at = now + effective_timeout

        # Extract fields from ToolCallEvent or dictionary
        if isinstance(event, ToolCallEvent):
            event_id = event.event_id
            session_id = event.session_id
            agent_id = event.agent_id
            tool_name = event.tool_name
            tool_server = event.tool_server
            parameters = dict(event.parameters)
            risk_score = event.risk_score
            risk_factors = list(event.risk_factors)
        else:
            event_id = str(event.get("event_id", secrets.token_hex(8)))
            session_id = str(event.get("session_id", "unknown_session"))
            agent_id = str(event.get("agent_id", "unknown_agent"))
            tool_name = str(event.get("tool_name", "unknown_tool"))
            tool_server = str(event.get("tool_server", "default"))
            parameters = dict(event.get("parameters", {}))
            risk_score = event.get("risk_score")
            risk_factors = list(event.get("risk_factors", []))

        challenge_id = f"chg_{secrets.token_hex(6)}"

        # Issue HMAC step-up token for operator approval
        step_up_token = self.token_manager.issue_token(
            challenge_id=challenge_id,
            operator_id="operator",
            action="approve",
            ttl_seconds=int(effective_timeout + 300),
        )

        challenge = ChallengeRequest(
            challenge_id=challenge_id,
            event_id=event_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_server=tool_server,
            parameters=parameters,
            risk_score=risk_score,
            risk_factors=risk_factors,
            created_at=now,
            expires_at=expires_at,
            timeout_seconds=effective_timeout,
            status=ChallengeStatus.PENDING,
            step_up_token=step_up_token,
        )

        try:
            loop = asyncio.get_running_loop()
            self._futures[challenge_id] = loop.create_future()
        except RuntimeError:
            # Handle sync or out-of-loop contexts
            loop = None

        self.challenges[challenge_id] = challenge

        if auto_dispatch and self.dispatcher.webhook_url and loop and loop.is_running():
            asyncio.create_task(self.dispatcher.dispatch(challenge, event_type="challenge.created"))

        return challenge

    async def wait_for_resolution(
        self,
        challenge_id: str,
        timeout_seconds: float | None = None,
    ) -> tuple[EventDecision, ChallengeRequest]:
        """Wait for operator resolution. Deterministically fails closed (BLOCK) upon timeout."""
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            raise ChallengeNotFoundError(f"Challenge '{challenge_id}' not found")

        # Fast-path check: already resolved or expired
        if challenge.status == ChallengeStatus.APPROVED:
            return EventDecision.ALLOW, challenge
        if challenge.status in (ChallengeStatus.REJECTED, ChallengeStatus.EXPIRED):
            return EventDecision.BLOCK, challenge

        now = time.time()
        remaining_time = max(0.0, challenge.expires_at - now)
        if timeout_seconds is not None:
            remaining_time = min(remaining_time, float(timeout_seconds))

        if remaining_time <= 0 or challenge.is_expired:
            # Strict deterministic fail-closed
            challenge.status = ChallengeStatus.EXPIRED
            challenge.decision = EventDecision.BLOCK
            challenge.resolved_by = "system:timeout"
            challenge.resolution_reason = f"Challenge timed out after {challenge.timeout_seconds}s (deterministic fail-closed)"
            challenge.resolved_at = time.time()
            if challenge_id in self._futures and not self._futures[challenge_id].done():
                self._futures[challenge_id].set_result(EventDecision.BLOCK)
            return EventDecision.BLOCK, challenge

        loop = asyncio.get_running_loop()
        future = self._futures.get(challenge_id)
        if future is None:
            future = loop.create_future()
            self._futures[challenge_id] = future

        try:
            decision = await asyncio.wait_for(asyncio.shield(future), timeout=remaining_time)
            return decision, challenge
        except TimeoutError:
            # STRICT FAIL-CLOSED TIMEOUT: Deterministic BLOCK
            challenge.status = ChallengeStatus.EXPIRED
            challenge.decision = EventDecision.BLOCK
            challenge.resolved_by = "system:timeout"
            challenge.resolution_reason = f"Challenge timed out after {challenge.timeout_seconds}s (deterministic fail-closed)"
            challenge.resolved_at = time.time()
            if not future.done():
                future.set_result(EventDecision.BLOCK)
            return EventDecision.BLOCK, challenge

    def resolve_challenge(
        self,
        challenge_id: str,
        action: str,
        operator_id: str = "secops-operator",
        reason: str = "",
        step_up_token: str | None = None,
        bearer_token: str | None = None,
        resolved_by: str | None = None,
    ) -> ChallengeRequest:
        """Resolve a pending human challenge with required step-up auth or bearer verification.

        Args:
            challenge_id: ID of the challenge to resolve.
            action: 'approve' or 'reject'.
            operator_id: Identity of the operator resolving the challenge.
            reason: Operator rationale for resolution.
            step_up_token: HMAC-SHA256 signed step-up token bound to this challenge.
            bearer_token: Administrator bearer token (e.g. from Authorization header).
            resolved_by: Alias for operator_id.

        Raises:
            ChallengeNotFoundError: Challenge does not exist.
            ChallengeExpiredError: Challenge has already expired and failed closed.
            InvalidChallengeStateError: Challenge is already approved or rejected.
            StepUpAuthError: Operator approval attempted without valid step-up auth or bearer token.
        """
        if resolved_by:
            operator_id = resolved_by
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            raise ChallengeNotFoundError(f"Challenge '{challenge_id}' not found")

        # Check expiration first
        if challenge.is_expired or challenge.status == ChallengeStatus.EXPIRED:
            challenge.status = ChallengeStatus.EXPIRED
            challenge.decision = EventDecision.BLOCK
            if challenge_id in self._futures and not self._futures[challenge_id].done():
                self._futures[challenge_id].set_result(EventDecision.BLOCK)
            raise ChallengeExpiredError(
                "Challenge has expired and failed closed; resolution rejected"
            )

        if challenge.status != ChallengeStatus.PENDING:
            raise InvalidChallengeStateError(
                f"Challenge '{challenge_id}' is already resolved with status '{challenge.status.value}'"
            )

        norm_action = action.lower().strip()
        now = time.time()

        if norm_action == "approve":
            # STEP-UP AUTH REQUIREMENT: Operator approval requires HMAC step-up token or bearer authorization
            is_valid, auth_identity, fail_msg = self.token_manager.validate_approval_credentials(
                challenge_id=challenge_id,
                step_up_token=step_up_token,
                bearer_token=bearer_token,
            )
            if not is_valid:
                raise StepUpAuthError(f"Approval rejected: {fail_msg}")

            # Mark step-up token as consumed to prevent replay attacks
            if step_up_token:
                self.token_manager.consume_token(step_up_token)

            challenge.status = ChallengeStatus.APPROVED
            challenge.decision = EventDecision.ALLOW
            challenge.resolved_by = (
                operator_id if operator_id != "secops-operator" else auth_identity
            )
            challenge.resolution_reason = reason or "Operator approved via step-up authentication"
            challenge.resolved_at = now

            if challenge_id in self._futures and not self._futures[challenge_id].done():
                self._futures[challenge_id].set_result(EventDecision.ALLOW)

        elif norm_action == "reject":
            challenge.status = ChallengeStatus.REJECTED
            challenge.decision = EventDecision.BLOCK
            challenge.resolved_by = operator_id
            challenge.resolution_reason = reason or "Operator rejected intercepted tool execution"
            challenge.resolved_at = now

            if challenge_id in self._futures and not self._futures[challenge_id].done():
                self._futures[challenge_id].set_result(EventDecision.BLOCK)

        else:
            raise ValueError(
                f"Unsupported challenge resolution action '{action}' (expected 'approve' or 'reject')"
            )

        # Dispatch resolution event webhook if configured
        if self.dispatcher.webhook_url:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    asyncio.create_task(
                        self.dispatcher.dispatch(challenge, event_type=f"challenge.{norm_action}d")
                    )
            except RuntimeError:
                pass

        return challenge

    async def create_and_wait(
        self,
        event: ToolCallEvent | dict[str, Any],
        timeout_seconds: float | None = None,
        auto_dispatch: bool = True,
    ) -> tuple[EventDecision, ChallengeRequest]:
        """Convenience method to register a challenge and wait for operator resolution."""
        challenge = self.create_challenge(
            event=event,
            timeout_seconds=timeout_seconds,
            auto_dispatch=auto_dispatch,
        )
        return await self.wait_for_resolution(
            challenge_id=challenge.challenge_id,
            timeout_seconds=timeout_seconds,
        )

    def get_challenge(self, challenge_id: str) -> ChallengeRequest | None:
        """Get challenge by ID, sweeping expiration state."""
        self.sweep_expired()
        return self.challenges.get(challenge_id)

    def list_challenges(self, status: ChallengeStatus | None = None) -> list[ChallengeRequest]:
        """List operator challenges, sweeping expiration state first."""
        self.sweep_expired()
        items = list(self.challenges.values())
        if status:
            items = [c for c in items if c.status == status]
        return items
