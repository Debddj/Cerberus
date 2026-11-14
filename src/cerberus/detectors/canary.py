"""Cerberus Honeytokens and Canary Credentials (ASI10 Tamper Defense).

Provides deterministic honeytoken generation, decoy credentials management
(.env.canary, AWS secrets, decoy database rows/tokens), and an ultra-fast O(1)
canary detector that scans tool call arguments, SQL queries, and egress parameters
for any registered honeytoken. Detection triggers instant 1.0 confidence compromise
detection, immediate BLOCK, session QUARANTINE (ASI10), and tamper alert logging.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
import urllib.parse
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from cerberus.proxy.models import EventDecision, ToolCallEvent

logger = logging.getLogger("cerberus.canary")

# Standard canary prefix used across Cerberus honeytokens
CANARY_PREFIX = "CERBERUS_CANARY_"

# Fast extraction regex for any candidate Cerberus honeytoken
CANARY_CANDIDATE_REGEX = re.compile(r"CERBERUS_CANARY_[A-Za-z0-9_\-]+")

# SQL string literal extraction regex (single or double quotes)
SQL_STRING_LITERAL_REGEX = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")


class CanaryType(str, Enum):
    """Classification of honeytoken / decoy credential types."""

    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    DATABASE_ROW = "database_row"
    DATABASE_TOKEN = "database_token"
    DATABASE_PASSWORD = "database_password"
    ENV_VAR = "env_var"
    SQL_TOKEN = "sql_token"
    GENERIC = "generic"


@dataclass(frozen=True)
class CanaryToken:
    """Immutable representation of a registered honeytoken."""

    token: str
    token_type: CanaryType
    label: str
    description: str = ""
    seed: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def mask_token(self) -> str:
        """Safely mask token for audit logging and diagnostics without leaking secrets."""
        if len(self.token) <= 8:
            return "***"
        return f"{self.token[:8]}...{self.token[-4:]}"


@dataclass
class CanaryEnvBundle:
    """Represents a generated .env.canary file and its registered tokens."""

    filename: str
    variables: dict[str, str]
    content: str
    tokens: list[CanaryToken]

    def to_env_string(self) -> str:
        return self.content


@dataclass
class CanaryDbBundle:
    """Represents a decoy database row / table insert and its registered tokens."""

    table_name: str
    row: dict[str, Any]
    sql_insert: str
    tokens: list[CanaryToken]


@dataclass
class CanaryScanResult:
    """Result of scanning an event, parameters, or query for canary tokens."""

    detected: bool
    confidence: float = 0.0
    risk_score: float = 0.0
    action: str = "ALLOW"
    decision: EventDecision = EventDecision.ALLOW
    quarantine_required: bool = False
    threat_category: str = "ASI10: Honeytoken Compromise / Rogue Execution"
    matched_tokens: list[CanaryToken] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    reason: str = ""
    tamper_alert: dict[str, Any] | None = None


class HoneytokenGenerator:
    """Deterministic generator for honeytokens and decoy credentials."""

    @staticmethod
    def derive_secret(seed: str | None, purpose: str, length: int = 32) -> str:
        """Derive deterministic hex secret using HMAC-SHA256, or random if seed is None."""
        if seed is not None:
            derived = hmac.new(
                seed.encode("utf-8"), purpose.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            return derived[:length]
        return secrets.token_hex(max(length // 2, 8))[:length]

    @classmethod
    def generate_aws_credentials(
        cls, seed: str | None = None, label: str = "aws_canary"
    ) -> tuple[CanaryToken, CanaryToken]:
        """Generate deterministic AWS Access Key ID and Secret Access Key.

        Produces:
        - Access Key ID: CERBERUS_CANARY_AWS_AKIA<16 uppercase chars>
        - Secret Key: CERBERUS_CANARY_AWS_SECRET_<32 chars>
        """
        ak_suffix = cls.derive_secret(seed, f"{label}:aws_access_key", length=16).upper()
        access_key_str = f"{CANARY_PREFIX}AWS_AKIA{ak_suffix}"

        sk_suffix = cls.derive_secret(seed, f"{label}:aws_secret_key", length=32)
        secret_key_str = f"{CANARY_PREFIX}AWS_SECRET_{sk_suffix}"

        ak_token = CanaryToken(
            token=access_key_str,
            token_type=CanaryType.AWS_ACCESS_KEY,
            label=f"{label}_access_key",
            description="Decoy AWS Access Key ID",
            seed=seed,
            metadata={"aws_format": "AKIA", "key_type": "access_key"},
        )
        sk_token = CanaryToken(
            token=secret_key_str,
            token_type=CanaryType.AWS_SECRET_KEY,
            label=f"{label}_secret_key",
            description="Decoy AWS Secret Access Key",
            seed=seed,
            metadata={"key_type": "secret_key"},
        )
        return ak_token, sk_token

    @classmethod
    def generate_api_key(
        cls, seed: str | None = None, label: str = "api_key_canary", prefix: str = "API_KEY"
    ) -> CanaryToken:
        """Generate deterministic generic API key."""
        secret = cls.derive_secret(seed, f"{label}:{prefix}", length=32)
        token_str = f"{CANARY_PREFIX}{prefix}_{secret}"
        return CanaryToken(
            token=token_str,
            token_type=CanaryType.API_KEY,
            label=label,
            description="Decoy API Key",
            seed=seed,
            metadata={"prefix": prefix},
        )

    @classmethod
    def generate_bearer_token(
        cls, seed: str | None = None, label: str = "bearer_canary"
    ) -> CanaryToken:
        """Generate deterministic Bearer token."""
        secret = cls.derive_secret(seed, f"{label}:bearer", length=36)
        token_str = f"{CANARY_PREFIX}BEARER_{secret}"
        return CanaryToken(
            token=token_str,
            token_type=CanaryType.BEARER_TOKEN,
            label=label,
            description="Decoy Bearer Authorization Token",
            seed=seed,
        )

    @classmethod
    def generate_env_canary(
        cls, seed: str | None = None, filename: str = ".env.canary", label: str = "env_canary"
    ) -> CanaryEnvBundle:
        """Generate a complete decoy .env.canary file with deterministic credentials."""
        aws_ak, aws_sk = cls.generate_aws_credentials(seed=seed, label=f"{label}_aws")
        api_key = cls.generate_api_key(seed=seed, label=f"{label}_api")
        db_pass = cls.derive_secret(seed, f"{label}:db_pass", length=24)
        db_pass_token_str = f"{CANARY_PREFIX}DB_PASS_{db_pass}"
        db_pass_token = CanaryToken(
            token=db_pass_token_str,
            token_type=CanaryType.DATABASE_PASSWORD,
            label=f"{label}_db_pass",
            description="Decoy Database Password",
            seed=seed,
        )

        openai_sec = cls.derive_secret(seed, f"{label}:openai", length=32)
        openai_token_str = f"{CANARY_PREFIX}OPENAI_sk-{openai_sec}"
        openai_token = CanaryToken(
            token=openai_token_str,
            token_type=CanaryType.API_KEY,
            label=f"{label}_openai",
            description="Decoy OpenAI Secret Key",
            seed=seed,
        )

        stripe_sec = cls.derive_secret(seed, f"{label}:stripe", length=28)
        stripe_token_str = f"{CANARY_PREFIX}STRIPE_sk_live_{stripe_sec}"
        stripe_token = CanaryToken(
            token=stripe_token_str,
            token_type=CanaryType.API_KEY,
            label=f"{label}_stripe",
            description="Decoy Stripe Secret Key",
            seed=seed,
        )

        db_url = (
            f"postgresql://canary_admin:{db_pass_token_str}@internal-db.corp.local:5432/production"
        )
        db_url_token = CanaryToken(
            token=db_url,
            token_type=CanaryType.DATABASE_TOKEN,
            label=f"{label}_db_url",
            description="Decoy Full Database Connection URL",
            seed=seed,
        )

        variables = {
            "AWS_ACCESS_KEY_ID": aws_ak.token,
            "AWS_SECRET_ACCESS_KEY": aws_sk.token,
            "DATABASE_URL": db_url,
            "INTERNAL_API_KEY": api_key.token,
            "OPENAI_API_KEY": openai_token.token,
            "STRIPE_SECRET_KEY": stripe_token.token,
        }

        env_lines = [
            "# ===================================================================",
            f"# Cerberus Canary Decoy Environment File ({filename})",
            "# WARNING: Credentials below are active honeytokens.",
            "# Any use or egress of these values triggers instant ASI10 Quarantine.",
            "# ===================================================================",
        ]
        for k, v in variables.items():
            env_lines.append(f"{k}={v}")
        env_content = "\n".join(env_lines) + "\n"

        tokens = [aws_ak, aws_sk, api_key, db_pass_token, openai_token, stripe_token, db_url_token]
        return CanaryEnvBundle(
            filename=filename, variables=variables, content=env_content, tokens=tokens
        )

    @classmethod
    def generate_db_decoy_row(
        cls, table_name: str = "users", seed: str | None = None, label: str = "db_canary"
    ) -> CanaryDbBundle:
        """Generate deterministic decoy database table row and SQL insert statement."""
        token_secret = cls.derive_secret(seed, f"{label}:{table_name}:token", length=32)
        db_token_str = f"{CANARY_PREFIX}DB_TOKEN_{token_secret}"
        db_token = CanaryToken(
            token=db_token_str,
            token_type=CanaryType.DATABASE_TOKEN,
            label=f"{label}_{table_name}_token",
            description=f"Decoy token in {table_name} table",
            seed=seed,
            metadata={"table": table_name},
        )

        if table_name == "users":
            row = {
                "id": 999999,
                "username": "honey_admin",
                "email": "canary.decoy@corp.internal",
                "api_token": db_token_str,
                "role": "superadmin",
                "is_active": True,
            }
            sql_insert = (
                f"INSERT INTO users (id, username, email, api_token, role, is_active) "
                f"VALUES ({row['id']}, '{row['username']}', '{row['email']}', "
                f"'{row['api_token']}', '{row['role']}', true);"
            )
        elif table_name == "service_accounts":
            row = {
                "account_id": "sa-canary-vault-01",
                "name": "canary-vault-backup",
                "secret_key": db_token_str,
                "scopes": "admin:all",
            }
            sql_insert = (
                f"INSERT INTO service_accounts (account_id, name, secret_key, scopes) "
                f"VALUES ('{row['account_id']}', '{row['name']}', '{row['secret_key']}', '{row['scopes']}');"
            )
        else:
            row = {
                "id": 999999,
                "token_id": f"tok_{seed or 'canary'}",
                "secret": db_token_str,
            }
            sql_insert = (
                f"INSERT INTO {table_name} (id, token_id, secret) "
                f"VALUES ({row['id']}, '{row['token_id']}', '{row['secret']}');"
            )

        return CanaryDbBundle(
            table_name=table_name, row=row, sql_insert=sql_insert, tokens=[db_token]
        )


class CanaryRegistry:
    """Thread-safe registry for active honeytokens providing O(1) hash set lookups."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: dict[str, CanaryToken] = {}
        self._token_set: set[str] = set()
        self._tokens_by_type: dict[CanaryType, list[CanaryToken]] = {}
        self._tokens_by_label: dict[str, list[CanaryToken]] = {}
        self._custom_tokens: dict[str, CanaryToken] = {}
        self._custom_regex: re.Pattern | None = None
        self._custom_regex_dirty: bool = False

    def register(
        self,
        token: CanaryToken | str,
        token_type: CanaryType | str = CanaryType.GENERIC,
        label: str = "custom_canary",
        description: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> CanaryToken:
        """Register a honeytoken into the O(1) lookup set."""
        if isinstance(token, str):
            t_type = CanaryType(token_type) if isinstance(token_type, str) else token_type
            token_obj = CanaryToken(
                token=token,
                token_type=t_type,
                label=label,
                description=description,
                metadata=metadata or {},
            )
        else:
            token_obj = token

        with self._lock:
            token_str = token_obj.token
            self._tokens[token_str] = token_obj
            self._token_set.add(token_str)
            self._tokens_by_type.setdefault(token_obj.token_type, []).append(token_obj)
            self._tokens_by_label.setdefault(token_obj.label, []).append(token_obj)

            if not token_str.startswith(CANARY_PREFIX):
                self._custom_tokens[token_str] = token_obj
                self._custom_regex_dirty = True

        return token_obj

    def register_many(self, tokens: Sequence[CanaryToken | str]) -> list[CanaryToken]:
        """Bulk register multiple honeytokens."""
        registered = []
        with self._lock:
            for t in tokens:
                registered.append(self.register(t))
        return registered

    def unregister(self, token_str: str) -> bool:
        """Remove a honeytoken from the registry."""
        with self._lock:
            token_obj = self._tokens.pop(token_str, None)
            if token_obj is None:
                return False
            self._token_set.discard(token_str)

            type_list = self._tokens_by_type.get(token_obj.token_type, [])
            self._tokens_by_type[token_obj.token_type] = [
                t for t in type_list if t.token != token_str
            ]

            label_list = self._tokens_by_label.get(token_obj.label, [])
            self._tokens_by_label[token_obj.label] = [t for t in label_list if t.token != token_str]

            if token_str in self._custom_tokens:
                del self._custom_tokens[token_str]
                self._custom_regex_dirty = True

            return True

    def get(self, token_str: str) -> CanaryToken | None:
        """O(1) retrieval of a CanaryToken by its exact string."""
        with self._lock:
            return self._tokens.get(token_str)

    def contains(self, token_str: str) -> bool:
        """O(1) exact membership check."""
        with self._lock:
            return token_str in self._token_set

    def __contains__(self, token_str: str) -> bool:
        return self.contains(token_str)

    def __len__(self) -> int:
        with self._lock:
            return len(self._token_set)

    @property
    def has_custom_tokens(self) -> bool:
        with self._lock:
            return len(self._custom_tokens) > 0

    def list_tokens(self) -> list[CanaryToken]:
        """Return a copy of all registered CanaryTokens."""
        with self._lock:
            return list(self._tokens.values())

    def clear(self) -> None:
        """Clear all registered tokens."""
        with self._lock:
            self._tokens.clear()
            self._token_set.clear()
            self._tokens_by_type.clear()
            self._tokens_by_label.clear()
            self._custom_tokens.clear()
            self._custom_regex = None
            self._custom_regex_dirty = False

    def get_custom_regex(self) -> re.Pattern | None:
        """Return compiled regex pattern for arbitrary non-prefixed custom tokens."""
        with self._lock:
            if not self._custom_regex_dirty and self._custom_regex is not None:
                return self._custom_regex

            if not self._custom_tokens:
                self._custom_regex = None
                self._custom_regex_dirty = False
                return None

            sorted_tokens = sorted(self._custom_tokens.keys(), key=len, reverse=True)
            pattern_str = "|".join(re.escape(t) for t in sorted_tokens)
            self._custom_regex = re.compile(pattern_str)
            self._custom_regex_dirty = False
            return self._custom_regex


class CanaryDetector:
    """Ultra-fast O(1) honeytoken detector and ASI10 quarantine enforcer."""

    def __init__(
        self,
        registry: CanaryRegistry | None = None,
        generator: HoneytokenGenerator | None = None,
    ) -> None:
        self.registry = registry or CanaryRegistry()
        self.generator = generator or HoneytokenGenerator()
        self._quarantined_sessions: set[str] = set()
        self._tamper_alerts: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    # -----------------------------------------------------------------------
    # Convenience Decoy Generation + Auto-Registration
    # -----------------------------------------------------------------------

    def create_canary_aws(
        self, seed: str | None = None, label: str = "aws_canary"
    ) -> tuple[CanaryToken, CanaryToken]:
        """Generate and register deterministic AWS decoy credentials."""
        ak, sk = self.generator.generate_aws_credentials(seed=seed, label=label)
        self.registry.register(ak)
        self.registry.register(sk)
        return ak, sk

    def create_canary_api_key(
        self, seed: str | None = None, label: str = "api_key_canary", prefix: str = "API_KEY"
    ) -> CanaryToken:
        """Generate and register deterministic API key."""
        token = self.generator.generate_api_key(seed=seed, label=label, prefix=prefix)
        self.registry.register(token)
        return token

    def create_canary_env(
        self, seed: str | None = None, filename: str = ".env.canary", label: str = "env_canary"
    ) -> CanaryEnvBundle:
        """Generate and register a decoy .env.canary file with credentials."""
        bundle = self.generator.generate_env_canary(seed=seed, filename=filename, label=label)
        self.registry.register_many(bundle.tokens)
        return bundle

    def create_canary_db_row(
        self, table_name: str = "users", seed: str | None = None, label: str = "db_canary"
    ) -> CanaryDbBundle:
        """Generate and register a decoy database table row and SQL insert."""
        bundle = self.generator.generate_db_decoy_row(table_name=table_name, seed=seed, label=label)
        self.registry.register_many(bundle.tokens)
        return bundle

    def register_token(
        self,
        token: CanaryToken | str,
        token_type: str = "custom",
        label: str = "",
    ) -> CanaryToken:
        """Register a canary token directly on the detector registry."""
        return self.registry.register(token, token_type=token_type, label=label)

    # -----------------------------------------------------------------------
    # Quarantine Management (ASI10)
    # -----------------------------------------------------------------------

    def is_session_quarantined(self, session_id: str) -> bool:
        """Check if a session is currently quarantined under ASI10."""
        with self._lock:
            return session_id in self._quarantined_sessions

    def quarantine_session(
        self, session_id: str, reason: str = "", matched_token: CanaryToken | None = None
    ) -> None:
        """Place a session under immediate ASI10 quarantine."""
        with self._lock:
            self._quarantined_sessions.add(session_id)
        logger.warning(
            f"ASI10 Session Quarantine enforced for '{session_id}'. Reason: {reason}. "
            f"Token: {matched_token.mask_token() if matched_token else 'N/A'}"
        )

    def release_quarantine(self, session_id: str) -> bool:
        """Release a session from quarantine (e.g. operator manual override)."""
        with self._lock:
            if session_id in self._quarantined_sessions:
                self._quarantined_sessions.remove(session_id)
                return True
            return False

    @property
    def quarantined_sessions(self) -> set[str]:
        """Return a copy of all active quarantined session IDs."""
        with self._lock:
            return set(self._quarantined_sessions)

    # -----------------------------------------------------------------------
    # Tamper Alert Logging
    # -----------------------------------------------------------------------

    def _record_tamper_alert(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        token: CanaryToken,
        location: str,
    ) -> dict[str, Any]:
        """Construct, log, and persist a structured tamper alert."""
        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "ASI10_TAMPER_ALERT",
            "threat_category": "ASI10: Honeytoken Compromise / Rogue Execution",
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "token_label": token.label,
            "token_type": token.token_type.value,
            "masked_token": token.mask_token(),
            "location": location,
            "action": "BLOCK_AND_QUARANTINE",
            "confidence": 1.0,
            "risk_score": 1.0,
        }
        with self._lock:
            self._tamper_alerts.append(alert)

        logger.critical(
            f"ASI10 TAMPER ALERT: Honeytoken '{token.label}' ({token.token_type.value}) detected! "
            f"Session '{session_id}' by Agent '{agent_id}' calling '{tool_name}' at '{location}'. "
            f"Action: IMMEDIATE BLOCK AND QUARANTINE."
        )
        return alert

    def get_tamper_alerts(self) -> list[dict[str, Any]]:
        """Return a copy of all recorded tamper alerts."""
        with self._lock:
            return list(self._tamper_alerts)

    def clear_tamper_alerts(self) -> None:
        """Clear the tamper alert log."""
        with self._lock:
            self._tamper_alerts.clear()

    # -----------------------------------------------------------------------
    # Ultra-Fast O(1) String & Query Scanner
    # -----------------------------------------------------------------------

    def scan_string(self, text: str) -> list[CanaryToken]:
        """Scan a string for any registered honeytoken using fast O(1) set lookup and candidate extraction."""
        if not text or len(self.registry) == 0:
            return []

        matched: list[CanaryToken] = []

        # 1. Exact O(1) match on the full text
        exact_match = self.registry.get(text)
        if exact_match is not None:
            return [exact_match]

        # 2. Fast O(1) check for standard Cerberus prefix
        if CANARY_PREFIX in text:
            candidates = CANARY_CANDIDATE_REGEX.findall(text)
            for cand in candidates:
                tok = self.registry.get(cand)
                if tok is not None and tok not in matched:
                    matched.append(tok)
            if matched:
                return matched

        # 3. SQL literal extraction: check literals in single or double quotes in O(1) per literal
        if "'" in text or '"' in text:
            literals = SQL_STRING_LITERAL_REGEX.findall(text)
            for lit in literals:
                cleaned = lit[1:-1].replace("''", "'").replace('""', '"')
                tok = self.registry.get(cleaned)
                if tok is not None and tok not in matched:
                    matched.append(tok)
            if matched:
                return matched

        # 4. Check custom non-prefixed tokens only if custom tokens are present
        if self.registry.has_custom_tokens:
            custom_re = self.registry.get_custom_regex()
            if custom_re is not None:
                for m in custom_re.finditer(text):
                    hit_str = m.group(0)
                    tok = self.registry.get(hit_str)
                    if tok is not None and tok not in matched:
                        matched.append(tok)

        return matched

    def scan_sql_query(
        self, query: str, location: str = "sql_query"
    ) -> list[tuple[CanaryToken, str]]:
        """Scan a SQL query for any registered honeytoken."""
        tokens = self.scan_string(query)
        return [(t, location) for t in tokens]

    def scan_egress_parameters(
        self, destination: str | None, parameters: dict[str, Any]
    ) -> list[tuple[CanaryToken, str]]:
        """Scan egress destination and egress request parameters/payloads for canary tokens."""
        hits: list[tuple[CanaryToken, str]] = []

        if destination:
            # Check raw destination string
            dest_tokens = self.scan_string(destination)
            for t in dest_tokens:
                hits.append((t, "destination"))

            # Check URL unquoted query parameters and path
            try:
                unquoted_dest = urllib.parse.unquote(destination)
                if unquoted_dest != destination:
                    for t in self.scan_string(unquoted_dest):
                        if (t, "destination.unquoted") not in hits:
                            hits.append((t, "destination.unquoted"))
            except Exception as e:
                logger.debug(f"Failed to unquote destination URL: {e}")

        # Scan all parameter values
        param_hits = self.scan_parameters(parameters, parent_key="egress")
        hits.extend(param_hits)
        return hits

    def scan_parameters(
        self, parameters: Any, parent_key: str = "parameters", visited: set[int] | None = None
    ) -> list[tuple[CanaryToken, str]]:
        """Recursively scan tool call parameter dictionary, lists, and primitives."""
        if visited is None:
            visited = set()

        hits: list[tuple[CanaryToken, str]] = []

        if parameters is None:
            return hits

        # Cycle prevention on self-referential structures
        obj_id = id(parameters)
        if obj_id in visited:
            return hits
        visited.add(obj_id)

        if isinstance(parameters, str):
            matched = self.scan_string(parameters)
            for t in matched:
                hits.append((t, parent_key))

        elif isinstance(parameters, dict):
            for k, v in parameters.items():
                loc = f"{parent_key}.{k}"
                # Check dictionary keys themselves (e.g. key as token)
                if isinstance(k, str):
                    for t in self.scan_string(k):
                        hits.append((t, f"{loc}.key"))
                # Recursively check values
                hits.extend(self.scan_parameters(v, parent_key=loc, visited=visited))

        elif isinstance(parameters, (list, tuple, set)):
            for idx, item in enumerate(parameters):
                loc = f"{parent_key}[{idx}]"
                hits.extend(self.scan_parameters(item, parent_key=loc, visited=visited))

        elif isinstance(parameters, bytes):
            try:
                decoded = parameters.decode("utf-8", errors="ignore")
                for t in self.scan_string(decoded):
                    hits.append((t, f"{parent_key}.bytes"))
            except Exception as e:
                logger.debug(f"Failed to decode bytes parameter: {e}")

        return hits

    # -----------------------------------------------------------------------
    # High-Level Tool Call and Event Scanning
    # -----------------------------------------------------------------------

    def scan_tool_call(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        destination: str | None = None,
    ) -> CanaryScanResult:
        """Scan an incoming tool call for registered honeytokens and ASI10 quarantine state."""
        # 1. Check existing session quarantine
        if self.is_session_quarantined(session_id):
            reason = (
                f"Session '{session_id}' is quarantined (ASI10: Canary credential compromise). "
                f"All subsequent tool calls are blocked."
            )
            return CanaryScanResult(
                detected=True,
                confidence=1.0,
                risk_score=1.0,
                action="BLOCK",
                decision=EventDecision.QUARANTINE,
                quarantine_required=True,
                matched_tokens=[],
                locations=["session.quarantine"],
                reason=reason,
            )

        # 2. Fast scan of parameters and destination
        hits: list[tuple[CanaryToken, str]] = []

        # If tool involves SQL execution
        is_sql_tool = any(kw in tool_name.lower() for kw in ("sql", "query", "database", "db"))
        if is_sql_tool:
            for k in ("query", "sql", "statement", "command"):
                if k in parameters and isinstance(parameters[k], str):
                    hits.extend(self.scan_sql_query(parameters[k], location=f"parameters.{k}"))

        # Scan egress destination and parameters
        if destination:
            hits.extend(self.scan_egress_parameters(destination, parameters))
        else:
            hits.extend(self.scan_parameters(parameters))

        if not hits:
            return CanaryScanResult(
                detected=False,
                confidence=0.0,
                risk_score=0.0,
                action="ALLOW",
                decision=EventDecision.ALLOW,
                quarantine_required=False,
                matched_tokens=[],
                locations=[],
                reason="No honeytokens detected",
            )

        # 3. Honeytoken detected: Trigger instant 1.0 confidence compromise detection
        matched_tokens = [h[0] for h in hits]
        locations = [h[1] for h in hits]
        first_token = matched_tokens[0]
        first_loc = locations[0]

        # Immediate quarantine
        quarantine_reason = (
            f"ASI10 Security Violation: Honeytoken '{first_token.label}' detected in {first_loc} "
            f"during invocation of '{tool_name}'."
        )
        self.quarantine_session(
            session_id=session_id, reason=quarantine_reason, matched_token=first_token
        )

        # Tamper alert logging
        alert = self._record_tamper_alert(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            token=first_token,
            location=first_loc,
        )

        return CanaryScanResult(
            detected=True,
            confidence=1.0,
            risk_score=1.0,
            action="BLOCK",
            decision=EventDecision.BLOCK,
            quarantine_required=True,
            matched_tokens=matched_tokens,
            locations=locations,
            reason=quarantine_reason,
            tamper_alert=alert,
        )

    def scan_event(
        self, event: ToolCallEvent, raw_parameters: dict[str, Any] | None = None
    ) -> CanaryScanResult:
        """Scan a ToolCallEvent and enforce immediate BLOCK, session QUARANTINE, and 1.0 risk score."""
        params_to_scan = raw_parameters if raw_parameters is not None else event.parameters

        result = self.scan_tool_call(
            session_id=event.session_id,
            agent_id=event.agent_id,
            tool_name=event.tool_name,
            parameters=params_to_scan,
            destination=event.destination_domain,
        )

        if result.detected:
            event.risk_score = 1.0
            factor = (
                f"ASI10: Honeytoken Compromise - Canary Credential Detected "
                f"('{result.matched_tokens[0].label}' in {result.locations[0]})"
                if result.matched_tokens
                else "ASI10: Session Quarantined Due to Prior Canary Credential Compromise"
            )
            if factor not in event.risk_factors:
                event.risk_factors.append(factor)

            event.decision = EventDecision.BLOCK
            event.decision_reason = result.reason

        return result

    def reset(self) -> None:
        """Reset quarantine states and tamper alerts."""
        with self._lock:
            self._quarantined_sessions.clear()
            self._tamper_alerts.clear()
