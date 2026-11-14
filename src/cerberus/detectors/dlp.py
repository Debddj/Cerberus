"""Cerberus Egress DLP and Sliding-Window Quota Budgets.

Provides deterministic outbound Data Loss Prevention (DLP) payload scanning for PII
and secrets, coupled with per-agent and per-session time-window sliding byte quotas
and destination quotas to neutralize slow-drip and burst data exfiltration.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cerberus.proxy.models import EventDecision, ToolCallEvent

# ---------------------------------------------------------------------------
# PII & Secrets Detection Constants and Compiled Regexes
# ---------------------------------------------------------------------------

# US SSN: 3 digits (not 000, 666, 900-999), hyphen/space, 2 digits (not 00), hyphen/space, 4 digits (not 0000)
SSN_REGEX = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b")
SSN_UNFORMATTED_CONTEXT_REGEX = re.compile(
    r"(?i)(?:ssn|social[_\s-]?security(?:[_\s-]?number)?)\s*[:=]?\s*['\"]?(\b(?!000|666|9\d{2})\d{9}\b)['\"]?"
)

# Personal email provider domains
PERSONAL_EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?:gmail\.com|googlemail\.com|yahoo\.com|ymail\.com|"
    r"hotmail\.com|outlook\.com|live\.com|msn\.com|icloud\.com|me\.com|mac\.com|"
    r"protonmail\.com|proton\.me|aol\.com|mail\.com|gmx\.com|zoho\.com)\b",
    re.IGNORECASE,
)

# Generic candidate credit card regex: 13 to 19 digits with optional hyphens or spaces
CREDIT_CARD_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Secrets Regexes
AWS_ACCESS_KEY_REGEX = re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY_REGEX = re.compile(
    r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)

GCP_API_KEY_REGEX = re.compile(r"\bAIza[0-9A-Za-z_\-]{30,36}\b")
GCP_SERVICE_ACCOUNT_REGEX = re.compile(
    r'"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[0-9a-f]{40}"'
)

OPENAI_KEY_REGEX = re.compile(
    r"\b(?:sk-proj-[a-zA-Z0-9_\-]{40,}|sk-admin-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{48})\b"
)

GITHUB_TOKEN_REGEX = re.compile(
    r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36}|"
    r"ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b"
)

PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----|"
    r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]+?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----|"
    r"PuTTY-User-Key-File-[0-9]+:"
)


# ---------------------------------------------------------------------------
# Luhn Algorithm for Credit Card Validation
# ---------------------------------------------------------------------------


def verify_luhn(card_number_candidate: str) -> bool:
    """Verify Luhn checksum (Mod 10) for a credit card candidate.

    Strips non-digits, checks valid card length (13-19 digits), and computes checksum.
    """
    digits = [int(c) for c in card_number_candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


def mask_sensitive(text: str, category: str) -> str:
    """Return a masked representation of sensitive findings for safe audit logging."""
    if not text:
        return ""
    clean = text.strip()
    if category == "CREDIT_CARD":
        digits = [c for c in clean if c.isdigit()]
        if len(digits) >= 4:
            last4 = "".join(digits[-4:])
            return f"****-****-****-{last4}"
        return "****-****-****-****"
    if category == "SSN":
        digits = [c for c in clean if c.isdigit()]
        if len(digits) == 9:
            return f"***-**-{''.join(digits[-4:])}"
        return "***-**-****"
    if category == "PERSONAL_EMAIL":
        parts = clean.split("@")
        if len(parts) == 2:
            user, domain = parts
            masked_user = (user[0] + "***" + user[-1]) if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return "***@masked"
    if category in (
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "OPENAI_KEY",
        "GITHUB_TOKEN",
        "GCP_API_KEY",
    ):
        if len(clean) > 8:
            prefix = clean[:4]
            suffix = clean[-4:]
            return f"{prefix}{'*' * (len(clean) - 8)}{suffix}"
        return "********"
    if category in ("PRIVATE_KEY", "GCP_SERVICE_ACCOUNT"):
        return "[REDACTED_CRYPTO_MATERIAL]"
    return "[REDACTED]"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DLPFinding:
    category: str
    finding_type: str  # "PII" or "SECRET"
    matched_text: str  # Masked for safety
    path: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    confidence: float
    description: str


@dataclass
class QuotaBudgetConfig:
    """Configuration for sliding-window quotas and egress destinations."""

    max_bytes_per_window: int = 50 * 1024  # 50 KB per window
    window_seconds: float = 600.0  # 10 minutes sliding window
    burst_bytes_per_window: int = 15 * 1024  # 15 KB burst window
    burst_window_seconds: float = 60.0  # 1 minute burst window
    max_destinations_per_window: int = 5  # Max distinct external destinations
    egress_tools: set[str] = field(
        default_factory=lambda: {
            "http_post",
            "http_request",
            "curl",
            "send_email",
            "webhook",
            "fetch",
            "requests_post",
            "upload",
            "sftp_upload",
            "export_data",
            "publish_message",
        }
    )
    strict_destination_enforcement: bool = True


@dataclass(frozen=True)
class EgressRecord:
    timestamp: float
    byte_size: int
    destination: str | None
    tool_name: str


@dataclass
class QuotaCheckResult:
    allowed: bool
    violation_type: str | None = None
    reason: str | None = None
    scope: str = "agent"  # "agent" or "session"
    current_window_bytes: int = 0
    limit_window_bytes: int = 0
    current_burst_bytes: int = 0
    limit_burst_bytes: int = 0
    unique_destinations: list[str] = field(default_factory=list)
    limit_destinations: int = 0


@dataclass
class DLPResult:
    allowed: bool
    decision: EventDecision
    risk_score: float
    findings: list[DLPFinding] = field(default_factory=list)
    quota_result: QuotaCheckResult | None = None
    reason: str = ""
    alert: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Outbound Payload DLP Scanner
# ---------------------------------------------------------------------------


class DLPScanner:
    """Outbound payload scanner detecting PII and Secrets across arbitrary nested data structures."""

    def __init__(self) -> None:
        pass

    def scan_text(self, text: str, path: str = "") -> list[DLPFinding]:
        """Scan a single text string for PII and secrets, including base64 & URL obfuscation."""
        if not text:
            return []

        findings: list[DLPFinding] = []

        # 1. Direct regex scans
        findings.extend(self._scan_direct_text(text, path))

        # 2. Check for URL-encoded variants if % is present
        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    findings.extend(self._scan_direct_text(unquoted, f"{path}[url_unquoted]"))
            except (ValueError, UnicodeDecodeError):
                pass

        # 3. Check for Base64 encoded payload segments
        b64_findings = self._scan_base64_chunks(text, path)
        findings.extend(b64_findings)

        return findings

    def _scan_direct_text(self, text: str, path: str) -> list[DLPFinding]:
        findings: list[DLPFinding] = []

        # --- Private Keys ---
        if PRIVATE_KEY_REGEX.search(text):
            findings.append(
                DLPFinding(
                    category="PRIVATE_KEY",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(text, "PRIVATE_KEY"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="Private cryptographic key material detected in outbound payload.",
                )
            )

        # --- AWS Credentials ---
        for m in AWS_ACCESS_KEY_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="AWS_ACCESS_KEY",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(matched, "AWS_ACCESS_KEY"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="AWS Access Key ID detected in outbound payload.",
                )
            )

        for m in AWS_SECRET_KEY_REGEX.finditer(text):
            secret_matched = m.group(1)
            findings.append(
                DLPFinding(
                    category="AWS_SECRET_KEY",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(secret_matched, "AWS_SECRET_KEY"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="AWS Secret Access Key credential detected in outbound payload.",
                )
            )

        # Standalone 40-char AWS secret key if path indicates an AWS secret key
        path_lower = path.lower()
        if "aws" in path_lower and ("secret" in path_lower or "key" in path_lower):
            candidate = text.strip().strip("'\"")
            if len(candidate) == 40 and re.match(r"^[A-Za-z0-9/+=]{40}$", candidate):
                findings.append(
                    DLPFinding(
                        category="AWS_SECRET_KEY",
                        finding_type="SECRET",
                        matched_text=mask_sensitive(candidate, "AWS_SECRET_KEY"),
                        path=path,
                        severity="CRITICAL",
                        confidence=1.0,
                        description="AWS Secret Access Key credential detected in outbound payload.",
                    )
                )

        # --- GCP Credentials ---
        for m in GCP_API_KEY_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="GCP_API_KEY",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(matched, "GCP_API_KEY"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="Google Cloud API Key detected in outbound payload.",
                )
            )

        if GCP_SERVICE_ACCOUNT_REGEX.search(text):
            findings.append(
                DLPFinding(
                    category="GCP_SERVICE_ACCOUNT",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(text, "GCP_SERVICE_ACCOUNT"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="Google Cloud Service Account JSON / Private Key detected.",
                )
            )

        # --- OpenAI API Keys ---
        for m in OPENAI_KEY_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="OPENAI_KEY",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(matched, "OPENAI_KEY"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="OpenAI API key detected in outbound payload.",
                )
            )

        # --- GitHub Tokens ---
        for m in GITHUB_TOKEN_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="GITHUB_TOKEN",
                    finding_type="SECRET",
                    matched_text=mask_sensitive(matched, "GITHUB_TOKEN"),
                    path=path,
                    severity="CRITICAL",
                    confidence=1.0,
                    description="GitHub personal or OAuth access token detected in outbound payload.",
                )
            )

        # --- SSN ---
        for m in SSN_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="SSN",
                    finding_type="PII",
                    matched_text=mask_sensitive(matched, "SSN"),
                    path=path,
                    severity="CRITICAL",
                    confidence=0.98,
                    description="US Social Security Number (SSN) detected in outbound payload.",
                )
            )

        for m in SSN_UNFORMATTED_CONTEXT_REGEX.finditer(text):
            matched = m.group(1)
            findings.append(
                DLPFinding(
                    category="SSN",
                    finding_type="PII",
                    matched_text=mask_sensitive(matched, "SSN"),
                    path=path,
                    severity="CRITICAL",
                    confidence=0.95,
                    description="Unformatted SSN with contextual label detected in outbound payload.",
                )
            )

        # --- Credit Cards with Luhn Check ---
        for m in CREDIT_CARD_CANDIDATE_REGEX.finditer(text):
            candidate = m.group(0)
            if verify_luhn(candidate):
                findings.append(
                    DLPFinding(
                        category="CREDIT_CARD",
                        finding_type="PII",
                        matched_text=mask_sensitive(candidate, "CREDIT_CARD"),
                        path=path,
                        severity="CRITICAL",
                        confidence=1.0,
                        description="Luhn-verified credit card number detected in outbound payload.",
                    )
                )

        # --- Personal Emails ---
        for m in PERSONAL_EMAIL_REGEX.finditer(text):
            matched = m.group(0)
            findings.append(
                DLPFinding(
                    category="PERSONAL_EMAIL",
                    finding_type="PII",
                    matched_text=mask_sensitive(matched, "PERSONAL_EMAIL"),
                    path=path,
                    severity="HIGH",
                    confidence=0.95,
                    description="Personal consumer email address detected in outbound payload.",
                )
            )

        return findings

    def _scan_base64_chunks(self, text: str, path: str) -> list[DLPFinding]:
        """Detect and scan base64-encoded strings that may conceal secrets or PII."""
        findings: list[DLPFinding] = []
        # Find candidate base64 tokens (at least 16 chars of valid b64 with optional padding)
        b64_pattern = re.compile(
            r"(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?=[^A-Za-z0-9+/=]|$)"
        )
        for match in b64_pattern.finditer(text):
            candidate = match.group(1)
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                # Ensure it's valid UTF-8 and contains printable ASCII
                decoded_text = decoded_bytes.decode("utf-8")
                if any(c.isalnum() for c in decoded_text):
                    sub_findings = self._scan_direct_text(
                        decoded_text, f"{path}[b64_decoded:{candidate[:6]}...]"
                    )
                    findings.extend(sub_findings)
            except (ValueError, UnicodeDecodeError):
                continue
        return findings

    def scan_payload(self, data: Any, path_prefix: str = "parameters") -> list[DLPFinding]:
        """Recursively scan a payload (dict, list, string, or primitive) for PII/Secrets."""
        findings: list[DLPFinding] = []

        if isinstance(data, str):
            findings.extend(self.scan_text(data, path_prefix))
            # If the string itself looks like JSON, attempt parsing to scan structured payload
            stripped = data.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (
                stripped.startswith("[") and stripped.endswith("]")
            ):
                try:
                    nested_json = json.loads(stripped)
                    findings.extend(self.scan_payload(nested_json, f"{path_prefix}[json]"))
                except (json.JSONDecodeError, ValueError):
                    pass

        elif isinstance(data, dict):
            for key, val in data.items():
                current_path = f"{path_prefix}.{key}" if path_prefix else str(key)
                findings.extend(self.scan_payload(val, current_path))

        elif isinstance(data, (list, tuple, set)):
            for idx, item in enumerate(data):
                current_path = f"{path_prefix}[{idx}]"
                findings.extend(self.scan_payload(item, current_path))

        return findings


# ---------------------------------------------------------------------------
# Sliding-Window Quota Budget Tracker
# ---------------------------------------------------------------------------


class QuotaTracker:
    """Per-agent and per-session time-window sliding byte quotas and destination quotas.

    Defeats slow-drip exfiltration by maintaining a hard deterministic budget across
    sliding time windows (default: 50KB / 10-minute window) and enforcing destination
    diversity limits.
    """

    def __init__(self, config: QuotaBudgetConfig | None = None) -> None:
        self.config = config or QuotaBudgetConfig()
        self._lock = threading.Lock()
        # Storage: entity_id -> list[EgressRecord]
        self._agent_records: dict[str, list[EgressRecord]] = {}
        self._session_records: dict[str, list[EgressRecord]] = {}

    def _prune(self, records: list[EgressRecord], now: float) -> list[EgressRecord]:
        """Prune records older than the maximum window duration."""
        cutoff = now - self.config.window_seconds
        return [r for r in records if r.timestamp >= cutoff]

    def _check_entity_budget(
        self,
        records: list[EgressRecord],
        new_bytes: int,
        new_destination: str | None,
        now: float,
        scope: str,
    ) -> QuotaCheckResult:
        """Check whether proposed egress complies with byte budgets and destination limits."""
        active_records = self._prune(records, now)

        # 1. Sliding window cumulative bytes
        window_bytes = sum(r.byte_size for r in active_records)
        total_window_bytes = window_bytes + new_bytes

        # 2. Burst window cumulative bytes
        burst_cutoff = now - self.config.burst_window_seconds
        burst_bytes = sum(r.byte_size for r in active_records if r.timestamp >= burst_cutoff)
        total_burst_bytes = burst_bytes + new_bytes

        # 3. Destination diversity in sliding window
        destinations = {r.destination for r in active_records if r.destination}
        is_new_dest = bool(new_destination and new_destination not in destinations)
        unique_dest_list = sorted(destinations)

        # Check burst byte quota
        if total_burst_bytes > self.config.burst_bytes_per_window:
            return QuotaCheckResult(
                allowed=False,
                violation_type="BURST_QUOTA_EXCEEDED",
                reason=(
                    f"Burst egress byte quota exceeded for {scope}: "
                    f"{total_burst_bytes} bytes in {self.config.burst_window_seconds}s "
                    f"(limit: {self.config.burst_bytes_per_window} bytes)"
                ),
                scope=scope,
                current_window_bytes=total_window_bytes,
                limit_window_bytes=self.config.max_bytes_per_window,
                current_burst_bytes=total_burst_bytes,
                limit_burst_bytes=self.config.burst_bytes_per_window,
                unique_destinations=unique_dest_list,
                limit_destinations=self.config.max_destinations_per_window,
            )

        # Check sliding window byte quota (deterministic slow-drip stopper)
        if total_window_bytes > self.config.max_bytes_per_window:
            return QuotaCheckResult(
                allowed=False,
                violation_type="BYTE_QUOTA_EXCEEDED",
                reason=(
                    f"Cumulative sliding-window byte quota exceeded for {scope}: "
                    f"{total_window_bytes} bytes in {self.config.window_seconds}s "
                    f"(limit: {self.config.max_bytes_per_window} bytes)"
                ),
                scope=scope,
                current_window_bytes=total_window_bytes,
                limit_window_bytes=self.config.max_bytes_per_window,
                current_burst_bytes=total_burst_bytes,
                limit_burst_bytes=self.config.burst_bytes_per_window,
                unique_destinations=unique_dest_list,
                limit_destinations=self.config.max_destinations_per_window,
            )

        # Check destination quota
        if (
            self.config.strict_destination_enforcement
            and is_new_dest
            and len(destinations) >= self.config.max_destinations_per_window
        ):
            return QuotaCheckResult(
                allowed=False,
                violation_type="DESTINATION_QUOTA_EXCEEDED",
                reason=(
                    f"Destination diversity quota exceeded for {scope}: "
                    f"attempted to contact '{new_destination}' but {len(destinations)} distinct "
                    f"destinations already reached in {self.config.window_seconds}s "
                    f"(limit: {self.config.max_destinations_per_window})"
                ),
                scope=scope,
                current_window_bytes=total_window_bytes,
                limit_window_bytes=self.config.max_bytes_per_window,
                current_burst_bytes=total_burst_bytes,
                limit_burst_bytes=self.config.burst_bytes_per_window,
                unique_destinations=unique_dest_list,
                limit_destinations=self.config.max_destinations_per_window,
            )

        return QuotaCheckResult(
            allowed=True,
            scope=scope,
            current_window_bytes=total_window_bytes,
            limit_window_bytes=self.config.max_bytes_per_window,
            current_burst_bytes=total_burst_bytes,
            limit_burst_bytes=self.config.burst_bytes_per_window,
            unique_destinations=unique_dest_list,
            limit_destinations=self.config.max_destinations_per_window,
        )

    def check_quota(
        self,
        agent_id: str,
        session_id: str,
        byte_size: int,
        destination: str | None = None,
        timestamp: float | None = None,
    ) -> QuotaCheckResult:
        """Check both agent and session quotas without recording usage."""
        now = timestamp if timestamp is not None else time.time()

        with self._lock:
            # 1. Check agent budget
            agent_recs = self._agent_records.get(agent_id, [])
            agent_result = self._check_entity_budget(
                agent_recs, byte_size, destination, now, scope=f"agent:{agent_id}"
            )
            if not agent_result.allowed:
                return agent_result

            # 2. Check session budget
            session_recs = self._session_records.get(session_id, [])
            session_result = self._check_entity_budget(
                session_recs, byte_size, destination, now, scope=f"session:{session_id}"
            )
            if not session_result.allowed:
                return session_result

            return agent_result

    def record_egress(
        self,
        agent_id: str,
        session_id: str,
        byte_size: int,
        destination: str | None = None,
        tool_name: str = "",
        timestamp: float | None = None,
    ) -> None:
        """Record committed egress usage against both agent and session."""
        now = timestamp if timestamp is not None else time.time()
        record = EgressRecord(
            timestamp=now,
            byte_size=byte_size,
            destination=destination,
            tool_name=tool_name,
        )

        with self._lock:
            # Update agent records
            a_recs = self._prune(self._agent_records.get(agent_id, []), now)
            a_recs.append(record)
            self._agent_records[agent_id] = a_recs

            # Update session records
            s_recs = self._prune(self._session_records.get(session_id, []), now)
            s_recs.append(record)
            self._session_records[session_id] = s_recs

    def get_agent_usage(self, agent_id: str, timestamp: float | None = None) -> dict[str, Any]:
        """Inspect current quota consumption for an agent."""
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            recs = self._prune(self._agent_records.get(agent_id, []), now)
            window_bytes = sum(r.byte_size for r in recs)
            destinations = {r.destination for r in recs if r.destination}
            return {
                "agent_id": agent_id,
                "window_bytes": window_bytes,
                "max_window_bytes": self.config.max_bytes_per_window,
                "remaining_bytes": max(0, self.config.max_bytes_per_window - window_bytes),
                "destinations": sorted(destinations),
                "records_count": len(recs),
            }

    def get_session_usage(self, session_id: str, timestamp: float | None = None) -> dict[str, Any]:
        """Inspect current quota consumption for a session."""
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            recs = self._prune(self._session_records.get(session_id, []), now)
            window_bytes = sum(r.byte_size for r in recs)
            destinations = {r.destination for r in recs if r.destination}
            return {
                "session_id": session_id,
                "window_bytes": window_bytes,
                "max_window_bytes": self.config.max_bytes_per_window,
                "remaining_bytes": max(0, self.config.max_bytes_per_window - window_bytes),
                "destinations": sorted(destinations),
                "records_count": len(recs),
            }

    def reset(self) -> None:
        """Clear all active quota state."""
        with self._lock:
            self._agent_records.clear()
            self._session_records.clear()


# ---------------------------------------------------------------------------
# Egress DLP Detector
# ---------------------------------------------------------------------------


class EgressDLPDetector:
    """Unified Egress DLP Detector combining payload PII/Secrets inspection and Quota Budgets."""

    def __init__(
        self,
        config: QuotaBudgetConfig | None = None,
        scanner: DLPScanner | None = None,
    ) -> None:
        self.config = config or QuotaBudgetConfig()
        self.scanner = scanner or DLPScanner()
        self.quota_tracker = QuotaTracker(self.config)
        self._alerts: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _extract_destination(self, event: ToolCallEvent) -> str | None:
        """Extract external destination domain from event or parameters."""
        if event.destination_domain:
            return event.destination_domain

        # Inspect parameters for URLs, hosts, or destinations
        for key in ("url", "uri", "endpoint", "host", "hostname", "destination", "target_url"):
            val = event.parameters.get(key)
            if isinstance(val, str) and val:
                try:
                    parsed = urllib.parse.urlparse(val)
                    if parsed.netloc:
                        return parsed.netloc.split(":")[0].lower()
                    if "/" not in val and "." in val:
                        return val.split(":")[0].lower()
                except (ValueError, AttributeError):
                    continue

        return None

    def _compute_payload_size(self, event: ToolCallEvent) -> int:
        """Compute the byte size of the outgoing tool call payload."""
        if event.parameter_size_bytes > 0:
            return event.parameter_size_bytes
        try:
            return len(json.dumps(event.parameters, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return len(str(event.parameters).encode("utf-8"))

    def is_egress_call(self, event: ToolCallEvent) -> bool:
        """Determine whether the tool call constitutes external egress."""
        tool_lower = event.tool_name.lower()
        if tool_lower in self.config.egress_tools:
            return True
        if any(tool_lower.startswith(prefix) for prefix in ("http", "curl", "send_", "upload")):
            return True
        return bool(event.destination_domain)

    def evaluate(self, event: ToolCallEvent) -> DLPResult:
        """Evaluate an outbound ToolCallEvent for DLP policy violations and quota budgets.

        Enforces:
        1. Immediate BLOCK if PII or secrets are detected in parameters.
        2. Immediate BLOCK if cumulative byte quota or destination budget is exceeded.
        """
        # 1. Payload DLP Scanning
        findings = self.scanner.scan_payload(event.parameters)
        if findings:
            categories = sorted({f.category for f in findings})
            reason = f"DLP payload violation: detected {', '.join(categories)}"
            alert = {
                "timestamp": datetime.now(UTC).isoformat(),
                "alert_type": "DLP_PAYLOAD_VIOLATION",
                "session_id": event.session_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "categories": categories,
                "findings": [
                    {
                        "category": f.category,
                        "type": f.finding_type,
                        "path": f.path,
                        "severity": f.severity,
                        "matched": f.matched_text,
                    }
                    for f in findings
                ],
            }
            with self._lock:
                self._alerts.append(alert)

            return DLPResult(
                allowed=False,
                decision=EventDecision.BLOCK,
                risk_score=1.0,
                findings=findings,
                quota_result=None,
                reason=reason,
                alert=alert,
            )

        # 2. Check Quota Budgets for Egress Tools
        is_egress = self.is_egress_call(event)
        if is_egress:
            payload_bytes = self._compute_payload_size(event)
            destination = self._extract_destination(event)
            # Use event timestamp if available
            ts = event.timestamp.timestamp() if event.timestamp else time.time()

            quota_res = self.quota_tracker.check_quota(
                agent_id=event.agent_id,
                session_id=event.session_id,
                byte_size=payload_bytes,
                destination=destination,
                timestamp=ts,
            )

            if not quota_res.allowed:
                alert = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "alert_type": "DLP_QUOTA_EXCEEDED",
                    "violation_type": quota_res.violation_type,
                    "session_id": event.session_id,
                    "agent_id": event.agent_id,
                    "tool_name": event.tool_name,
                    "destination": destination,
                    "attempted_bytes": payload_bytes,
                    "current_window_bytes": quota_res.current_window_bytes,
                    "limit_window_bytes": quota_res.limit_window_bytes,
                    "reason": quota_res.reason,
                }
                with self._lock:
                    self._alerts.append(alert)

                return DLPResult(
                    allowed=False,
                    decision=EventDecision.BLOCK,
                    risk_score=1.0,
                    findings=[],
                    quota_result=quota_res,
                    reason=quota_res.reason or "Egress quota exceeded",
                    alert=alert,
                )

            # Record approved egress
            self.quota_tracker.record_egress(
                agent_id=event.agent_id,
                session_id=event.session_id,
                byte_size=payload_bytes,
                destination=destination,
                tool_name=event.tool_name,
                timestamp=ts,
            )

            return DLPResult(
                allowed=True,
                decision=EventDecision.ALLOW,
                risk_score=0.0,
                findings=[],
                quota_result=quota_res,
                reason="Egress payload clean and within quota budget",
            )

        # Non-egress tool with clean payload
        return DLPResult(
            allowed=True,
            decision=EventDecision.ALLOW,
            risk_score=0.0,
            findings=[],
            quota_result=None,
            reason="Payload clean, non-egress invocation",
        )

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return a copy of all accumulated security alerts."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clear the security alert log."""
        with self._lock:
            self._alerts.clear()

    def reset(self) -> None:
        """Reset quota trackers and alert state."""
        self.quota_tracker.reset()
        self.clear_alerts()
