"""Cerberus Deterministic Taint and Provenance Tracking Detector.

Provides deterministic data labeling, cryptographic fingerprinting, and session-wide
taint propagation tracking to prevent indirect prompt injection, sensitive data exfiltration,
and behavioral mimicry attacks across agent tool calls.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import threading
import urllib.parse
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from cerberus.proxy.models import EventDecision, ToolCallEvent


class TaintOriginType(str, Enum):
    """Categorical origin of tainted or sensitive information."""

    UNTRUSTED_CONTENT = "untrusted_content"
    PRIVATE_DATA = "private_data"
    EXTERNAL_TOOL = "external_tool"
    USER_INPUT = "user_input"
    WEB = "web"
    EMAIL = "email"
    ISSUE = "issue"


class TaintTag(BaseModel):
    """Metadata tag and cryptographic identity for tracked data."""

    tag_id: str = Field(description="Unique identifier for this taint origin tag")
    origin_type: TaintOriginType = Field(description="Classification of the taint source")
    source_tool: str = Field(default="", description="Name of the tool that yielded this data")
    origin_label: str = Field(default="", description="Descriptive label of origin (e.g. issue#42)")
    taint_token: str = Field(description="Deterministic synthetic taint token embedded in data")
    fingerprint_hash: str = Field(description="SHA-256 fingerprint hash of the tainted content")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaintProvenanceNode(BaseModel):
    """Audit node in the session's provenance and taint propagation lineage."""

    step: int
    session_id: str
    tool_name: str
    tool_server: str = ""
    action: str = Field(
        description="Lineage action: 'source', 'propagated', 'egress_blocked', or 'sink'"
    )
    matched_tag_ids: list[str] = Field(default_factory=list)
    matched_parameters: list[str] = Field(default_factory=list)
    matched_substrings: list[str] = Field(default_factory=list)
    details: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TaintResult(BaseModel):
    """Evaluation result from the Taint and Provenance Tracking detector."""

    allowed: bool = Field(description="Whether the tool call is permitted to proceed")
    decision: EventDecision = Field(description="Policy decision (ALLOW or BLOCK)")
    risk_score: float = Field(default=0.0, description="Risk score (1.0 for hard block violations)")
    is_tainted: bool = Field(
        default=False, description="Whether arguments or session carry tainted data"
    )
    reason: str | None = None
    factors: list[str] = Field(default_factory=list)
    matched_tags: list[TaintTag] = Field(default_factory=list)
    matched_parameters: list[str] = Field(default_factory=list)
    provenance_chain: list[TaintProvenanceNode] = Field(default_factory=list)
    alert: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Default Tool Classification Sets
# ---------------------------------------------------------------------------

UNTRUSTED_TOOL_KEYWORDS: set[str] = {
    "issue",
    "web",
    "scrape",
    "search",
    "inbox",
    "email",
    "fetch_url",
    "public",
    "untrusted",
    "public_issue",
    "read_public",
    "get_ticket",
    "jira",
    "slack",
    "rss",
    "feed",
    "browser",
    "html",
}

PRIVATE_TOOL_KEYWORDS: set[str] = {
    "read_private",
    "private_repo",
    "get_secret",
    "credentials",
    "database",
    "fetch_db",
    "env",
    "secret",
    "token",
    "password",
    "confidential",
    "internal",
    "keychain",
    "vault",
}

EGRESS_TOOL_KEYWORDS: set[str] = {
    "http_post",
    "http_put",
    "http_patch",
    "curl",
    "send_email",
    "email",
    "webhook",
    "upload",
    "publish",
    "post_message",
    "export",
    "dns_lookup",
    "exfil",
    "socket",
    "request",
    "sftp",
    "ssh",
}

EGRESS_PARAM_NAMES: set[str] = {
    "data",
    "body",
    "payload",
    "url",
    "content",
    "message",
    "query",
    "text",
    "value",
    "params",
    "json",
    "file",
    "export",
}

SENSITIVE_FILE_INDICATORS: tuple[str, ...] = (
    ".env",
    "id_rsa",
    "id_ed25519",
    "secrets",
    "credentials",
    "passwd",
    "shadow",
    "auth.token",
    "api_key",
    "private_key",
)


def compute_content_hash(content: Any) -> str:
    """Computes a deterministic SHA-256 fingerprint hash of string or structured content."""
    if isinstance(content, (dict, list)):
        serialized = json.dumps(content, sort_keys=True, ensure_ascii=True)
    elif isinstance(content, bytes):
        return hashlib.sha256(content).hexdigest()
    else:
        serialized = str(content)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _normalize_string(val: str) -> str:
    """Normalize string for consistent fingerprint and token matching."""
    return re.sub(r"\s+", " ", val.strip())


def extract_searchable_strings(data: Any, max_depth: int = 5) -> list[str]:
    """Recursively extracts candidate strings from nested structures,

    including URL-decoded and Base64-decoded variants.
    """
    results: list[str] = []

    def _walk(obj: Any, depth: int) -> None:
        if depth > max_depth or obj is None:
            return
        if isinstance(obj, str):
            s = obj.strip()
            if not s:
                return
            results.append(s)

            # URL decoded variant
            with contextlib.suppress(Exception):
                decoded_url = urllib.parse.unquote(s)
                if decoded_url != s and len(decoded_url) >= 3:
                    results.append(decoded_url)

            # Base64 decoded variant (if plausible)
            if len(s) >= 8 and len(s) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", s):
                with contextlib.suppress(Exception):
                    decoded_b64 = base64.b64decode(s, validate=True).decode(
                        "utf-8", errors="ignore"
                    )
                    if decoded_b64 and len(decoded_b64) >= 3:
                        results.append(decoded_b64)

        elif isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str):
                    results.append(k)
                _walk(v, depth + 1)
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                _walk(item, depth + 1)
        elif isinstance(obj, (int, float, bool)):
            results.append(str(obj))

    _walk(data, 0)
    return results


class SessionTaintState:
    """Maintains active taint tags, tokens, fingerprints, and provenance for a session."""

    def __init__(self, session_id: str, min_substring_len: int = 6):
        self.session_id: str = session_id
        self.min_substring_len: int = min_substring_len
        self.step_counter: int = 0

        # Tags and tokens
        self.tags: dict[str, TaintTag] = {}
        self.taint_tokens: set[str] = set()

        # Content fingerprints
        self.fingerprint_hashes: set[str] = set()
        self.exact_tainted_strings: set[str] = set()
        self.tainted_shingles: set[str] = set()

        # Tainted resources (e.g. file paths or variable names contaminated by tool writes)
        self.tainted_resources: set[str] = set()

        # Provenance audit trail
        self.provenance_nodes: list[TaintProvenanceNode] = []

        # Overall session taint status
        self.has_untrusted_exposure: bool = False
        self.has_private_access: bool = False

    def add_tag(
        self,
        tag: TaintTag,
        raw_content: Any = None,
        exact_tokens: list[str] | None = None,
    ) -> None:
        """Registers a new taint tag and indexes its content fingerprints."""
        self.tags[tag.tag_id] = tag
        self.taint_tokens.add(tag.taint_token)
        self.fingerprint_hashes.add(tag.fingerprint_hash)

        if tag.origin_type in (
            TaintOriginType.UNTRUSTED_CONTENT,
            TaintOriginType.WEB,
            TaintOriginType.EMAIL,
            TaintOriginType.ISSUE,
        ):
            self.has_untrusted_exposure = True
        elif tag.origin_type == TaintOriginType.PRIVATE_DATA:
            self.has_private_access = True

        # Extract and index substrings/shingles if content is provided
        if raw_content is not None:
            strs = extract_searchable_strings(raw_content)
            for s in strs:
                norm = _normalize_string(s)
                if len(norm) >= self.min_substring_len:
                    self.exact_tainted_strings.add(norm)
                    # Shingles of length min_substring_len to 32 chars for partial matching
                    shingle_len = max(self.min_substring_len, 8)
                    if len(norm) >= shingle_len:
                        for i in range(0, len(norm) - shingle_len + 1, 4):
                            self.tainted_shingles.add(norm[i : i + shingle_len])

        if exact_tokens:
            for tok in exact_tokens:
                norm_tok = _normalize_string(tok)
                if len(norm_tok) >= self.min_substring_len:
                    self.exact_tainted_strings.add(norm_tok)

    def record_node(self, node: TaintProvenanceNode) -> None:
        """Appends a provenance node to the session's audit history."""
        self.provenance_nodes.append(node)


class TaintTracker:
    """Deterministic Taint and Provenance Tracking Engine.

    Labels untrusted and private data with cryptographic fingerprints and taint tokens,
    tracks multi-step propagation across tool invocations, and enforces hard 1.0 blocks
    when tainted content or confidential data reaches outbound egress parameters.
    """

    def __init__(
        self,
        min_substring_len: int = 6,
        untrusted_keywords: set[str] | None = None,
        private_keywords: set[str] | None = None,
        egress_keywords: set[str] | None = None,
    ):
        self.min_substring_len = min_substring_len
        self.untrusted_keywords = set(untrusted_keywords or UNTRUSTED_TOOL_KEYWORDS)
        self.private_keywords = set(private_keywords or PRIVATE_TOOL_KEYWORDS)
        self.egress_keywords = set(egress_keywords or EGRESS_TOOL_KEYWORDS)

        self._lock = threading.RLock()
        self._sessions: dict[str, SessionTaintState] = {}
        self._alerts: list[dict[str, Any]] = []

    def get_or_create_session(self, session_id: str) -> SessionTaintState:
        """Retrieves or creates the SessionTaintState for the given session ID."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionTaintState(
                    session_id, min_substring_len=self.min_substring_len
                )
            return self._sessions[session_id]

    def reset_session(self, session_id: str) -> None:
        """Resets taint tracking state for a specific session."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def reset(self) -> None:
        """Resets all session states and security alerts."""
        with self._lock:
            self._sessions.clear()
            self._alerts.clear()

    # -----------------------------------------------------------------------
    # Classification Utilities
    # -----------------------------------------------------------------------

    def is_egress_tool(
        self,
        tool_name: str,
        tool_server: str = "",
        destination_domain: str | None = None,
    ) -> bool:
        """Determines whether a tool invocation represents an external egress channel."""
        name_lower = tool_name.lower()
        server_lower = tool_server.lower()

        if destination_domain:
            return True

        if any(k in name_lower for k in self.egress_keywords):
            return True

        return any(k in server_lower for k in ("webhook", "external", "egress", "network"))

    def is_untrusted_source(
        self,
        tool_name: str,
        tool_server: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        """Determines whether a tool produces data originating from an untrusted source."""
        # Egress tools (sinks) are not untrusted content sources
        if self.is_egress_tool(tool_name, tool_server):
            return False

        name_lower = tool_name.lower()
        server_lower = tool_server.lower()

        if any(k in name_lower for k in self.untrusted_keywords):
            return True

        if any(k in server_lower for k in ("crawler", "scraper", "public", "email-reader")):
            return True

        # Check parameters for external URLs or untrusted markers in read tools
        if parameters and any(r in name_lower for r in ("read", "fetch", "get", "parse")):
            params_str = str(parameters).lower()
            if "http://" in params_str or "https://" in params_str:
                return True
            if any(k in params_str for k in ("untrusted", "public_issue", "github.com")):
                return True

        return False

    def is_private_source(
        self,
        tool_name: str,
        tool_server: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        """Determines whether a tool accesses private, internal, or confidential data."""
        name_lower = tool_name.lower()
        server_lower = tool_server.lower()

        if any(k in name_lower for k in self.private_keywords):
            return True

        if any(k in server_lower for k in ("secret", "vault", "credentials", "internal-db")):
            return True

        # Check if parameters reference sensitive files
        if parameters:
            for val in extract_searchable_strings(parameters):
                val_lower = val.lower()
                if any(sens in val_lower for sens in SENSITIVE_FILE_INDICATORS):
                    return True

        return False

    # -----------------------------------------------------------------------
    # Labeling and Fingerprinting (Requirement 1)
    # -----------------------------------------------------------------------

    def label_untrusted_data(
        self,
        session_id: str,
        data: Any,
        origin_label: str,
        source_tool: str = "",
        metadata: dict[str, Any] | None = None,
        exact_tokens: list[str] | None = None,
    ) -> TaintTag:
        """Labels and fingerprints data originating from untrusted sources (e.g.

        issues, web, email, external tool outputs) with taint tokens and origin tags.
        """
        content_hash = compute_content_hash(data)
        tag_id = f"untrusted_{content_hash[:12]}"
        taint_token = f"CERBERUS_TAINT_{tag_id}"

        tag = TaintTag(
            tag_id=tag_id,
            origin_type=TaintOriginType.UNTRUSTED_CONTENT,
            source_tool=source_tool,
            origin_label=origin_label,
            taint_token=taint_token,
            fingerprint_hash=content_hash,
            metadata=metadata or {},
        )

        with self._lock:
            state = self.get_or_create_session(session_id)
            state.step_counter += 1
            state.add_tag(tag, raw_content=data, exact_tokens=exact_tokens)

            state.record_node(
                TaintProvenanceNode(
                    step=state.step_counter,
                    session_id=session_id,
                    tool_name=source_tool or "label_untrusted",
                    action="source",
                    matched_tag_ids=[tag_id],
                    details=f"Labeled untrusted data from origin: '{origin_label}' (token: {taint_token})",
                )
            )

        return tag

    def label_private_data(
        self,
        session_id: str,
        data: Any,
        origin_label: str,
        source_tool: str = "",
        metadata: dict[str, Any] | None = None,
        exact_tokens: list[str] | None = None,
    ) -> TaintTag:
        """Labels and fingerprints confidential/private data with taint tokens and origin tags."""
        content_hash = compute_content_hash(data)
        tag_id = f"private_{content_hash[:12]}"
        taint_token = f"CERBERUS_TAINT_{tag_id}"

        tag = TaintTag(
            tag_id=tag_id,
            origin_type=TaintOriginType.PRIVATE_DATA,
            source_tool=source_tool,
            origin_label=origin_label,
            taint_token=taint_token,
            fingerprint_hash=content_hash,
            metadata=metadata or {},
        )

        with self._lock:
            state = self.get_or_create_session(session_id)
            state.step_counter += 1
            state.add_tag(tag, raw_content=data, exact_tokens=exact_tokens)

            state.record_node(
                TaintProvenanceNode(
                    step=state.step_counter,
                    session_id=session_id,
                    tool_name=source_tool or "label_private",
                    action="source",
                    matched_tag_ids=[tag_id],
                    details=f"Labeled private data: '{origin_label}' (token: {taint_token})",
                )
            )

        return tag

    def inject_taint_token(
        self,
        session_id: str,
        raw_text: str,
        origin_label: str,
        source_tool: str = "",
    ) -> tuple[str, TaintTag]:
        """Convenience method that creates a TaintTag and embeds the synthetic taint token

        directly into the text (e.g. for prompt or tool result context reflection).
        """
        tag = self.label_untrusted_data(session_id, raw_text, origin_label, source_tool)
        injected_text = f"{raw_text}\n<!-- {tag.taint_token} -->"
        return injected_text, tag

    # -----------------------------------------------------------------------
    # Tool Output Ingestion
    # -----------------------------------------------------------------------

    def record_tool_output(
        self,
        session_id: str,
        tool_name: str,
        tool_server: str,
        parameters: dict[str, Any],
        output_data: Any,
    ) -> list[TaintTag]:
        """Inspects and registers tool outputs.

        If the tool is an untrusted or private source, or if its inputs were
        tainted, automatically generates taint tokens and provenance tags.
        """
        tags_created: list[TaintTag] = []
        with self._lock:
            state = self.get_or_create_session(session_id)

            # Check if this call consumed tainted input
            input_strings = extract_searchable_strings(parameters)
            input_tainted = False
            for s in input_strings:
                if any(tok in s for tok in state.taint_tokens):
                    input_tainted = True
                    break
                if any(exact in s for exact in state.exact_tainted_strings):
                    input_tainted = True
                    break

            # 1. Untrusted Source Output
            if self.is_untrusted_source(tool_name, tool_server, parameters):
                tag = self.label_untrusted_data(
                    session_id=session_id,
                    data=output_data,
                    origin_label=f"ToolOutput:{tool_name}",
                    source_tool=tool_name,
                    metadata={"tool_server": tool_server, "parameters": parameters},
                )
                tags_created.append(tag)

            # 2. Private Source Output
            elif self.is_private_source(tool_name, tool_server, parameters):
                tag = self.label_private_data(
                    session_id=session_id,
                    data=output_data,
                    origin_label=f"PrivateData:{tool_name}",
                    source_tool=tool_name,
                    metadata={"tool_server": tool_server, "parameters": parameters},
                )
                tags_created.append(tag)

            # 3. Downstream Propagation: input was tainted, so output inherits taint
            elif input_tainted:
                tag = self.label_untrusted_data(
                    session_id=session_id,
                    data=output_data,
                    origin_label=f"PropagatedFrom:{tool_name}",
                    source_tool=tool_name,
                    metadata={"tool_server": tool_server, "propagated": True},
                )
                tags_created.append(tag)

            # Record written files as tainted resources if writing tainted data
            if input_tainted and "write" in tool_name.lower():
                written_path = parameters.get("path") or parameters.get("file")
                if written_path and isinstance(written_path, str):
                    state.tainted_resources.add(written_path)

        return tags_created

    # -----------------------------------------------------------------------
    # Taint Propagation and Interception (Requirements 2 & 3)
    # -----------------------------------------------------------------------

    def check_tool_call(
        self,
        event: ToolCallEvent,
        session_id: str | None = None,
    ) -> TaintResult:
        """Inspects an incoming ToolCallEvent for tainted substrings, hashes, and tokens.

        - If tainted or private data reaches egress parameters: deterministically
          flags and blocks with risk_score = 1.0 (stops mimicry and injection leaks).
        - If tainted data is passed to intermediate tools: marks session state and
          downstream outputs as tainted (propagation).
        """
        sid = session_id or event.session_id
        tool_name = event.tool_name
        tool_server = event.tool_server
        parameters = event.parameters
        dest_domain = event.destination_domain

        with self._lock:
            state = self.get_or_create_session(sid)
            state.step_counter += 1

            # Check if this tool reads a resource previously tainted by a write
            if "read" in tool_name.lower():
                target_path = parameters.get("path") or parameters.get("file")
                if (
                    target_path
                    and isinstance(target_path, str)
                    and target_path in state.tainted_resources
                ):
                    # Re-taint session output for reading contaminated resource
                    self.label_untrusted_data(
                        session_id=sid,
                        data=target_path,
                        origin_label=f"ContaminatedResource:{target_path}",
                        source_tool=tool_name,
                    )

            # Automatic source detection on call entry (e.g. read_public_issue, read_private_repo)
            if self.is_untrusted_source(tool_name, tool_server, parameters):
                state.has_untrusted_exposure = True

            if self.is_private_source(tool_name, tool_server, parameters):
                state.has_private_access = True

            # Scan parameters (keys and values) for taint tokens, hashes, and exact strings
            matched_tags: list[TaintTag] = []
            matched_params: list[str] = []
            matched_substrings: list[str] = []

            for param_key, param_val in parameters.items():
                val_strings = [param_key] + extract_searchable_strings(param_val)
                for val_s in val_strings:
                    # 1. Exact taint token match
                    for tok in state.taint_tokens:
                        if tok in val_s:
                            matched_params.append(param_key)
                            matched_substrings.append(tok)
                            # Find tag associated with token
                            for t in state.tags.values():
                                if t.taint_token == tok and t not in matched_tags:
                                    matched_tags.append(t)

                    # 2. Exact tainted string match (e.g. sensitive secret or hostile payload)
                    for exact in state.exact_tainted_strings:
                        if exact in val_s:
                            matched_params.append(param_key)
                            matched_substrings.append(exact)
                            for t in state.tags.values():
                                if (
                                    t.fingerprint_hash in state.fingerprint_hashes
                                    and t not in matched_tags
                                ):
                                    matched_tags.append(t)

                    # 3. Shingle / partial fingerprint match
                    for shingle in state.tainted_shingles:
                        if shingle in val_s:
                            matched_params.append(param_key)
                            matched_substrings.append(shingle)

            # Deduplicate matched items
            matched_params = list(dict.fromkeys(matched_params))
            matched_substrings = list(dict.fromkeys(matched_substrings))
            matched_tags = list({t.tag_id: t for t in matched_tags}.values())

            # Check if this call is an EGRESS destination
            is_egress = self.is_egress_tool(tool_name, tool_server, dest_domain)

            # REQUIREMENT 3: Intercept and flag/block with 1.0 risk score when tainted
            # or private data reaches egress parameters (or session exhibits lethal toxic flow to egress)
            has_taint_match = len(matched_tags) > 0 or len(matched_substrings) > 0
            has_toxic_flow = state.has_untrusted_exposure and state.has_private_access and is_egress

            if is_egress and (has_taint_match or has_toxic_flow):
                # Critical violation: Deterministic Egress Block
                factors: list[str] = []
                reason_parts: list[str] = []

                if has_taint_match:
                    origins = [t.origin_label or t.source_tool for t in matched_tags]
                    origin_str = ", ".join(origins) if origins else "untrusted/private session"
                    factors.append(
                        f"Deterministic Taint Violation: Tainted data from [{origin_str}] "
                        f"reached egress tool '{tool_name}' in parameter(s) {matched_params}"
                    )
                    reason_parts.append(
                        f"Taint propagation detected in egress parameter '{', '.join(matched_params)}'"
                    )

                if has_toxic_flow and not has_taint_match:
                    factors.append(
                        f"Deterministic Provenance Violation: Untrusted content combined with "
                        f"private access flowing to egress tool '{tool_name}'"
                    )
                    reason_parts.append(
                        "Toxic flow detected: Untrusted session context reaching outbound egress"
                    )

                alert = {
                    "alert_type": "DETERMINISTIC_TAINT_EGRESS_BLOCKED",
                    "session_id": sid,
                    "agent_id": event.agent_id,
                    "tool_name": tool_name,
                    "tool_server": tool_server,
                    "destination_domain": dest_domain,
                    "matched_parameters": matched_params,
                    "matched_substrings": matched_substrings[:5],
                    "matched_tags": [t.tag_id for t in matched_tags],
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                self._alerts.append(alert)

                node = TaintProvenanceNode(
                    step=state.step_counter,
                    session_id=sid,
                    tool_name=tool_name,
                    tool_server=tool_server,
                    action="egress_blocked",
                    matched_tag_ids=[t.tag_id for t in matched_tags],
                    matched_parameters=matched_params,
                    matched_substrings=matched_substrings,
                    details=f"Egress blocked: {'; '.join(factors)}",
                )
                state.record_node(node)

                return TaintResult(
                    allowed=False,
                    decision=EventDecision.BLOCK,
                    risk_score=1.0,
                    is_tainted=True,
                    reason="; ".join(reason_parts),
                    factors=factors,
                    matched_tags=matched_tags,
                    matched_parameters=matched_params,
                    provenance_chain=list(state.provenance_nodes),
                    alert=alert,
                )

            # REQUIREMENT 2: Track taint propagation across intermediate tool calls
            if has_taint_match:
                # Non-egress tool with tainted inputs: mark session and propagate
                node = TaintProvenanceNode(
                    step=state.step_counter,
                    session_id=sid,
                    tool_name=tool_name,
                    tool_server=tool_server,
                    action="propagated",
                    matched_tag_ids=[t.tag_id for t in matched_tags],
                    matched_parameters=matched_params,
                    matched_substrings=matched_substrings,
                    details=f"Taint propagated into intermediate tool '{tool_name}'",
                )
                state.record_node(node)

                # Record resource contamination if writing
                if "write" in tool_name.lower():
                    written_path = parameters.get("path") or parameters.get("file")
                    if written_path and isinstance(written_path, str):
                        state.tainted_resources.add(written_path)

                return TaintResult(
                    allowed=True,
                    decision=EventDecision.ALLOW,
                    risk_score=0.0,
                    is_tainted=True,
                    reason=f"Taint propagated across tool '{tool_name}' (intermediate)",
                    factors=[f"Taint Propagation: '{tool_name}' received tainted input"],
                    matched_tags=matched_tags,
                    matched_parameters=matched_params,
                    provenance_chain=list(state.provenance_nodes),
                    alert=None,
                )

            # Clean tool call
            return TaintResult(
                allowed=True,
                decision=EventDecision.ALLOW,
                risk_score=0.0,
                is_tainted=False,
                reason="Call parameters clean",
                factors=[],
                matched_tags=[],
                matched_parameters=[],
                provenance_chain=list(state.provenance_nodes),
                alert=None,
            )

    # -----------------------------------------------------------------------
    # Mimicry Attack Detection (Requirement 4)
    # -----------------------------------------------------------------------

    def evaluate_sequence(
        self,
        sequence: list[ToolCallEvent],
        session_id: str | None = None,
    ) -> list[TaintResult]:
        """Evaluates an ordered sequence of tool calls (such as a mimicry attack)

        and returns the TaintResult for each step, pinpointing when taint was
        propagated and deterministically blocked.
        """
        results: list[TaintResult] = []
        for event in sequence:
            res = self.check_tool_call(event, session_id=session_id)
            results.append(res)
        return results

    def get_provenance_history(self, session_id: str) -> list[TaintProvenanceNode]:
        """Returns the full provenance audit history for a session."""
        with self._lock:
            state = self._sessions.get(session_id)
            if not state:
                return []
            return list(state.provenance_nodes)

    def get_alerts(self) -> list[dict[str, Any]]:
        """Returns all recorded security alerts."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clears all security alerts."""
        with self._lock:
            self._alerts.clear()


# Alias for backward compatibility and clean naming
DeterministicTaintTracker = TaintTracker
