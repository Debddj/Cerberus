import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventDecision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class ToolCallEvent(BaseModel):
    """Normalized intercepted tool call event."""

    # Identity
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = Field(description="Session or conversation identifier")
    agent_id: str = Field(description="Unique agent identifier")

    # Tool Invocation
    tool_name: str = Field(description="Target tool name")
    tool_server: str = Field(description="Upstream MCP server name")
    parameters: dict[str, Any] = Field(default_factory=dict)
    parameter_size_bytes: int = 0
    parameter_entropy: float = 0.0

    # Context & Network
    source_prompt: str | None = None
    destination_domain: str | None = None

    # Timing
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    time_since_previous_ms: float | None = None
    session_duration_ms: float = 0.0
    sequence_position: int = 0

    # Response
    response_summary: str | None = None
    response_size_bytes: int | None = None

    # Behavioral Risk
    risk_score: float | None = None
    risk_factors: list[str] = Field(default_factory=list)

    # Decision
    decision: EventDecision | None = None
    decision_reason: str | None = None
    redacted_fields: list[str] = Field(default_factory=list)


class MarkovFeatures(BaseModel):
    tool_name: str
    server_name: str
    prev_tool_1: str | None = None
    prev_tool_2: str | None = None
    prev_tool_3: str | None = None


class IsolationForestFeatures(BaseModel):
    param_size_bytes_z: float
    param_entropy_z: float
    response_size_bytes_z: float
    time_since_previous_ms_z: float
    session_duration_ms_z: float
    sequence_position_z: float
    destination_novelty: float
    tool_novelty: float


class RuleFeatures(BaseModel):
    tool_name: str
    param_size_bytes: float
    param_entropy: float
    response_size_bytes: float
    time_since_previous_ms: float
    sequence_position: int
    destination_novelty: float
    tool_novelty: float
    destination_domain: str | None
    prev_tools: list[str] = Field(default_factory=list)


class SchemaPin(BaseModel):
    server_url: str
    tool_name: str
    description_hash: str
    schema_hash: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_verified: datetime = Field(default_factory=lambda: datetime.now(UTC))
    pin_version: int = 1


class BaselineSnapshot(BaseModel):
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    calls_in_snapshot: int
    transition_matrix_path: str
    isolation_forest_path: str
    scaling_params_path: str
    is_active: bool = False


class AgentBaseline(BaseModel):
    agent_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_calls_observed: int = 0
    snapshots: list[BaselineSnapshot] = Field(default_factory=list)
    active_snapshot_id: str | None = None
    known_tools: set[str] = Field(default_factory=set)
    known_destinations: set[str] = Field(default_factory=set)
    avg_param_entropy: float = 0.0
    std_param_entropy: float = 1.0
    avg_time_between_calls_ms: float = 0.0
    std_time_between_calls_ms: float = 1.0
    is_warm: bool = False
    warm_threshold_calls: int = 100
    flagged_calls_excluded: int = 0
