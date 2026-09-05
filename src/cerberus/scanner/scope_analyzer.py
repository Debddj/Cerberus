from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScopeVerdict:
    """Result of a scope check — separates 'allowed' from 'enforced'."""

    allowed: bool
    enforced: bool
    reason: str


class ScopeAnalyzer:
    """Validates whether a tool call adheres to the agent's declared scope.

    Supports a three-state enforcement model:
    - 'strict': Fail-closed — agents without declared scope are blocked.
    - 'learn':  Monitor + log — undeclared agents are allowed but flagged
                as unenforced so the gap is visible to operators.

    Once an agent reaches warm status and gets an approved synthesized policy,
    scope enforcement flips to fail-closed automatically for that agent.
    """

    def __init__(self, mode: str = "learn"):
        self.mode = mode  # "learn" or "strict"
        self.agent_scopes: dict[str, set[str]] = {}
        self.agent_enforced: dict[str, bool] = {}

    def register_scope(self, agent_id: str, allowed_tools: set[str], enforced: bool = True):
        """Register an agent's allowed tool scope."""
        self.agent_scopes[agent_id] = set(allowed_tools)
        self.agent_enforced[agent_id] = enforced

    def promote_to_enforced(self, agent_id: str):
        """Flip an agent from learning to enforced after warm + policy approval."""
        self.agent_enforced[agent_id] = True

    def check_scope(self, agent_id: str, tool_name: str) -> ScopeVerdict:
        """Check if a tool call is in scope for the given agent."""
        allowed_tools = self.agent_scopes.get(agent_id)
        is_enforced = self.agent_enforced.get(agent_id, False)

        # Case 1: Agent has no scope declared at all
        if allowed_tools is None:
            if self.mode == "strict":
                return ScopeVerdict(
                    allowed=False,
                    enforced=True,
                    reason=f"Strict mode: Agent '{agent_id}' has no declared scope — blocked",
                )
            # Learn mode: allow but flag as unenforced
            return ScopeVerdict(
                allowed=True,
                enforced=False,
                reason=f"Learn mode: Agent '{agent_id}' has no declared scope — monitoring",
            )

        # Case 2: Agent has scope declared but empty set
        if not allowed_tools:
            if self.mode == "strict" or is_enforced:
                return ScopeVerdict(
                    allowed=False,
                    enforced=True,
                    reason=f"Agent '{agent_id}' has empty scope — all tools blocked",
                )
            return ScopeVerdict(
                allowed=True,
                enforced=False,
                reason=f"Learn mode: Agent '{agent_id}' has empty scope — monitoring",
            )

        # Case 3: Agent has scope; check if tool is in it
        if tool_name in allowed_tools:
            return ScopeVerdict(
                allowed=True, enforced=is_enforced, reason="Tool is within declared scope"
            )

        # Tool is NOT in scope
        if is_enforced or self.mode == "strict":
            return ScopeVerdict(
                allowed=False,
                enforced=True,
                reason=f"Out-of-scope: '{tool_name}' not in agent '{agent_id}' allowed tools",
            )
        return ScopeVerdict(
            allowed=True,
            enforced=False,
            reason=f"Learn mode: '{tool_name}' not in agent '{agent_id}' scope — monitoring",
        )

    @staticmethod
    def is_in_scope(tool_name: str, allowed_tools: set[str] | list[str]) -> bool:
        """Check whether tool_name is within allowed_tools."""
        return tool_name in allowed_tools
