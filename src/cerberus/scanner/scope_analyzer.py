class ScopeAnalyzer:
    """Validates whether a tool call adheres to the agent's declared scope."""
    
    @staticmethod
    def is_in_scope(tool_name: str, allowed_tools: set[str]) -> bool:
        if not allowed_tools:
            return True
        return tool_name in allowed_tools
