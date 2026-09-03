from collections import deque

class SessionWindowManager:
    """Maintains recent sliding sequence context per agent session."""
    
    def __init__(self, window_size: int = 5):
        self.window_size = window_size
        self.sessions: dict[str, deque[str]] = {}

    def get_recent_tools(self, session_id: str) -> list[str]:
        if session_id not in self.sessions:
            return []
        return list(self.sessions[session_id])

    def record_tool(self, session_id: str, tool_name: str):
        if session_id not in self.sessions:
            self.sessions[session_id] = deque(maxlen=self.window_size)
        self.sessions[session_id].append(tool_name)

    def close_session(self, session_id: str):
        self.sessions.pop(session_id, None)
