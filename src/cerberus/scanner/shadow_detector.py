class ShadowDetector:
    """Detects shadowing attempts where a lookalike server exposes an identical tool name."""
    
    def __init__(self):
        self.known_registry: dict[str, str] = {} # tool_name -> authorized_server

    def register_trusted(self, tool_name: str, server_url: str):
        self.known_registry[tool_name] = server_url

    def check_shadowing(self, tool_name: str, candidate_server: str) -> bool:
        if tool_name in self.known_registry:
            return self.known_registry[tool_name] != candidate_server
        return False
