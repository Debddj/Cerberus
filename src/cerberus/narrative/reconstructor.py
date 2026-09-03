from cerberus.proxy.models import ToolCallEvent
from cerberus.narrative.templates import PHASES

class NarrativeReconstructor:
    """Weaves individual tool call events into an end-to-end incident narrative."""
    
    @classmethod
    def reconstruct(cls, events: list[ToolCallEvent]) -> str:
        lines = [
            "=" * 60,
            f"INCIDENT NARRATIVE — Session {events[0].session_id if events else 'N/A'}",
            f"Agent: {events[0].agent_id if events else 'N/A'} | Total Intercepted Calls: {len(events)}",
            "=" * 60,
            ""
        ]
        
        # Categorize events into phases
        recon = []
        staging = []
        exfil = []
        
        for e in events:
            name = e.tool_name.lower()
            if any(k in name for k in ["read", "list", "search", "get", "fetch"]):
                recon.append(e)
            elif any(k in name for k in ["query", "write", "dump", "export"]):
                staging.append(e)
            elif any(k in name for k in ["post", "send", "upload", "webhook"]):
                exfil.append(e)
            else:
                recon.append(e)
                
        if recon:
            lines.append("Phase 1: RECONNAISSANCE")
            for e in recon:
                lines.append(f"  ├─ [{e.tool_server}] {e.tool_name} (Risk: {e.risk_score or 0.0:.2f})")
            lines.append("")
            
        if staging:
            lines.append("Phase 2: DATA STAGING & ACCESS")
            for e in staging:
                lines.append(f"  ├─ [{e.tool_server}] {e.tool_name} (Risk: {e.risk_score or 0.0:.2f})")
            lines.append("")
            
        if exfil:
            lines.append("Phase 3: EXFILTRATION & EGRESS")
            for e in exfil:
                lines.append(f"  └─ [{e.tool_server}] {e.tool_name} -> {e.destination_domain or 'External'} [DECISION: {e.decision}]")
            lines.append("")
            
        lines.append("VERDICT: Multi-step tool-call sequence flagged and intercepted by Cerberus.")
        return "\n".join(lines)
