import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from jinja2 import Template

from cerberus.proxy.models import ToolCallEvent

logger = logging.getLogger("cerberus.synthesizer")

REGO_TEMPLATE = """
# Auto-generated least-privilege policy for agent {{ agent_id }}
# Generated at {{ generated_at }}
package cerberus.agent.{{ agent_safe_id }}

default allow := true

allowed_tools := {
{% for tool in allowed_tools %}
    "{{ tool }}",
{% endfor %}
}

deny if {
    not input.tool_name in allowed_tools
}

reason := "Auto-synthesized policy: Tool is not in agent's observed baseline allowed set" if {
    deny
}
"""

BLOCKED_EVENT_TEMPLATE = """
# Auto-synthesized defensive rule for event {{ event_id }}
# Generated at {{ generated_at }}
package cerberus.generated.{{ policy_id }}

default block := false

block if {
    input.tool_name == "{{ tool_name }}"
    input.agent_id == "{{ agent_id }}"
}

reason := "Defensive policy: Tool '{{ tool_name }}' quarantined for anomalous risk profile" if {
    block
}
"""


class PolicySynthesizer:
    """Synthesizes least-privilege Rego policies from observed agent baselines and blocked anomalies."""

    def __init__(self, output_dir: str = "policies/generated"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    @staticmethod
    def synthesize_rego(agent_id: str, observed_tools: set[str], generated_at: str) -> str:
        template = Template(REGO_TEMPLATE)
        agent_safe_id = agent_id.replace("-", "_")
        return template.render(
            agent_id=agent_id,
            agent_safe_id=agent_safe_id,
            allowed_tools=sorted(observed_tools),
            generated_at=generated_at,
        )

    def synthesize_for_blocked(self, event: ToolCallEvent) -> tuple[str, str, str]:
        """Generate a candidate defensive policy for a blocked or quarantined event."""
        policy_id = f"pol_{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(UTC).isoformat()
        template = Template(BLOCKED_EVENT_TEMPLATE)
        rego = template.render(
            policy_id=policy_id,
            event_id=event.event_id,
            generated_at=now_str,
            tool_name=event.tool_name,
            agent_id=event.agent_id,
        )

        rego_path = os.path.join(self.output_dir, f"{policy_id}.rego")
        meta_path = os.path.join(self.output_dir, f"{policy_id}.json")

        with open(rego_path, "w", encoding="utf-8") as f:
            f.write(rego)

        metadata = {
            "policy_id": policy_id,
            "created_at": now_str,
            "status": "pending",  # pending, approved, rejected
            "agent_id": event.agent_id,
            "tool_name": event.tool_name,
            "risk_score": event.risk_score,
            "factors": event.risk_factors,
            "rego_path": rego_path,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return policy_id, rego, rego_path

    def list_pending_policies(self) -> list[dict[str, Any]]:
        """Return list of candidate generated policies waiting for human review."""
        results: list[dict[str, Any]] = []
        if not os.path.exists(self.output_dir):
            return results

        for fname in os.listdir(self.output_dir):
            if fname.endswith(".json"):
                meta_file = os.path.join(self.output_dir, fname)
                try:
                    with open(meta_file, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if meta.get("status") == "pending":
                        results.append(meta)
                except Exception as e:
                    logger.warning(f"Error reading policy metadata {meta_file}: {e}")
        return results

    def approve_policy(self, policy_id: str) -> bool:
        """Mark candidate policy as approved and active."""
        meta_file = os.path.join(self.output_dir, f"{policy_id}.json")
        if not os.path.exists(meta_file):
            return False
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta["status"] = "approved"
            meta["approved_at"] = datetime.now(UTC).isoformat()
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to approve policy {policy_id}: {e}")
            return False

    def reject_policy(self, policy_id: str) -> bool:
        """Reject and disable candidate policy."""
        meta_file = os.path.join(self.output_dir, f"{policy_id}.json")
        if not os.path.exists(meta_file):
            return False
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta["status"] = "rejected"
            meta["rejected_at"] = datetime.now(UTC).isoformat()
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            # Optionally remove rego or keep with rejected status
            return True
        except Exception as e:
            logger.error(f"Failed to reject policy {policy_id}: {e}")
            return False
