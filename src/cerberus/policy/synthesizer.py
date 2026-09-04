from jinja2 import Template

REGO_TEMPLATE = """
# Auto-generated least-privilege policy for agent {{ agent_id }}
# Generated at {{ generated_at }}
package cerberus.agent.{{ agent_safe_id }}

default allow = true

allowed_tools = {
{% for tool in allowed_tools %}
    "{{ tool }}",
{% endfor %}
}

deny {
    not input.tool_name in allowed_tools
}

reason = "Auto-synthesized policy: Tool is not in agent's observed baseline allowed set" {
    deny
}
"""


class PolicySynthesizer:
    """Synthesizes least-privilege Rego policies from observed agent baselines."""

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
