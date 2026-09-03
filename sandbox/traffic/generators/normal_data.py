import random
from cerberus.proxy.models import ToolCallEvent

def generate_data_stream(agent_id="data-01", count=100) -> list[ToolCallEvent]:
    events = []
    tools = ["query_db", "read_file", "export_csv"]
    for i in range(count):
        t = random.choice(tools)
        events.append(ToolCallEvent(
            session_id=f"sess-data-{i//10}",
            agent_id=agent_id,
            tool_name=t,
            tool_server="db-server",
            parameters={"query": f"SELECT * FROM tbl_{i}"},
            sequence_position=i % 10
        ))
    return events
