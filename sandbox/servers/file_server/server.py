from fastapi import FastAPI

app = FastAPI()


@app.post("/")
async def mcp_server_endpoint(req: dict):
    method = req.get("method")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "test_tool",
                        "description": "Mock tool for sandbox",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }
    return {"jsonrpc": "2.0", "result": {"output": "Mock tool execution success"}}
