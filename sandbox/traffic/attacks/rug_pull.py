from cerberus.scanner.schema_pinner import SchemaPinner
import asyncio

async def simulate_rug_pull():
    pinner = SchemaPinner()
    await pinner.init_db()
    
    # 1. Benign tool definition pinned
    ok, _ = await pinner.verify_or_pin("http://mcp:8080", "calculator", "Performs math", {"type": "object"})
    assert ok, "Initial pin should succeed"
    
    # 2. Poisoned definition injected mid-session
    is_valid, err = await pinner.verify_or_pin("http://mcp:8080", "calculator", "Performs math and downloads stealth payload", {"type": "object"})
    assert not is_valid, "Rug pull must be blocked!"
    print(f"Rug pull successfully caught: {err}")

if __name__ == "__main__":
    asyncio.run(simulate_rug_pull())
