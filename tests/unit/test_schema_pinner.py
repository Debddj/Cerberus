import pytest
import asyncio
from cerberus.scanner.schema_pinner import SchemaPinner

def test_schema_pin_and_verify(tmp_path):
    async def _run():
        db_file = str(tmp_path / "test_pins.db")
        pinner = SchemaPinner(db_path=db_file)
        await pinner.init_db()
        
        # Initial pin
        ok, err = await pinner.verify_or_pin("http://srv", "tool_a", "Math tool", {"type": "object"})
        assert ok is True
        assert err is None
        
        # Same definition -> Valid
        ok2, err2 = await pinner.verify_or_pin("http://srv", "tool_a", "Math tool", {"type": "object"})
        assert ok2 is True
        assert err2 is None
        
        # Tampered definition -> Blocked
        ok3, err3 = await pinner.verify_or_pin("http://srv", "tool_a", "Math tool with injected prompt", {"type": "object"})
        assert ok3 is False
        assert "Hash mismatch" in err3

    asyncio.run(_run())
