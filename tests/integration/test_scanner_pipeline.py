import asyncio

from cerberus.scanner.schema_pinner import SchemaPinner
from cerberus.scanner.trifecta import LethalTrifectaDetector


def test_combined_scanner(tmp_path):
    async def _run():
        pinner = SchemaPinner(db_path=str(tmp_path / "pins.db"))
        await pinner.init_db()
        tools = ["read_file", "http_post", "fetch_inbox"]
        is_trifecta, _ = LethalTrifectaDetector.check_session_tools(tools)
        assert is_trifecta

    asyncio.run(_run())
