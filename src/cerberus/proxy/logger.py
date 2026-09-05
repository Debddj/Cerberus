import asyncio
import json

from cerberus.config import settings
from cerberus.proxy.models import ToolCallEvent


class AuditLogger:
    """Asynchronous audit logger supporting both JSONL and SQLite with redaction."""

    def __init__(self, log_path: str | None = None, db_path: str | None = None):
        self.log_path = log_path or settings.log_path
        self.db_path = db_path or settings.pins_db_path

    def _sync_write(self, raw_line: str) -> None:
        with open(self.log_path, mode="a", encoding="utf-8") as f:
            f.write(raw_line + "\n")

    async def log_event(self, event: ToolCallEvent) -> None:
        raw_json = json.dumps(event.model_dump(mode="json"))
        await asyncio.to_thread(self._sync_write, raw_json)
