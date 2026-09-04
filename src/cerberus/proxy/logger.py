import json

import aiofiles

from cerberus.config import settings
from cerberus.proxy.models import ToolCallEvent


class AuditLogger:
    """Asynchronous audit logger supporting both JSONL and SQLite with redaction."""

    def __init__(self, log_path: str | None = None, db_path: str | None = None):
        self.log_path = log_path or settings.log_path
        self.db_path = db_path or settings.pins_db_path

    async def log_event(self, event: ToolCallEvent) -> None:
        raw_json = json.dumps(event.model_dump(mode="json"))
        # Non-blocking append to JSON Lines file
        async with aiofiles.open(self.log_path, mode="a", encoding="utf-8") as f:
            await f.write(raw_json + "\n")
