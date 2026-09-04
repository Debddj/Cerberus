import hashlib
import json
from datetime import UTC, datetime

import aiosqlite


class SchemaPinner:
    """Calculates and verifies SHA-256 cryptographic hashes of tool definitions."""

    def __init__(self, db_path: str = "cerberus_pins.db"):
        self.db_path = db_path

    @staticmethod
    def compute_hash(description: str, input_schema: dict) -> tuple[str, str]:
        desc_hash = hashlib.sha256(description.strip().encode("utf-8")).hexdigest()
        schema_canonical = json.dumps(input_schema, sort_keys=True)
        schema_hash = hashlib.sha256(schema_canonical.encode("utf-8")).hexdigest()
        return desc_hash, schema_hash

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS schema_pins (
                    server_url TEXT,
                    tool_name TEXT,
                    description_hash TEXT,
                    schema_hash TEXT,
                    first_seen TEXT,
                    last_verified TEXT,
                    pin_version INTEGER,
                    PRIMARY KEY (server_url, tool_name)
                )
            """)
            await db.commit()

    async def verify_or_pin(
        self, server_url: str, tool_name: str, desc: str, schema: dict
    ) -> tuple[bool, str | None]:
        d_hash, s_hash = self.compute_hash(desc, schema)
        now = datetime.now(UTC).isoformat()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT description_hash, schema_hash, pin_version FROM schema_pins WHERE server_url=? AND tool_name=?",
                (server_url, tool_name),
            ) as cursor:
                row = await cursor.fetchone()

            if not row:
                # First time seen: Pin it
                await db.execute(
                    "INSERT INTO schema_pins VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (server_url, tool_name, d_hash, s_hash, now, now, 1),
                )
                await db.commit()
                return True, None

            stored_d_hash, stored_s_hash, _version = row
            if stored_d_hash != d_hash or stored_s_hash != s_hash:
                return (
                    False,
                    f"Hash mismatch detected! Potential tool poisoning or rug-pull on '{tool_name}'",
                )

            await db.execute(
                "UPDATE schema_pins SET last_verified=? WHERE server_url=? AND tool_name=?",
                (now, server_url, tool_name),
            )
            await db.commit()
            return True, None
