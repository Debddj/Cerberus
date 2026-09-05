from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
from typing import TYPE_CHECKING

from cerberus.config import settings

if TYPE_CHECKING:
    from cerberus.proxy.models import ToolCallEvent

logger = logging.getLogger("cerberus.audit")

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None  # type: ignore[assignment,misc]

GENESIS_HASH = "0" * 64


class AuditLogger:
    """Asynchronous audit logger with tamper-evident SHA-256 hash chaining
    and optional Fernet symmetric encryption.

    Each line embeds:
    - index: Monotonically increasing index
    - prev_hash: SHA-256 hash of the preceding entry
    - event: Serialized ToolCallEvent
    - hash: SHA-256(index:prev_hash:event_json)
    """

    def __init__(self, log_path: str | None = None, key: str | None = None):
        self.log_path = log_path or settings.log_path
        self._fernet: Fernet | None = None  # type: ignore[assignment]
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        self._entry_index = 0
        self._raw_key: str = (key or settings.log_encryption_key).strip()

        if settings.encrypt_logs:
            self._fernet = self._init_encryption()

        self._init_chain_state()

    def _init_encryption(self) -> Fernet | None:
        if Fernet is None:
            logger.warning("`cryptography` package not available — writing plaintext audit log")
            return None

        if not self._raw_key:
            key_path = os.path.splitext(self.log_path)[0] + ".key"
            if os.path.exists(key_path):
                with open(key_path, "r", encoding="utf-8") as f:
                    self._raw_key = f.read().strip()
            if not self._raw_key:
                self._raw_key = Fernet.generate_key().decode()
                try:
                    with open(key_path, "w", encoding="utf-8") as f:
                        f.write(self._raw_key)
                    logger.info("Generated new audit log encryption key at %s", key_path)
                except Exception as e:
                    logger.warning("Could not write key file %s: %s", key_path, e)

        try:
            return Fernet(self._raw_key.encode("utf-8"))
        except Exception as e:
            logger.error("Invalid CERBERUS_LOG_ENCRYPTION_KEY (%s) — writing plaintext", e)
            return None

    def _init_chain_state(self):
        if not os.path.exists(self.log_path):
            return

        try:
            last_line = ""
            count = 0
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        last_line = s
                        count += 1
            if last_line:
                raw_json = self.decrypt_log_line(last_line)
                data = json.loads(raw_json)
                self._last_hash = data.get("hash", GENESIS_HASH)
                self._entry_index = count
        except Exception as e:
            logger.warning("Could not restore audit hash chain from %s: %s", self.log_path, e)

    @staticmethod
    def compute_entry_hash(index: int, prev_hash: str, raw_event_json: str) -> str:
        payload = f"{index}:{prev_hash}:{raw_event_json}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _sync_write(self, raw_event_json: str) -> None:
        with self._lock:
            index = self._entry_index
            prev_h = self._last_hash
            entry_hash = self.compute_entry_hash(index, prev_h, raw_event_json)

            record = {
                "index": index,
                "prev_hash": prev_h,
                "event": json.loads(raw_event_json),
                "hash": entry_hash,
            }
            envelope_str = json.dumps(record, sort_keys=True)

            line = envelope_str
            if self._fernet is not None:
                line = self._fernet.encrypt(envelope_str.encode("utf-8")).decode("ascii")

            with open(self.log_path, mode="a", encoding="utf-8") as f:
                f.write(line + "\n")

            self._last_hash = entry_hash
            self._entry_index += 1

    async def log_event(self, event: ToolCallEvent) -> None:
        raw_json = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        await asyncio.to_thread(self._sync_write, raw_json)

    def decrypt_log_line(self, encrypted_line: str) -> str:
        """Decrypt a single audit log line for forensic review."""
        if self._fernet is None:
            return encrypted_line
        token = encrypted_line.strip().encode("ascii")
        return self._fernet.decrypt(token).decode("utf-8")

    @classmethod
    def verify_ledger(
        cls, log_path: str, encryption_key: str | None = None
    ) -> tuple[bool, int, str | None]:
        """Validates hash chain integrity across all entries in the audit ledger.

        Returns:
            (is_valid, total_entries, error_message)
        """
        if not os.path.exists(log_path):
            return False, 0, f"Log file not found: {log_path}"

        fernet_inst = None
        key = encryption_key or settings.log_encryption_key
        if not key:
            key_path = os.path.splitext(log_path)[0] + ".key"
            if os.path.exists(key_path):
                with open(key_path, "r", encoding="utf-8") as f:
                    key = f.read().strip()
        if key and Fernet is not None:
            try:
                fernet_inst = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
            except Exception as e:
                logger.debug("Failed to initialize Fernet with key: %s", e)

        expected_prev = GENESIS_HASH
        count = 0

        with open(log_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                s = raw_line.strip()
                if not s:
                    continue

                line_content = s
                if fernet_inst is not None:
                    try:
                        line_content = fernet_inst.decrypt(s.encode("ascii")).decode("utf-8")
                    except Exception as e:
                        return False, count, f"Line {line_no}: Decryption failed ({e})"

                try:
                    record = json.loads(line_content)
                except Exception as e:
                    return False, count, f"Line {line_no}: Invalid JSON envelope ({e})"

                idx = record.get("index")
                prev_h = record.get("prev_hash")
                h = record.get("hash")
                event = record.get("event", {})

                if prev_h != expected_prev:
                    return (
                        False,
                        count,
                        (
                            f"Line {line_no} (Index {idx}): Hash chain broken! "
                            f"Expected prev_hash {expected_prev[:12]}..., got {prev_h[:12]}..."
                        ),
                    )

                recomputed = cls.compute_entry_hash(idx, prev_h, json.dumps(event, sort_keys=True))
                if h != recomputed:
                    return (
                        False,
                        count,
                        (
                            f"Line {line_no} (Index {idx}): Entry tampering detected! "
                            f"Hash signature does not match payload."
                        ),
                    )

                expected_prev = h
                count += 1

        return True, count, None
