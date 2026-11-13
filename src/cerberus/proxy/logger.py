from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import threading
from typing import TYPE_CHECKING

import portalocker

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
    """Asynchronous audit logger with tamper-evident HMAC-SHA256 hash chaining,
    cross-process safe file locking, durable fsync writes, and optional Fernet
    symmetric encryption.

    Each line embeds:
    - index: Monotonically increasing index across restarts and rotations
    - prev_hash: HMAC-SHA256 hash of the preceding entry (or segment header anchor)
    - event: Serialized ToolCallEvent or segment header dictionary
    - hash: HMAC-SHA256(index:prev_hash:event_json)
    """

    def __init__(
        self,
        log_path: str | None = None,
        key: str | None = None,
        hmac_key: str | None = None,
        max_bytes: int | None = None,
        backup_count: int | None = None,
    ):
        self.log_path = log_path or settings.log_path
        self.lock_path = self.log_path + ".lock"
        self.max_bytes = max_bytes if max_bytes is not None else settings.log_max_bytes
        self.backup_count = backup_count if backup_count is not None else settings.log_backup_count
        self._fernet: Fernet | None = None  # type: ignore[assignment]
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        self._entry_index = 0
        self._raw_key: str = (key or settings.log_encryption_key).strip()

        # Bug 3 & 4: Strict fail-closed encryption initialization with safe file permissions
        if settings.encrypt_logs:
            self._fernet = self._init_encryption()

        # Bug 7: HMAC secret key for tamper-proof hash chaining
        self._hmac_key: str = self._init_hmac_key(hmac_key)

        # Bug 5 & 6 & 9: Crash-resilient chain initialization with partial tail truncation
        self._init_chain_state()

    def _init_encryption(self) -> Fernet:
        """Initialize Fernet encryption. Refuses to start if encryption is requested
        but the cryptography package is missing or the key is invalid (Bug 3).
        """
        if Fernet is None:
            raise RuntimeError(
                "`cryptography` package is not available but `encrypt_logs=True`. "
                "Refusing to start in insecure plaintext mode. "
                "Install `cryptography` or explicitly disable `encrypt_logs`."
            )

        if not self._raw_key:
            key_path = settings.log_encryption_key_path or (
                os.path.splitext(self.log_path)[0] + ".key"
            )
            if os.path.exists(key_path):
                self._check_file_permissions(key_path, "Encryption")
                with open(key_path, "r", encoding="utf-8") as f:
                    self._raw_key = f.read().strip()

            if not self._raw_key:
                self._raw_key = Fernet.generate_key().decode()
                try:
                    # Bug 4: 0o600 safe permissions without world-readable leaks
                    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(self._raw_key)
                    logger.info("Generated new audit log encryption key at %s", key_path)
                except Exception as e:
                    raise RuntimeError(
                        f"Could not securely create encryption key file {key_path}: {e}"
                    ) from e

        try:
            return Fernet(self._raw_key.encode("utf-8"))
        except Exception as e:
            raise RuntimeError(
                f"Invalid CERBERUS_LOG_ENCRYPTION_KEY ({e}). "
                "Refusing to start with invalid encryption key while encrypt_logs=True."
            ) from e

    def _init_hmac_key(self, custom_key: str | None = None) -> str:
        """Initialize or load HMAC secret key for tamper-proof hash chaining (Bug 7)."""
        key = (custom_key or settings.log_hmac_key).strip()
        if key:
            return key

        key_path = settings.log_hmac_key_path or (os.path.splitext(self.log_path)[0] + ".hmac.key")
        if os.path.exists(key_path):
            self._check_file_permissions(key_path, "HMAC")
            with open(key_path, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key

        key = secrets.token_hex(32)
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(key)
            logger.info("Generated new audit log HMAC key at %s", key_path)
        except Exception as e:
            logger.warning("Could not persist audit HMAC key file %s: %s", key_path, e)
        return key

    @staticmethod
    def _check_file_permissions(file_path: str, key_type: str) -> None:
        """Warn if a key file has group or world readable/writable permissions on POSIX."""
        if os.name != "nt":
            try:
                mode = os.stat(file_path).st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    logger.warning(
                        "%s key file %s has overly permissive permissions (%o). "
                        "Run `chmod 600 %s` to secure it.",
                        key_type,
                        file_path,
                        mode & 0o777,
                        file_path,
                    )
            except OSError as e:
                logger.debug("Failed to check key permissions: %s", e)

    def _truncate_partial_tail(self) -> None:
        """Truncate incomplete trailing line from a previous crash to prevent torn writes (Bug 6)."""
        if not os.path.exists(self.log_path):
            return
        size = os.path.getsize(self.log_path)
        if size == 0:
            return

        with open(self.log_path, "rb") as f:
            read_size = min(size, 8192)
            f.seek(size - read_size)
            chunk = f.read()

        if not chunk.endswith(b"\n"):
            last_nl = chunk.rfind(b"\n")
            if last_nl == -1:
                truncate_at = max(0, size - len(chunk))
            else:
                truncate_at = size - (len(chunk) - last_nl - 1)

            with open(self.log_path, "r+b") as f:
                f.truncate(truncate_at)
            logger.warning(
                "Truncated partial tail line in audit log %s at %d bytes (recovered from torn write)",
                self.log_path,
                truncate_at,
            )

    def _init_chain_state(self) -> None:
        """Restore hash chain state from existing log file.
        Fails fast on corrupted tail rather than silently resetting to genesis (Bug 5).
        Restores global index monotonically (Bug 9).
        """
        if not os.path.exists(self.log_path):
            return

        self._truncate_partial_tail()

        try:
            last_line = ""
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        last_line = s

            if last_line:
                raw_json = self.decrypt_log_line(last_line)
                data = json.loads(raw_json)
                if not isinstance(data, dict) or "hash" not in data:
                    raise ValueError("Last log line is not a valid audit record envelope")

                self._last_hash = data["hash"]
                # Bug 9: Derive index from stored record to prevent drift after rotation
                self._entry_index = int(data.get("index", 0)) + 1
        except Exception as e:
            # Bug 5: Fail explicitly so operator is aware of corruption or key mismatch
            raise RuntimeError(
                f"Could not restore audit hash chain from {self.log_path}: {e}. "
                "Refusing to silently reset chain to genesis. "
                "Check that the correct encryption key is configured, or verify with `cerberus verify-log`."
            ) from e

    def _refresh_tail_under_lock(self) -> None:
        """Under cross-process lock, re-read the log tail in case another process appended (Bug 2)."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return

        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                read_size = min(size, 8192)
                f.seek(size - read_size)
                lines = f.read().splitlines()

            for raw in reversed(lines):
                s = raw.strip()
                if s:
                    decrypted = self.decrypt_log_line(s.decode("utf-8", errors="replace"))
                    data = json.loads(decrypted)
                    if isinstance(data, dict) and "hash" in data:
                        self._last_hash = data["hash"]
                        self._entry_index = int(data.get("index", 0)) + 1
                    break
        except Exception as e:
            logger.debug("Tail refresh under lock encountered: %s", e)

    @staticmethod
    def compute_entry_hash(
        index: int, prev_hash: str, raw_event_json: str, hmac_key: str | None = None
    ) -> str:
        """Compute HMAC-SHA256 (or plain SHA-256 for legacy support) over the canonical record payload (Bug 7)."""
        payload = f"{index}:{prev_hash}:{raw_event_json}"
        payload_bytes = payload.encode("utf-8")
        if hmac_key:
            return hmac.new(hmac_key.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload_bytes).hexdigest()

    def _write_segment_header_under_lock(self, prev_tail_hash: str) -> None:
        """Write a segment-header record bridging rotated files together (Bug 1)."""
        header_event = {
            "__segment_header": True,
            "prev_segment_tail_hash": prev_tail_hash,
            "segment_start_index": self._entry_index,
        }
        header_json = json.dumps(header_event, sort_keys=True)
        index = self._entry_index
        prev_h = prev_tail_hash
        entry_hash = self.compute_entry_hash(index, prev_h, header_json, self._hmac_key)

        record = {
            "index": index,
            "prev_hash": prev_h,
            "event": header_event,
            "hash": entry_hash,
        }
        envelope_str = json.dumps(record, sort_keys=True)
        line = envelope_str
        if self._fernet is not None:
            line = self._fernet.encrypt(envelope_str.encode("utf-8")).decode("ascii")

        with open(self.log_path, mode="a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = entry_hash
        self._entry_index += 1

    def _rotate_if_needed(self) -> None:
        """Rotate audit log when max_bytes threshold is reached.
        Writes a segment-header bridging record so hash verification remains unbroken (Bug 1).
        """
        if self.max_bytes <= 0 or not os.path.exists(self.log_path):
            return
        try:
            if os.path.getsize(self.log_path) < self.max_bytes:
                return

            prev_tail_hash = self._last_hash

            for i in range(self.backup_count - 1, 0, -1):
                s_from = f"{self.log_path}.{i}"
                s_to = f"{self.log_path}.{i + 1}"
                if os.path.exists(s_from):
                    if os.path.exists(s_to):
                        os.remove(s_to)
                    os.rename(s_from, s_to)

            dest = f"{self.log_path}.1"
            if os.path.exists(dest):
                os.remove(dest)
            os.rename(self.log_path, dest)
            logger.info("Rotated audit log %s -> %s", self.log_path, dest)

            # Bug 1: Write segment header as first record in the newly rotated log
            self._write_segment_header_under_lock(prev_tail_hash)
        except Exception as e:
            logger.warning("Audit log rotation failed: %s", e)

    def _sync_write(self, raw_event_json: str) -> None:
        """Cross-process locked, durable write with HMAC chain update (Bugs 2 & 6)."""
        with self._lock:
            # Bug 2: Cross-process lock using portalocker
            lock_dir = os.path.dirname(os.path.abspath(self.lock_path))
            os.makedirs(lock_dir, exist_ok=True)
            with portalocker.Lock(self.lock_path, mode="a", timeout=10):
                self._refresh_tail_under_lock()
                self._rotate_if_needed()

                index = self._entry_index
                prev_h = self._last_hash
                entry_hash = self.compute_entry_hash(index, prev_h, raw_event_json, self._hmac_key)

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

                # Bug 6: Single-call atomic line write followed by fsync
                with open(self.log_path, mode="a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())

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
        cls,
        log_path: str,
        encryption_key: str | None = None,
        hmac_key: str | None = None,
        start_hash: str | None = None,
        start_index: int | None = None,
        walk_segments: bool = False,
    ) -> tuple[bool, int, str | None]:
        """Validates hash chain integrity across all entries in the audit ledger.
        Handles segment headers across rotations (Bug 1), supports HMAC verification (Bug 7),
        and safely validates types and indexes without crashing (Bug 8).

        Returns:
            (is_valid, total_entries, error_message)
        """
        if not os.path.exists(log_path):
            return False, 0, f"Log file not found: {log_path}"

        # Resolve encryption key
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

        # Resolve HMAC key
        resolved_hmac = hmac_key or settings.log_hmac_key
        if not resolved_hmac:
            h_path = os.path.splitext(log_path)[0] + ".hmac.key"
            if os.path.exists(h_path):
                with open(h_path, "r", encoding="utf-8") as f:
                    resolved_hmac = f.read().strip()

        # Bug 1: Support walking rotated segments (.backup_count down to .1 and current)
        if walk_segments:
            segments: list[str] = []
            for i in range(settings.log_backup_count, 0, -1):
                seg_file = f"{log_path}.{i}"
                if os.path.exists(seg_file):
                    segments.append(seg_file)
            segments.append(log_path)

            curr_hash = start_hash or GENESIS_HASH
            curr_idx = start_index or 0
            total_count = 0
            for seg in segments:
                ok, seg_count, tail_h, tail_i, err = cls._verify_single_file(
                    seg, fernet_inst, resolved_hmac, curr_hash, curr_idx
                )
                if not ok:
                    return False, total_count, f"In segment {seg}: {err}"
                total_count += seg_count
                if tail_h is not None:
                    curr_hash = tail_h
                curr_idx = (tail_i + 1) if tail_i is not None else curr_idx
            return True, total_count, None

        ok, count, _, _, err = cls._verify_single_file(
            log_path, fernet_inst, resolved_hmac, start_hash, start_index
        )
        return ok, count, err

    @classmethod
    def _verify_single_file(
        cls,
        file_path: str,
        fernet_inst: Fernet | None,
        hmac_key: str | None,
        expected_start_hash: str | None = None,
        expected_start_index: int | None = None,
    ) -> tuple[bool, int, str | None, int | None, str | None]:
        expected_prev = expected_start_hash
        expected_idx = expected_start_index
        count = 0
        last_h = None
        last_idx = None

        with open(file_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                s = raw_line.strip()
                if not s:
                    continue

                line_content = s
                if fernet_inst is not None:
                    try:
                        line_content = fernet_inst.decrypt(s.encode("ascii")).decode("utf-8")
                    except Exception as e:
                        return False, count, None, None, f"Line {line_no}: Decryption failed ({e})"
                else:
                    # Bug 8: Clear detection if encrypted without key instead of obscure JSON error
                    if s.startswith("gAAAAA") or (
                        len(s) > 80 and " " not in s and "{" not in s and ":" not in s
                    ):
                        return (
                            False,
                            count,
                            None,
                            None,
                            f"Line {line_no}: Log appears to be encrypted but no decryption key was provided",
                        )

                try:
                    record = json.loads(line_content)
                except Exception as e:
                    return False, count, None, None, f"Line {line_no}: Invalid JSON envelope ({e})"

                if not isinstance(record, dict):
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Record envelope must be a JSON object",
                    )

                # Bug 8: Strict field type validation preventing crashes
                idx = record.get("index")
                prev_h = record.get("prev_hash")
                h = record.get("hash")
                event = record.get("event")

                if idx is None or not isinstance(idx, int):
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Missing or invalid 'index' field",
                    )
                if prev_h is None or not isinstance(prev_h, str):
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Missing or invalid 'prev_hash' field",
                    )
                if h is None or not isinstance(h, str):
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Missing or invalid 'hash' field",
                    )
                if event is None or not isinstance(event, dict):
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Missing or invalid 'event' field",
                    )

                # Bug 1: Segment header handles chain transition across rotated files
                if count == 0:
                    if event.get("__segment_header") is True:
                        if expected_prev is not None and expected_prev != GENESIS_HASH:
                            if prev_h != expected_prev:
                                exp_prev_str = (expected_prev or "")[:12]
                                got_prev_str = prev_h[:12]
                                return (
                                    False,
                                    count,
                                    None,
                                    None,
                                    (
                                        f"Line {line_no} (Index {idx}): Segment header prev_hash {got_prev_str}... "
                                        f"does not match expected previous segment tail {exp_prev_str}..."
                                    ),
                                )
                        else:
                            # Prior rotated segments have rolled off or this segment is verified standalone
                            expected_prev = prev_h
                            expected_idx = idx
                    else:
                        if expected_prev is None:
                            expected_prev = GENESIS_HASH
                            expected_idx = 0

                # Bug 8: Validate monotonic index sequence
                if expected_idx is not None and idx != expected_idx:
                    return (
                        False,
                        count,
                        None,
                        None,
                        f"Line {line_no}: Index sequence broken! Expected index {expected_idx}, got {idx}",
                    )

                if prev_h != expected_prev:
                    exp_prev_str = (expected_prev or "")[:12]
                    got_prev_str = prev_h[:12]
                    return (
                        False,
                        count,
                        None,
                        None,
                        (
                            f"Line {line_no} (Index {idx}): Hash chain broken! "
                            f"Expected prev_hash {exp_prev_str}..., got {got_prev_str}..."
                        ),
                    )

                event_str = json.dumps(event, sort_keys=True)
                recomputed = cls.compute_entry_hash(idx, prev_h, event_str, hmac_key)
                if h != recomputed:
                    # Bug 7: When HMAC key is specified, plain SHA-256 is rejected as tampering
                    return (
                        False,
                        count,
                        None,
                        None,
                        (
                            f"Line {line_no} (Index {idx}): Entry tampering detected! "
                            f"Hash signature does not match payload."
                        ),
                    )

                last_h = h
                last_idx = idx
                expected_prev = h
                expected_idx = idx + 1
                count += 1

        return True, count, last_h, last_idx, None
