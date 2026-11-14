import hashlib
import json
import os
import stat
import sys

import pytest

from cerberus.config import settings
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.models import ToolCallEvent


@pytest.mark.asyncio
async def test_audit_logger_hash_chain_and_encryption(tmp_path):
    log_file = str(tmp_path / "test_audit.jsonl")
    settings.encrypt_logs = True
    settings.log_encryption_key = ""

    logger = AuditLogger(log_path=log_file)
    assert logger._fernet is not None
    key = logger._raw_key

    # Write 3 sequential events
    for i in range(3):
        event = ToolCallEvent(
            session_id=f"s-{i}",
            agent_id=f"a-{i}",
            tool_name=f"tool_{i}",
            tool_server="srv",
            parameters={"index": i, "secret": f"hidden_{i}"},
        )
        await logger.log_event(event)

    assert os.path.exists(log_file)

    # Verify complete ledger integrity
    is_valid, count, err = AuditLogger.verify_ledger(log_file, encryption_key=key)
    assert is_valid is True
    assert count == 3
    assert err is None

    # Test tampering detection: alter one line in the middle
    with open(log_file, "r", encoding="utf-8") as f:  # noqa: ASYNC230
        lines = [line.strip() for line in f if line.strip()]

    # Decrypt middle entry, alter payload, re-encrypt with same key
    middle_json = logger.decrypt_log_line(lines[1])
    record = json.loads(middle_json)
    record["event"]["tool_name"] = "tampered_tool"
    tampered_raw = json.dumps(record, sort_keys=True)
    lines[1] = logger._fernet.encrypt(tampered_raw.encode("utf-8")).decode("ascii")

    tampered_log = str(tmp_path / "tampered_audit.jsonl")
    with open(tampered_log, "w", encoding="utf-8") as f:  # noqa: ASYNC230
        f.write("\n".join(lines) + "\n")

    # Verification must flag tampering
    is_tampered, _, err_msg = AuditLogger.verify_ledger(tampered_log, encryption_key=key)
    assert is_tampered is False
    assert isinstance(err_msg, str)
    assert "tampering" in (err_msg or "").lower() or "broken" in (err_msg or "").lower()


def test_bug3_encryption_fails_open_with_invalid_key(tmp_path):
    """Bug 3: Encryption must fail hard at startup with an invalid key when encrypt_logs=True."""
    log_file = str(tmp_path / "fail_open_test.jsonl")
    settings.encrypt_logs = True

    with pytest.raises(RuntimeError, match="Invalid CERBERUS_LOG_ENCRYPTION_KEY"):
        AuditLogger(log_path=log_file, key="invalid_non_base64_key")


def test_bug4_key_file_secure_permissions(tmp_path):
    """Bug 4: Key files must be created with secure 0o600 permissions."""
    log_file = str(tmp_path / "secure_key_test.jsonl")
    settings.encrypt_logs = True
    settings.log_encryption_key = ""

    AuditLogger(log_path=log_file)
    key_path = str(tmp_path / "secure_key_test.key")
    assert os.path.exists(key_path)

    # On POSIX, assert permissions are 0o600 (owner only)
    if sys.platform != "win32":
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600


def test_bug5_silent_chain_reset_fails_hard(tmp_path):
    """Bug 5: Corrupted tail line must fail fast at startup rather than resetting to genesis."""
    log_file = str(tmp_path / "corrupt_test.jsonl")
    settings.encrypt_logs = False

    # Write corrupt JSON line
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("corrupted_non_json_line\n")

    with pytest.raises(RuntimeError, match="Could not restore audit hash chain"):
        AuditLogger(log_path=log_file)


def test_bug6_torn_write_recovery(tmp_path):
    """Bug 6: Torn write without newline must be truncated at startup, restoring prior valid records."""
    log_file = str(tmp_path / "torn_test.jsonl")
    settings.encrypt_logs = False
    AuditLogger(log_path=log_file)

    # Write 1 valid record
    rec = {
        "index": 0,
        "prev_hash": "0" * 64,
        "event": {"tool_name": "test"},
        "hash": AuditLogger.compute_entry_hash(
            0, "0" * 64, json.dumps({"tool_name": "test"}, sort_keys=True)
        ),
    }
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
        # Incomplete torn write
        f.write('{"index": 1, "partial_t')

    # Reopen logger: startup must truncate the torn line and restore index 1
    logger2 = AuditLogger(log_path=log_file)
    assert logger2._entry_index == 1
    assert logger2._last_hash == rec["hash"]


def test_bug7_hmac_prevents_forgery(tmp_path):
    """Bug 7: Ledger uses HMAC secret key; recomputing with plain SHA-256 is detected as tampering."""
    log_file = str(tmp_path / "hmac_test.jsonl")
    settings.encrypt_logs = False
    hmac_key = "super_secret_hmac_signing_key_123"

    logger = AuditLogger(log_path=log_file, hmac_key=hmac_key)
    raw_event = json.dumps({"tool": "ping"}, sort_keys=True)
    h = logger.compute_entry_hash(0, "0" * 64, raw_event, hmac_key=hmac_key)

    record = {"index": 0, "prev_hash": "0" * 64, "event": {"tool": "ping"}, "hash": h}
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    # Verifies with correct HMAC key
    valid, count, err = AuditLogger.verify_ledger(log_file, hmac_key=hmac_key)
    assert valid is True
    assert count == 1

    # Tamper payload and forge with plain SHA-256 (no secret)
    forged_event = {"tool": "malicious"}
    forged_raw = json.dumps(forged_event, sort_keys=True)
    forged_sha = hashlib.sha256(f"0:{'0' * 64}:{forged_raw}".encode()).hexdigest()
    forged_rec = {"index": 0, "prev_hash": "0" * 64, "event": forged_event, "hash": forged_sha}

    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(forged_rec, sort_keys=True) + "\n")

    # Must fail because HMAC signature is missing/invalid
    valid, _, err = AuditLogger.verify_ledger(log_file, hmac_key=hmac_key)
    assert valid is False
    assert isinstance(err, str)
    assert "tampering" in (err or "").lower()


def test_bug8_verifier_safe_error_messages(tmp_path):
    """Bug 8: Verifier must not crash on missing fields and clearly report encrypted-without-key."""
    log_file = str(tmp_path / "safe_err_test.jsonl")

    # Case 1: Encrypted file verified without key
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(
            "gAAAAABnRandomFernetLikeTokenDataThatIsNotPlaintextJSON123456789012345678901234567890\n"
        )

    valid, _count, err = AuditLogger.verify_ledger(log_file, encryption_key=None)
    assert valid is False
    assert isinstance(err, str)
    assert "encrypted" in (err or "").lower()

    # Case 2: Missing prev_hash field
    rec_bad = {"index": 0, "hash": "abc", "event": {}}
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(rec_bad) + "\n")

    valid, _count, err = AuditLogger.verify_ledger(log_file)
    assert valid is False
    assert isinstance(err, str)
    assert "missing or invalid 'prev_hash'" in (err or "").lower()


@pytest.mark.asyncio
async def test_bug1_and_9_rotation_segment_header_and_index_continuity(tmp_path):
    """Bugs 1 & 9: Log rotation writes segment header and maintains monotonic global index."""
    log_file = str(tmp_path / "rot_test.jsonl")
    settings.encrypt_logs = False
    # Set max_bytes very low to trigger rotation quickly
    logger = AuditLogger(log_path=log_file, max_bytes=300, backup_count=3)

    for i in range(6):
        ev = ToolCallEvent(
            session_id=f"s-{i}",
            agent_id="test-agent",
            tool_name="tool_call",
            tool_server="test_srv",
            parameters={"param": f"value_{i}" * 5},
        )
        await logger.log_event(ev)

    # Check that rotated file exists
    assert os.path.exists(f"{log_file}.1")

    # Restart logger: index must continue monotonically, not reset to current file line count
    logger_restarted = AuditLogger(log_path=log_file, max_bytes=300, backup_count=3)
    assert logger_restarted._entry_index >= 6

    # Verify ledger across rotated segments
    valid, count, err = AuditLogger.verify_ledger(log_file, walk_segments=True)
    assert valid is True, f"Verification failed with: {err} (count: {count})"
    assert count >= 6
    assert err is None
