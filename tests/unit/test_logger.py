import json
import os

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
    assert err_msg is not None
    assert "tampering" in err_msg.lower() or "broken" in err_msg.lower()
