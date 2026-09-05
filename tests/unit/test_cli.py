import asyncio
import json
import sys
from unittest.mock import patch

import pytest

from cerberus.cli import main
from cerberus.config import settings
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.models import ToolCallEvent


def test_cli_issue_token(capsys):
    test_args = ["cerberus", "issue-token", "--agent-id", "agent-alpha", "--ttl", "1800"]
    with patch.object(sys, "argv", test_args):
        main()
    captured = capsys.readouterr()
    assert "Issued Token for Agent 'agent-alpha'" in captured.out
    assert "TTL: 1800s" in captured.out


def test_cli_verify_log_valid(tmp_path, capsys):
    log_file = tmp_path / "valid_audit.log"
    settings.encrypt_logs = False
    logger = AuditLogger(log_path=str(log_file))

    async def log_events():
        await logger.log_event(
            ToolCallEvent(session_id="s1", agent_id="a1", tool_name="tool_1", tool_server="srv")
        )
        await logger.log_event(
            ToolCallEvent(session_id="s1", agent_id="a1", tool_name="tool_2", tool_server="srv")
        )

    asyncio.run(log_events())

    test_args = ["cerberus", "verify-log", "--log-path", str(log_file)]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "[SUCCESS] Audit ledger integrity verified" in captured.out
    assert "2 records" in captured.out


def test_cli_verify_log_tampered(tmp_path, capsys):
    log_file = tmp_path / "tampered_audit.log"
    settings.encrypt_logs = False
    logger = AuditLogger(log_path=str(log_file))

    async def log_events():
        await logger.log_event(
            ToolCallEvent(session_id="s1", agent_id="a1", tool_name="tool_1", tool_server="srv")
        )
        await logger.log_event(
            ToolCallEvent(session_id="s1", agent_id="a1", tool_name="tool_2", tool_server="srv")
        )

    asyncio.run(log_events())

    # Tamper with the file
    content = log_file.read_text().splitlines()
    data = json.loads(content[0])
    data["event"]["tool_name"] = "malicious_tool"
    content[0] = json.dumps(data)
    log_file.write_text("\n".join(content) + "\n")

    test_args = ["cerberus", "verify-log", "--log-path", str(log_file)]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "[FAIL] Audit ledger verification failed" in captured.err
