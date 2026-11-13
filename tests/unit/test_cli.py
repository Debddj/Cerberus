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
    orig_encrypt = settings.encrypt_logs
    settings.encrypt_logs = False
    try:
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
    finally:
        settings.encrypt_logs = orig_encrypt


def test_cli_verify_log_tampered(tmp_path, capsys):
    log_file = tmp_path / "tampered_audit.log"
    orig_encrypt = settings.encrypt_logs
    settings.encrypt_logs = False
    try:
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
    finally:
        settings.encrypt_logs = orig_encrypt


def test_cli_pin_schema_single_tool(tmp_path, capsys):
    db_file = tmp_path / "pins.db"
    test_args = [
        "cerberus",
        "pin-schema",
        "--server-url",
        "http://mcp.internal:8080",
        "--tool-name",
        "fetch_customer_record",
        "--description",
        "Fetches customer details",
        "--schema",
        '{"type": "object", "properties": {"id": {"type": "string"}}}',
        "--db-path",
        str(db_file),
    ]
    with patch.object(sys, "argv", test_args):
        main()
    captured = capsys.readouterr()
    assert "[PINNED]" in captured.out
    assert "fetch_customer_record" in captured.out
    assert "Successfully pinned 1 tool schema(s)" in captured.out


def test_cli_pin_schema_manifest(tmp_path, capsys):
    db_file = tmp_path / "pins.db"
    manifest_file = tmp_path / "tools_manifest.json"
    manifest_content = {
        "tools": [
            {
                "name": "sql_query",
                "description": "Executes read-only SQL query",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
            },
            {
                "name": "export_report",
                "description": "Exports audit report",
                "inputSchema": {"type": "object", "properties": {"format": {"type": "string"}}},
            },
        ]
    }
    manifest_file.write_text(json.dumps(manifest_content), encoding="utf-8")

    test_args = [
        "cerberus",
        "pin-schema",
        "--server-url",
        "http://analytics.corp:9000",
        "--manifest",
        str(manifest_file),
        "--db-path",
        str(db_file),
    ]
    with patch.object(sys, "argv", test_args):
        main()
    captured = capsys.readouterr()
    assert "[PINNED] Pinned pin for tool 'sql_query'" in captured.out
    assert "[PINNED] Pinned pin for tool 'export_report'" in captured.out
    assert "Successfully pinned 2 tool schema(s)" in captured.out
