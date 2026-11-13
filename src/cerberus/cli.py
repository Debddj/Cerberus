import argparse
import asyncio
import sys

import uvicorn


def main():
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="Cerberus Runtime Behavioral Firewall for MCP Agents",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # HTTP proxy command
    http_p = subparsers.add_parser("http", help="Run Cerberus HTTP JSON-RPC Gateway")
    http_p.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    http_p.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")

    # Stdio proxy command (Bug 15)
    stdio_p = subparsers.add_parser("stdio", help="Run Cerberus stdio proxy wrapping an MCP server")
    stdio_p.add_argument("--upstream", required=True, help="Command to run upstream MCP server")
    stdio_p.add_argument("args", nargs="*", help="Arguments for upstream command")

    # Verify log command (Pillar 4)
    verify_p = subparsers.add_parser(
        "verify-log", help="Verify integrity of tamper-evident forensic audit log"
    )
    verify_p.add_argument(
        "--log-path",
        default="cerberus_audit.jsonl",
        help="Path to audit log file (default: cerberus_audit.jsonl)",
    )
    verify_p.add_argument("--key", default=None, help="Decryption key if logs are encrypted")
    verify_p.add_argument(
        "--hmac-key", default=None, help="HMAC key if logs are tamper-protected with HMAC"
    )
    verify_p.add_argument(
        "--walk-segments",
        action="store_true",
        help="Verify all rotated log segments (.1 to .N plus current)",
    )

    # Issue token command (Pillar 7)
    token_p = subparsers.add_parser("issue-token", help="Issue an HMAC-signed agent identity token")
    token_p.add_argument("--agent-id", required=True, help="Agent ID")
    token_p.add_argument(
        "--secret", default=None, help="HMAC secret key (defaults to config or env)"
    )
    token_p.add_argument(
        "--ttl", type=int, default=3600, help="Token validity lifetime in seconds (default: 3600)"
    )

    # Pin schema command (Design 9 - Pre-pinning TOFU mitigation)
    pin_p = subparsers.add_parser(
        "pin-schema", help="Pre-pin tool schemas to prevent Trust-On-First-Use (TOFU) tampering"
    )
    pin_p.add_argument("--server-url", required=True, help="Upstream MCP server URL or identifier")
    pin_p.add_argument(
        "--manifest",
        default=None,
        help="Path to JSON manifest containing tool definitions (dict or list of tools)",
    )
    pin_p.add_argument("--tool-name", default=None, help="Name of tool to pin (single tool mode)")
    pin_p.add_argument("--description", default="", help="Description of tool (single tool mode)")
    pin_p.add_argument(
        "--schema",
        default="{}",
        help="Input JSON schema for tool as JSON string or file path (single tool mode)",
    )
    pin_p.add_argument(
        "--db-path",
        default="cerberus_pins.db",
        help="Path to SQLite pins database (default: cerberus_pins.db)",
    )
    pin_p.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing pin if tool is already pinned",
    )

    parsed = parser.parse_args()

    if parsed.command == "http":
        uvicorn.run("cerberus.proxy.server:app", host=parsed.host, port=parsed.port)
    elif parsed.command == "stdio":
        from cerberus.proxy.stdio_server import run_stdio_proxy

        asyncio.run(run_stdio_proxy(command=parsed.upstream, args=parsed.args))
    elif parsed.command == "verify-log":
        from cerberus.proxy.logger import AuditLogger

        is_valid, count, reason = AuditLogger.verify_ledger(
            parsed.log_path,
            encryption_key=parsed.key,
            hmac_key=parsed.hmac_key,
            walk_segments=parsed.walk_segments,
        )
        if is_valid:
            print(f"[SUCCESS] Audit ledger integrity verified: {count} records valid.")
            sys.exit(0)
        else:
            print(f"[FAIL] Audit ledger verification failed: {reason}", file=sys.stderr)
            sys.exit(1)
    elif parsed.command == "issue-token":
        from cerberus.proxy.auth import HMACAuthenticator

        auth = HMACAuthenticator(secret_key=parsed.secret)
        token = auth.issue_token(agent_id=parsed.agent_id, ttl_seconds=parsed.ttl)
        print(f"Issued Token for Agent '{parsed.agent_id}' (TTL: {parsed.ttl}s):\n{token}")
    elif parsed.command == "pin-schema":
        import json
        import os

        from cerberus.scanner.schema_pinner import SchemaPinner

        pinner = SchemaPinner(db_path=parsed.db_path)

        async def _run_pinning():
            pinned_count = 0
            if parsed.manifest:
                if not os.path.exists(parsed.manifest):
                    print(f"[FAIL] Manifest file not found: {parsed.manifest}", file=sys.stderr)
                    sys.exit(1)
                with open(parsed.manifest, "r", encoding="utf-8") as f:  # noqa: ASYNC230
                    manifest_data = json.load(f)

                tools_list = (
                    manifest_data.get("tools", manifest_data)
                    if isinstance(manifest_data, dict)
                    else manifest_data
                )
                if not isinstance(tools_list, list):
                    print(
                        "[FAIL] Manifest must contain a 'tools' list or be a JSON array of tool definitions",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                for tool_def in tools_list:
                    t_name = tool_def.get("name")
                    t_desc = tool_def.get("description", "")
                    t_schema = tool_def.get("inputSchema", tool_def.get("schema", {}))
                    if not t_name:
                        continue
                    ok, msg = await pinner.pin_schema(
                        server_url=parsed.server_url,
                        tool_name=t_name,
                        desc=t_desc,
                        schema=t_schema,
                        overwrite=parsed.overwrite,
                    )
                    status_tag = "[PINNED]" if ok else "[SKIPPED]"
                    print(f"{status_tag} {msg}")
                    if ok:
                        pinned_count += 1
            elif parsed.tool_name:
                schema_dict = {}
                if parsed.schema:
                    try:
                        schema_dict = json.loads(parsed.schema)
                    except Exception:
                        if os.path.exists(parsed.schema):
                            with open(parsed.schema, "r", encoding="utf-8") as f:  # noqa: ASYNC230
                                schema_dict = json.load(f)
                ok, msg = await pinner.pin_schema(
                    server_url=parsed.server_url,
                    tool_name=parsed.tool_name,
                    desc=parsed.description,
                    schema=schema_dict,
                    overwrite=parsed.overwrite,
                )
                status_tag = "[PINNED]" if ok else "[FAIL]"
                print(f"{status_tag} {msg}")
                if not ok:
                    sys.exit(1)
                pinned_count += 1
            else:
                print("[FAIL] Either --manifest or --tool-name must be specified", file=sys.stderr)
                sys.exit(1)

            print(
                f"[SUCCESS] Successfully pinned {pinned_count} tool schema(s) into {parsed.db_path}."
            )

        asyncio.run(_run_pinning())


if __name__ == "__main__":
    main()
