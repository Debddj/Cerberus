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
    http_p.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
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
        "--log-path", default="audit.log", help="Path to audit log file (default: audit.log)"
    )
    verify_p.add_argument("--key", default=None, help="Decryption key if logs are encrypted")

    # Issue token command (Pillar 7)
    token_p = subparsers.add_parser("issue-token", help="Issue an HMAC-signed agent identity token")
    token_p.add_argument("--agent-id", required=True, help="Agent ID")
    token_p.add_argument(
        "--secret", default=None, help="HMAC secret key (defaults to config or env)"
    )
    token_p.add_argument(
        "--ttl", type=int, default=3600, help="Token validity lifetime in seconds (default: 3600)"
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
            parsed.log_path, encryption_key=parsed.key
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


if __name__ == "__main__":
    main()
