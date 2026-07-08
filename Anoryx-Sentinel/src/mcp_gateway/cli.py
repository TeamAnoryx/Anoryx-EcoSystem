"""sentinel-mcp — operator CLI for F-026 MCP-server allow-listing + payload
inspection preview (ADR-0032).

    sentinel-mcp allowlist add --tenant <id> --name docs-search --url https://mcp.example.com
    sentinel-mcp allowlist list --tenant <id>
    sentinel-mcp allowlist revoke --tenant <id> --server-id <id>
    sentinel-mcp inspect --tenant <id> --team <id> --project <id> --agent <id> --text "..."

`inspect` is a preview/testing tool — it runs the SAME F-005 detector chain
/v1/chat/completions uses against arbitrary text (e.g. a captured MCP
tools/call payload), so an operator can verify governance behavior before any
live proxy exists. See src/mcp_gateway/__init__.py for why this is a CLI, not
an HTTP endpoint.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid

import structlog

from gateway.context import TenantContext
from mcp_gateway.allowlist import list_servers, register_server, revoke_server
from mcp_gateway.exceptions import McpGatewayError
from mcp_gateway.inspection import inspect_mcp_payload
from orchestration.exceptions import HookBlockedError, HookFailSafeError

log = structlog.get_logger(__name__)


async def _cmd_allowlist_add(
    tenant_id: str, name: str, url: str, team_id: str | None, project_id: str | None
) -> int:
    try:
        server = await register_server(tenant_id, name, url, team_id=team_id, project_id=project_id)
    except McpGatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"registered: server_id={server.server_id} name={server.name} url={server.server_url}")
    return 0


async def _cmd_allowlist_list(tenant_id: str, all_: bool) -> int:
    servers = await list_servers(tenant_id, active_only=not all_)
    if not servers:
        print("no MCP servers registered")
        return 0
    for s in servers:
        status = "active" if s.is_active else "inactive"
        print(f"{s.server_id}\t{s.name}\t{s.server_url}\t{status}")
    return 0


async def _cmd_allowlist_revoke(tenant_id: str, server_id: str) -> int:
    try:
        server = await revoke_server(tenant_id, server_id)
    except McpGatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"revoked: server_id={server.server_id} name={server.name}")
    return 0


async def _cmd_inspect(
    tenant_id: str, team_id: str, project_id: str, agent_id: str, text: str
) -> int:
    tenant_context = TenantContext(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        virtual_key_id="cli-preview",
    )
    request_id = "mcp-" + uuid.uuid4().hex
    try:
        result = await inspect_mcp_payload(
            text, tenant_context=tenant_context, request_id=request_id
        )
    except HookBlockedError as exc:
        print(f"BLOCKED: {exc.error_code}", file=sys.stderr)
        return 1
    except HookFailSafeError as exc:
        print(f"BLOCKED (fail-safe — inspection error): {exc}", file=sys.stderr)
        return 1
    if result != text:
        print("MASKED (PII/secret content was redacted):")
    else:
        print("PASS (no PII/injection/secret detected):")
    print(result)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-mcp", description="Anoryx Sentinel MCP-gateway governance CLI (F-026)."
    )
    groups = parser.add_subparsers(dest="group", required=True)

    allowlist_p = groups.add_parser("allowlist", help="Per-tenant MCP server allow-list")
    acmds = allowlist_p.add_subparsers(dest="cmd", required=True)

    add = acmds.add_parser("add", help="Register a new allow-listed MCP server.")
    add.add_argument("--tenant", required=True, dest="tenant_id")
    add.add_argument("--name", required=True)
    add.add_argument("--url", required=True)
    add.add_argument("--team", default=None, dest="team_id")
    add.add_argument("--project", default=None, dest="project_id")

    lst = acmds.add_parser("list", help="List a tenant's allow-listed MCP servers.")
    lst.add_argument("--tenant", required=True, dest="tenant_id")
    lst.add_argument("--all", action="store_true", help="Include inactive (revoked) servers.")

    revoke = acmds.add_parser("revoke", help="Soft-deactivate an allow-listed MCP server.")
    revoke.add_argument("--tenant", required=True, dest="tenant_id")
    revoke.add_argument("--server-id", required=True)

    inspect_p = groups.add_parser(
        "inspect", help="Preview F-005 inspection (PII/injection/secret) on arbitrary text."
    )
    inspect_p.add_argument("--tenant", required=True, dest="tenant_id")
    inspect_p.add_argument("--team", required=True, dest="team_id")
    inspect_p.add_argument("--project", required=True, dest="project_id")
    inspect_p.add_argument("--agent", required=True, dest="agent_id")
    inspect_p.add_argument("--text", required=True, help="Payload text to inspect.")

    args = parser.parse_args(argv)

    if args.group == "allowlist":
        if args.cmd == "add":
            return asyncio.run(
                _cmd_allowlist_add(
                    args.tenant_id, args.name, args.url, args.team_id, args.project_id
                )
            )
        if args.cmd == "list":
            return asyncio.run(_cmd_allowlist_list(args.tenant_id, args.all))
        if args.cmd == "revoke":
            return asyncio.run(_cmd_allowlist_revoke(args.tenant_id, args.server_id))
    elif args.group == "inspect":
        return asyncio.run(
            _cmd_inspect(args.tenant_id, args.team_id, args.project_id, args.agent_id, args.text)
        )
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
