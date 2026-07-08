"""Register / list / revoke a tenant's allow-listed MCP servers (F-026, ADR-0032).

Validates server_url via the SSRF guard BEFORE any write (mirrors
admin/webhooks.py::create_webhook_config's discipline exactly — a denied URL
never reaches the DB), then persists via TenantMcpServerRepository.
"""

from __future__ import annotations

import re

from mcp_gateway.exceptions import InvalidServerName, ServerUrlRejected
from mcp_gateway.url_guard import validate_mcp_server_url
from persistence.database import get_tenant_session
from persistence.models.tenant_mcp_server import TenantMcpServer
from persistence.repositories.tenant_mcp_server_repository import TenantMcpServerRepository

# Same naming convention as tenant/team/project names (admin/schemas.py's _TENANT_NAME_RE).
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise InvalidServerName(
            f"server name must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$, got {name!r}"
        )


async def register_server(
    tenant_id: str,
    name: str,
    server_url: str,
    *,
    team_id: str | None = None,
    project_id: str | None = None,
) -> TenantMcpServer:
    """Validate + persist a new allow-listed MCP server for a tenant.

    Raises InvalidServerName / ServerUrlRejected before touching the DB.
    """
    _validate_name(name)
    guard_result = validate_mcp_server_url(server_url)
    if not guard_result.allowed:
        raise ServerUrlRejected(f"server_url rejected: {guard_result.reason}")

    async with get_tenant_session(tenant_id) as ts:
        server = await TenantMcpServerRepository(ts).create(
            tenant_id=tenant_id,
            name=name,
            server_url=server_url,
            team_id=team_id,
            project_id=project_id,
        )
        await ts.commit()
        return server


async def list_servers(tenant_id: str, *, active_only: bool = True) -> list[TenantMcpServer]:
    async with get_tenant_session(tenant_id) as ts:
        return await TenantMcpServerRepository(ts).list_for_tenant(
            tenant_id, active_only=active_only
        )


async def revoke_server(tenant_id: str, server_id: str) -> TenantMcpServer:
    """Soft-deactivate an allow-listed server (no hard delete — mirrors the
    tenant/team/project/webhook_config convention)."""
    async with get_tenant_session(tenant_id) as ts:
        server = await TenantMcpServerRepository(ts).deactivate(
            server_id, caller_tenant_id=tenant_id
        )
        await ts.commit()
        return server


async def is_server_allowed(tenant_id: str, server_url: str) -> bool:
    """True iff server_url is a registered, active server for this tenant.

    This is the check a future live MCP proxy call site MUST invoke before
    dispatching a single byte to an external server — see
    docs/followups/f-026-mcp-proxy-endpoint.md.
    """
    async with get_tenant_session(tenant_id) as ts:
        return await TenantMcpServerRepository(ts).is_allowed(tenant_id, server_url)
