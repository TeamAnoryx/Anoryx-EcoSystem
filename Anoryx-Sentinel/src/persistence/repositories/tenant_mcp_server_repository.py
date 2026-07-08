"""TenantMcpServerRepository — data access for the tenant_mcp_servers table
(F-026, ADR-0032, migration 0033).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.tenant_mcp_server import TenantMcpServer


class TenantMcpServerNotFoundError(Exception):
    """Raised when a server lookup finds no matching row."""


class TenantMcpServerRepository:
    """Data-access object for the tenant_mcp_servers table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: str,
        name: str,
        server_url: str,
        *,
        team_id: str | None = None,
        project_id: str | None = None,
    ) -> TenantMcpServer:
        """Register a new allow-listed MCP server. Caller MUST have already
        validated server_url via mcp_gateway.url_guard (mirrors
        admin/webhooks.py's "SSRF guard BEFORE any persistence" discipline —
        this repository does not itself call the guard)."""
        server = TenantMcpServer(
            server_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            name=name,
            server_url=server_url,
            is_active=True,
        )
        self._session.add(server)
        await self._session.flush()
        return server

    async def get_by_id(self, server_id: str, caller_tenant_id: str) -> TenantMcpServer:
        """Return the server for server_id, or raise TenantMcpServerNotFoundError.

        caller_tenant_id is REQUIRED (mirrors TeamRepository/ProjectRepository's
        LOW-1 defense-in-depth guard, ADR-0005 round-2)."""
        stmt = select(TenantMcpServer).where(TenantMcpServer.server_id == server_id)
        stmt = stmt.where(TenantMcpServer.tenant_id == caller_tenant_id)
        result = await self._session.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            raise TenantMcpServerNotFoundError(f"MCP server not found: {server_id!r}")
        return server

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        active_only: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TenantMcpServer]:
        """Return servers for a tenant, ordered by name. Default: active only.

        Default limit: 100. Hard max: 1000. Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, 1000)
        stmt = select(TenantMcpServer).where(TenantMcpServer.tenant_id == tenant_id)
        if active_only:
            stmt = stmt.where(TenantMcpServer.is_active.is_(True))
        stmt = stmt.order_by(TenantMcpServer.name).limit(effective_limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def is_allowed(self, tenant_id: str, server_url: str) -> bool:
        """True iff server_url is a registered, active server for this tenant.

        Exact string match on server_url — no partial/prefix matching (a
        near-match must not silently authorize a different endpoint). This is
        the check any future MCP proxy call site (docs/followups/
        f-026-mcp-proxy-endpoint.md) MUST call before dispatching a single
        byte to an external server.
        """
        stmt = select(TenantMcpServer.server_id).where(
            TenantMcpServer.tenant_id == tenant_id,
            TenantMcpServer.server_url == server_url,
            TenantMcpServer.is_active.is_(True),
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def deactivate(self, server_id: str, caller_tenant_id: str) -> TenantMcpServer:
        """Soft-delete a server by marking it inactive."""
        server = await self.get_by_id(server_id, caller_tenant_id=caller_tenant_id)
        server.is_active = False
        server.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return server
