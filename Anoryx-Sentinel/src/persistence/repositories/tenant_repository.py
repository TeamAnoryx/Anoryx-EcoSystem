"""TenantRepository — data access for the tenants table (F-003).

Uses SQLAlchemy 2.x async session. All queries are parameterized.

Tenant isolation enforcement (caller_tenant_id scoping on get_by_id, RLS role
switching) is deferred to F-003b. F-003 ships the schema and repository layer
only; see ADR-0004 for the full scope statement.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.tenant import Tenant


class TenantNotFoundError(Exception):
    """Raised when a tenant lookup finds no matching row."""


class TenantRepository:
    """Data-access object for the tenants table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, name: str, display_name: str | None = None) -> Tenant:
        """Create a new tenant with a generated UUID v4 tenant_id."""
        tenant = Tenant(
            tenant_id=str(uuid.uuid4()),
            name=name,
            display_name=display_name,
            is_active=True,
        )
        self._session.add(tenant)
        await self._session.flush()
        return tenant

    async def get_by_id(self, tenant_id: str) -> Tenant:
        """Return the tenant for tenant_id, or raise TenantNotFoundError.

        PK lookup only. Tenant scoping is deferred to F-003b.
        """
        stmt = select(Tenant).where(Tenant.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        tenant = result.scalar_one_or_none()
        if tenant is None:
            raise TenantNotFoundError(f"Tenant not found: {tenant_id!r}")
        return tenant

    async def list_active(self) -> list[Tenant]:
        """Return all active tenants, ordered by name (privileged operation)."""
        stmt = select(Tenant).where(Tenant.is_active.is_(True)).order_by(Tenant.name)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def deactivate(self, tenant_id: str) -> Tenant:
        """Mark a tenant as inactive (soft delete). Returns updated row."""
        tenant = await self.get_by_id(tenant_id)
        tenant.is_active = False
        tenant.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return tenant
