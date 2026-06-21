"""IdpGroupRoleMapRepository — data access for idp_group_role_map (F-014 STEP 3/D6).

Per-tenant IdP group → role mapping. Fail-closed (ADR-0017 D6, R4): an IdP group
with no row here grants NO access; an assertion whose groups map to nothing
resolves to None and the caller MUST deny.

SECURITY INVARIANTS:
1. caller_tenant_id-guarded (app-layer defense-in-depth on top of RLS — the same
   pattern as the STEP-2 repos). All writes/reads include AND tenant_id =
   caller_tenant_id.
2. The role domain is LOCKED to ('tenant_admin', 'tenant_auditor') — enforced by
   the CHECK constraint in migration 0014 and by _VALID_ROLES here; an unknown
   role raises ValueError before any DB write.
3. resolve_role() returns the HIGHEST mapped role across the supplied groups, or
   None when none of them map (fail-closed). 'tenant_admin' > 'tenant_auditor'.

TYPE CONTRACT:
  id / tenant_id are VARCHAR(64); accepted/returned as plain str. IDs are
  str(uuid.uuid4()) at the app layer.

SESSION REQUIREMENT:
  All methods require a tenant-scoped session (get_tenant_session(tenant_id)).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import IdpGroupRoleMap

# Role precedence: higher index = lower privilege (same order as the STEP-2 repo).
_ROLE_PRECEDENCE: list[str] = ["tenant_admin", "tenant_auditor"]
_VALID_ROLES: frozenset[str] = frozenset(_ROLE_PRECEDENCE)


def _validate_role(role: str) -> None:
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(_VALID_ROLES)!r}, got {role!r}")


class IdpGroupRoleMapRepository:
    """Data-access object for idp_group_role_map. caller_tenant_id-scoped."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def set_mapping(
        self,
        *,
        tenant_id: str,
        idp_group: str,
        role: str,
        caller_tenant_id: str,
    ) -> IdpGroupRoleMap:
        """Upsert the (tenant_id, idp_group) → role mapping.

        One mapping per (tenant_id, idp_group) (unique constraint). On conflict the
        existing row's role is UPDATEd to the new value. Raises ValueError for an
        unknown role; caller_tenant_id must match tenant_id (defense-in-depth).
        """
        _validate_role(role)
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )

        stmt = (
            pg_insert(IdpGroupRoleMap)
            .values(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                idp_group=idp_group,
                role=role,
            )
            .on_conflict_do_update(
                constraint="uq_idp_group_role_map_tenant_group",
                set_={"role": role},
            )
            .returning(IdpGroupRoleMap)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def list_for_tenant(
        self, *, tenant_id: str, caller_tenant_id: str
    ) -> list[dict[str, Any]]:
        """Return all group→role mappings for the tenant (ordered by group)."""
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        stmt = (
            select(IdpGroupRoleMap)
            .where(IdpGroupRoleMap.tenant_id == caller_tenant_id)
            .order_by(IdpGroupRoleMap.idp_group)
        )
        result = await self._session.execute(stmt)
        return [
            {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "idp_group": row.idp_group,
                "role": row.role,
                "created_at": row.created_at,
            }
            for row in result.scalars().all()
        ]

    async def resolve_role(
        self, *, tenant_id: str, groups: list[str], caller_tenant_id: str
    ) -> str | None:
        """Return the HIGHEST mapped role across *groups*, or None (fail-closed, D6).

        Used by STEP 6 (group→role resolution after a verified assertion). An empty
        group list, or groups none of which are mapped for this tenant, resolves to
        None — the caller MUST deny and NOT provision (ADR-0017 D6, vector 14).
        """
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        if not groups:
            return None
        stmt = select(IdpGroupRoleMap.role).where(
            IdpGroupRoleMap.tenant_id == caller_tenant_id,
            IdpGroupRoleMap.idp_group.in_(groups),
        )
        result = await self._session.execute(stmt)
        mapped = set(result.scalars().all())
        if not mapped:
            return None
        for role in _ROLE_PRECEDENCE:
            if role in mapped:
                return role
        return None  # fail-closed (unreachable while CHECK constraint holds)
