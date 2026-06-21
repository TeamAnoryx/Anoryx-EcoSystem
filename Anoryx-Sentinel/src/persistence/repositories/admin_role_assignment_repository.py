"""AdminRoleAssignmentRepository — data access for admin_roles + admin_role_assignments (F-014).

STEP 2.

SECURITY INVARIANTS:
1. All mutations and queries are caller_tenant_id-scoped (app-layer defense-in-depth
   on top of RLS — the same pattern as VirtualApiKeyRepository and TeamRepository).
2. A user with no assignment has NO access (fail-closed, ADR-0017 D1 R4).
   highest_role_for_user() returns None when no assignments exist — callers MUST
   deny access on None.
3. provision_tenant_roles() seeds the two admin_roles rows lazily (idempotent).
   It is safe to call on every SSO login before the first assignment.
4. The role domain is LOCKED to ('tenant_admin', 'tenant_auditor') — enforced by
   a CHECK constraint in the migration and by _VALID_ROLES here at the app layer.
   Callers passing an unknown role string receive ValueError before any DB write.

TYPE CONTRACT:
  All id/tenant_id/fk columns are VARCHAR(64) in the schema. This repository
  accepts and returns them as plain str. IDs are generated as str(uuid.uuid4()).
  No uuid.UUID() conversion is performed before DB writes.

Role precedence (highest_role_for_user):
  tenant_admin > tenant_auditor
  A user with both assignments resolves to tenant_admin.

SESSION REQUIREMENT:
  All methods require a tenant-scoped session (get_tenant_session(tenant_id)).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import AdminRole, AdminRoleAssignment

# Role precedence: higher index = lower privilege.
_ROLE_PRECEDENCE: list[str] = ["tenant_admin", "tenant_auditor"]
_VALID_ROLES: frozenset[str] = frozenset(_ROLE_PRECEDENCE)


def _validate_role(role: str) -> None:
    """Raise ValueError if role is not in the locked domain."""
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(_VALID_ROLES)!r}, got {role!r}")


class AdminRoleAssignmentRepository:
    """Data-access object for admin_roles + admin_role_assignments."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def provision_tenant_roles(self, *, tenant_id: str) -> None:
        """Lazily seed the two admin_roles rows for a tenant (idempotent).

        Inserts 'tenant_admin' and 'tenant_auditor' rows for tenant_id using
        ON CONFLICT DO NOTHING so repeated calls are safe and cheap.

        Called before the first assignment for a tenant to ensure the role rows
        exist. This is the substitute for global migration-time seeding — there
        are no tenants at migrate time (ADR-0017 D1 note).
        """
        for role_name in _ROLE_PRECEDENCE:
            stmt = (
                pg_insert(AdminRole)
                .values(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    role_name=role_name,
                )
                .on_conflict_do_nothing(constraint="uq_admin_roles_tenant_role")
            )
            await self._session.execute(stmt)

    async def assign(
        self,
        *,
        tenant_id: str,
        admin_user_id: str,
        role: str,
        caller_tenant_id: str,
    ) -> AdminRoleAssignment:
        """Assign a role to an admin_user (idempotent via ON CONFLICT DO NOTHING).

        Returns the existing or newly inserted AdminRoleAssignment row.
        Raises ValueError for an unknown role.
        caller_tenant_id must match tenant_id (defense-in-depth guard).
        """
        _validate_role(role)

        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )

        row_id = str(uuid.uuid4())

        stmt = (
            pg_insert(AdminRoleAssignment)
            .values(
                id=row_id,
                tenant_id=tenant_id,
                admin_user_id=admin_user_id,
                role=role,
            )
            .on_conflict_do_nothing(constraint="uq_admin_role_assignments_user_role")
            .returning(AdminRoleAssignment)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            # Conflict — fetch the existing row.
            existing = await self._session.execute(
                select(AdminRoleAssignment).where(
                    AdminRoleAssignment.tenant_id == tenant_id,
                    AdminRoleAssignment.admin_user_id == admin_user_id,
                    AdminRoleAssignment.role == role,
                )
            )
            row = existing.scalar_one()
        return row

    async def list_roles_for_user(
        self,
        *,
        admin_user_id: str,
        caller_tenant_id: str,
    ) -> list[str]:
        """Return all role strings assigned to admin_user_id within caller_tenant_id.

        Returns an empty list if the user has no assignments (caller MUST treat
        this as deny — fail-closed, ADR-0017 D1 R4).
        """
        stmt = select(AdminRoleAssignment.role).where(
            AdminRoleAssignment.admin_user_id == admin_user_id,
            AdminRoleAssignment.tenant_id == caller_tenant_id,
        )
        result = await self._session.execute(stmt)
        return [row for row in result.scalars().all()]

    async def highest_role_for_user(
        self,
        *,
        admin_user_id: str,
        caller_tenant_id: str,
    ) -> str | None:
        """Return the highest-privilege role for admin_user_id, or None if unassigned.

        Callers MUST treat None as deny (fail-closed). 'tenant_admin' takes
        precedence over 'tenant_auditor'.
        """
        roles = await self.list_roles_for_user(
            admin_user_id=admin_user_id,
            caller_tenant_id=caller_tenant_id,
        )
        if not roles:
            return None
        role_set = set(roles)
        for role in _ROLE_PRECEDENCE:
            if role in role_set:
                return role
        # Should not reach here if CHECK constraint is intact, but fail-closed.
        return None
