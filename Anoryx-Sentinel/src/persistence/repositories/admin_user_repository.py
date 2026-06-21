"""AdminUserRepository — data access for admin_users table (F-014 STEP 2).

SECURITY INVARIANTS:
1. All lookups include AND tenant_id = caller_tenant_id (app-layer defense-in-depth).
   RLS on the tenant session is the primary boundary; the explicit WHERE clause is
   the second lock (mirrors the F-003b pattern in team_repository / virtual_api_key_repository).
2. idp_subject is the IdP's stable opaque subject (OIDC sub / SAML NameID).
   It is never a password, never logged verbatim in error messages.
3. upsert_by_subject() is idempotent — safe to call on every SSO login (just-in-time
   provisioning, ADR-0017 D1).
4. set_last_login() updates only last_login_at — no other column is mutated here.
   is_active is set only through explicit deactivation paths (future STEP).

TYPE CONTRACT:
  All id/tenant_id/fk columns are VARCHAR(64) in the schema. This repository
  accepts and returns them as plain str. IDs are generated as str(uuid.uuid4()).
  No uuid.UUID() conversion is performed before DB writes — the column type
  handles text natively and the GUC is also a string (see database.py).

SESSION REQUIREMENT:
  All methods require a tenant-scoped session (get_tenant_session(tenant_id)) so that
  RLS is in force.  A privileged session can be used for admin tooling only when the
  caller explicitly constrains the WHERE clause to the target tenant.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import AdminUser


class AdminUserNotFoundError(Exception):
    """Raised when an admin_user lookup finds no matching active row."""


class AdminUserRepository:
    """Data-access object for admin_users. All methods are caller_tenant_id-scoped."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_by_subject(
        self,
        *,
        tenant_id: str,
        idp_subject: str,
        caller_tenant_id: str,
        idp_config_id: str | None = None,
        display_name: str | None = None,
    ) -> AdminUser:
        """Insert or update an admin_user row keyed by (tenant_id, idp_subject).

        Idempotent — safe to call on every SSO login. On conflict on the
        (tenant_id, idp_subject) unique constraint, updates display_name and
        idp_config_id if they have changed. Returns the upserted row.

        caller_tenant_id MUST equal tenant_id. The guard is defense-in-depth:
        RLS already prevents cross-tenant writes, but the explicit check makes
        the security intent visible at the application boundary.
        """
        if tenant_id != caller_tenant_id:
            raise AdminUserNotFoundError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )

        row_id = str(uuid.uuid4())

        stmt = (
            pg_insert(AdminUser)
            .values(
                id=row_id,
                tenant_id=tenant_id,
                idp_subject=idp_subject,
                idp_config_id=idp_config_id,
                display_name=display_name,
                is_active=True,
            )
            .on_conflict_do_update(
                constraint="uq_admin_users_tenant_subject",
                set_={
                    "idp_config_id": idp_config_id,
                    "display_name": display_name,
                },
            )
            .returning(AdminUser)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one()
        return row

    async def get_by_subject(
        self,
        *,
        tenant_id: str,
        idp_subject: str,
        caller_tenant_id: str,
    ) -> AdminUser:
        """Return the AdminUser for (tenant_id, idp_subject), or raise AdminUserNotFoundError.

        Only returns is_active=True rows. Inactive users are treated as not found
        so that a deactivated operator cannot authenticate (fail-closed).
        """
        if tenant_id != caller_tenant_id:
            raise AdminUserNotFoundError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        stmt = select(AdminUser).where(
            AdminUser.tenant_id == tenant_id,
            AdminUser.idp_subject == idp_subject,
            AdminUser.is_active.is_(True),
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise AdminUserNotFoundError(
                f"AdminUser not found for tenant_id={tenant_id!r} "
                f"(subject omitted for security)"
            )
        return row

    async def get_by_id(
        self,
        *,
        user_id: str,
        caller_tenant_id: str,
    ) -> AdminUser:
        """Return the AdminUser for user_id scoped to caller_tenant_id.

        Raises AdminUserNotFoundError if not found or if the row belongs to a
        different tenant (the WHERE clause + RLS both enforce this).
        """
        stmt = select(AdminUser).where(
            AdminUser.id == user_id,
            AdminUser.tenant_id == caller_tenant_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise AdminUserNotFoundError(
                f"AdminUser not found: user_id={user_id!r} " f"tenant_id={caller_tenant_id!r}"
            )
        return row

    async def set_last_login(
        self,
        *,
        user_id: str,
        caller_tenant_id: str,
        login_at: datetime | None = None,
    ) -> None:
        """Update last_login_at for the given user_id.

        login_at defaults to the current UTC time when not provided.
        Does nothing if no matching row is found (RLS + tenant filter protect this).
        Only last_login_at is mutated — no other column is touched.
        """
        ts = login_at if login_at is not None else datetime.now(timezone.utc)
        stmt = (
            update(AdminUser)
            .where(
                AdminUser.id == user_id,
                AdminUser.tenant_id == caller_tenant_id,
            )
            .values(last_login_at=ts)
        )
        await self._session.execute(stmt)
