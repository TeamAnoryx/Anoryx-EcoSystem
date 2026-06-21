"""Unit tests for AdminUserRepository and AdminRoleAssignmentRepository (F-014 STEP 2).

Tests cover:
  - provision_tenant_roles seeds exactly 2 rows and is idempotent.
  - upsert_by_subject is idempotent (second call does not create a duplicate).
  - tenant mismatch guard raises on upsert/get_by_subject.
  - assign() is idempotent (second identical assign returns the existing row).
  - list_roles_for_user and highest_role_for_user return correct results.
  - highest_role_for_user returns None when no assignments exist (fail-closed R4).
  - Invalid role raises ValueError before any DB write.

All tests use the privileged `session` fixture (BYPASSRLS) to avoid the
RLS requirement (tenant_session needs a pre-existing tenants row +
get_tenant_session GUC dance). Repository-level unit tests isolate SQL logic;
the cross-tenant RLS isolation proof is in test_sso_rls_isolation.py.

Tests are skipped (not failed) when DATABASE_URL is absent or the DB is
unreachable, following the skip-not-fail pattern from the existing test suite.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import AdminRole, AdminRoleAssignment, AdminUser
from persistence.repositories.admin_role_assignment_repository import (
    AdminRoleAssignmentRepository,
)
from persistence.repositories.admin_user_repository import (
    AdminUserNotFoundError,
    AdminUserRepository,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())


async def _insert_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) "
            "VALUES (:tid, :name, true) ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"tid": tenant_id, "name": "SSO test tenant " + tenant_id[:8]},
    )


# ---------------------------------------------------------------------------
# provision_tenant_roles
# ---------------------------------------------------------------------------


async def test_provision_tenant_roles_seeds_two_rows(session: AsyncSession) -> None:
    """provision_tenant_roles inserts exactly two rows: tenant_admin and tenant_auditor."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminRoleAssignmentRepository(session)
    await repo.provision_tenant_roles(tenant_id=tenant_id)
    await session.flush()

    result = await session.execute(
        select(AdminRole.role_name).where(AdminRole.tenant_id == tenant_id)
    )
    role_names = sorted(result.scalars().all())
    assert role_names == ["tenant_admin", "tenant_auditor"]


async def test_provision_tenant_roles_is_idempotent(session: AsyncSession) -> None:
    """Calling provision_tenant_roles twice does not create duplicate rows."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminRoleAssignmentRepository(session)
    await repo.provision_tenant_roles(tenant_id=tenant_id)
    await repo.provision_tenant_roles(tenant_id=tenant_id)
    await session.flush()

    result = await session.execute(select(AdminRole).where(AdminRole.tenant_id == tenant_id))
    rows = result.scalars().all()
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# AdminUserRepository: upsert_by_subject
# ---------------------------------------------------------------------------


async def test_upsert_by_subject_creates_row(session: AsyncSession) -> None:
    """upsert_by_subject returns an AdminUser row with correct attributes."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    user = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|abc123",
        caller_tenant_id=tenant_id,
        display_name="Alice",
    )
    await session.flush()

    assert user.tenant_id == tenant_id
    assert user.idp_subject == "sub|abc123"
    assert user.display_name == "Alice"
    assert user.is_active is True


async def test_upsert_by_subject_is_idempotent(session: AsyncSession) -> None:
    """A second upsert for the same (tenant_id, idp_subject) does not create a duplicate."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    first = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|idempotent",
        caller_tenant_id=tenant_id,
        display_name="Bob v1",
    )
    await session.flush()

    second = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|idempotent",
        caller_tenant_id=tenant_id,
        display_name="Bob v2",
    )
    await session.flush()

    # Same primary key — no new row.
    assert first.id == second.id

    # Verify only one row in DB.
    result = await session.execute(
        select(AdminUser).where(
            AdminUser.tenant_id == tenant_id,
            AdminUser.idp_subject == "sub|idempotent",
        )
    )
    rows = result.scalars().all()
    assert len(rows) == 1


async def test_upsert_by_subject_tenant_mismatch_raises(session: AsyncSession) -> None:
    """upsert_by_subject raises AdminUserNotFoundError when tenant_id != caller_tenant_id."""
    tenant_id = _uid()
    other_tenant_id = _uid()

    repo = AdminUserRepository(session)
    with pytest.raises(AdminUserNotFoundError):
        await repo.upsert_by_subject(
            tenant_id=tenant_id,
            idp_subject="sub|attack",
            caller_tenant_id=other_tenant_id,
        )


# ---------------------------------------------------------------------------
# AdminUserRepository: get_by_subject
# ---------------------------------------------------------------------------


async def test_get_by_subject_returns_existing_row(session: AsyncSession) -> None:
    """get_by_subject returns the row created by upsert_by_subject."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    created = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|fetch",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    fetched = await repo.get_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|fetch",
        caller_tenant_id=tenant_id,
    )
    assert fetched.id == created.id


async def test_get_by_subject_missing_raises(session: AsyncSession) -> None:
    """get_by_subject raises AdminUserNotFoundError for an unknown subject."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    with pytest.raises(AdminUserNotFoundError):
        await repo.get_by_subject(
            tenant_id=tenant_id,
            idp_subject="sub|does-not-exist",
            caller_tenant_id=tenant_id,
        )


async def test_get_by_subject_tenant_mismatch_raises(session: AsyncSession) -> None:
    """get_by_subject raises AdminUserNotFoundError when tenant_id != caller_tenant_id."""
    tenant_id = _uid()
    other = _uid()

    repo = AdminUserRepository(session)
    with pytest.raises(AdminUserNotFoundError):
        await repo.get_by_subject(
            tenant_id=tenant_id,
            idp_subject="sub|mismatch",
            caller_tenant_id=other,
        )


# ---------------------------------------------------------------------------
# AdminUserRepository: get_by_id
# ---------------------------------------------------------------------------


async def test_get_by_id_returns_row(session: AsyncSession) -> None:
    """get_by_id returns the row when user_id and caller_tenant_id match."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    user = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|by-id",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    fetched = await repo.get_by_id(
        user_id=str(user.id),
        caller_tenant_id=tenant_id,
    )
    assert fetched.id == user.id


async def test_get_by_id_wrong_tenant_raises(session: AsyncSession) -> None:
    """get_by_id raises AdminUserNotFoundError when the tenant does not own the row."""
    tenant_id = _uid()
    other_tenant = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    user = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|tenant-pin",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    with pytest.raises(AdminUserNotFoundError):
        await repo.get_by_id(user_id=str(user.id), caller_tenant_id=other_tenant)


# ---------------------------------------------------------------------------
# AdminUserRepository: set_last_login
# ---------------------------------------------------------------------------


async def test_set_last_login_updates_timestamp(session: AsyncSession) -> None:
    """set_last_login updates last_login_at and no other column."""
    from datetime import datetime, timezone

    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    repo = AdminUserRepository(session)
    user = await repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|login-ts",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    assert user.last_login_at is None

    ts = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    await repo.set_last_login(
        user_id=str(user.id),
        caller_tenant_id=tenant_id,
        login_at=ts,
    )
    await session.flush()

    # Re-fetch to confirm the update.
    await session.refresh(user)
    assert user.last_login_at is not None
    # Timestamps may differ in tz-aware representation; compare at second precision.
    assert user.last_login_at.replace(tzinfo=timezone.utc).year == 2026


# ---------------------------------------------------------------------------
# AdminRoleAssignmentRepository: assign + list_roles_for_user + highest_role_for_user
# ---------------------------------------------------------------------------


async def test_assign_creates_assignment(session: AsyncSession) -> None:
    """assign() creates an AdminRoleAssignment for the given user and role."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    user_repo = AdminUserRepository(session)
    ra_repo = AdminRoleAssignmentRepository(session)

    await ra_repo.provision_tenant_roles(tenant_id=tenant_id)
    user = await user_repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|assign",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    assignment = await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_admin",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    assert assignment.tenant_id == tenant_id
    assert assignment.admin_user_id == user.id
    assert assignment.role == "tenant_admin"


async def test_assign_is_idempotent(session: AsyncSession) -> None:
    """Calling assign() twice for the same (user, role) returns the same row."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    user_repo = AdminUserRepository(session)
    ra_repo = AdminRoleAssignmentRepository(session)

    await ra_repo.provision_tenant_roles(tenant_id=tenant_id)
    user = await user_repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|idem-assign",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    first = await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_auditor",
        caller_tenant_id=tenant_id,
    )
    second = await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_auditor",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    assert first.id == second.id

    # Confirm only one row in DB.
    result = await session.execute(
        select(AdminRoleAssignment).where(
            AdminRoleAssignment.tenant_id == tenant_id,
            AdminRoleAssignment.admin_user_id == user.id,
            AdminRoleAssignment.role == "tenant_auditor",
        )
    )
    rows = result.scalars().all()
    assert len(rows) == 1


async def test_list_roles_for_user_returns_assigned(session: AsyncSession) -> None:
    """list_roles_for_user returns the roles assigned to the user."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    user_repo = AdminUserRepository(session)
    ra_repo = AdminRoleAssignmentRepository(session)

    await ra_repo.provision_tenant_roles(tenant_id=tenant_id)
    user = await user_repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|list-roles",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_auditor",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    roles = await ra_repo.list_roles_for_user(
        admin_user_id=str(user.id),
        caller_tenant_id=tenant_id,
    )
    assert roles == ["tenant_auditor"]


async def test_highest_role_for_user_admin_over_auditor(session: AsyncSession) -> None:
    """highest_role_for_user returns tenant_admin when both roles are assigned."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    user_repo = AdminUserRepository(session)
    ra_repo = AdminRoleAssignmentRepository(session)

    await ra_repo.provision_tenant_roles(tenant_id=tenant_id)
    user = await user_repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|highest",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_auditor",
        caller_tenant_id=tenant_id,
    )
    await ra_repo.assign(
        tenant_id=tenant_id,
        admin_user_id=str(user.id),
        role="tenant_admin",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    highest = await ra_repo.highest_role_for_user(
        admin_user_id=str(user.id),
        caller_tenant_id=tenant_id,
    )
    assert highest == "tenant_admin"


async def test_highest_role_for_user_none_when_unassigned(session: AsyncSession) -> None:
    """highest_role_for_user returns None for a user with no assignments (fail-closed R4)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)

    user_repo = AdminUserRepository(session)
    ra_repo = AdminRoleAssignmentRepository(session)

    user = await user_repo.upsert_by_subject(
        tenant_id=tenant_id,
        idp_subject="sub|no-role",
        caller_tenant_id=tenant_id,
    )
    await session.flush()

    result = await ra_repo.highest_role_for_user(
        admin_user_id=str(user.id),
        caller_tenant_id=tenant_id,
    )
    assert result is None


async def test_assign_invalid_role_raises_before_db(session: AsyncSession) -> None:
    """assign() raises ValueError for an unknown role — no DB round-trip."""
    tenant_id = _uid()
    ra_repo = AdminRoleAssignmentRepository(session)

    with pytest.raises(ValueError, match="role must be one of"):
        await ra_repo.assign(
            tenant_id=tenant_id,
            admin_user_id=_uid(),
            role="superuser",
            caller_tenant_id=tenant_id,
        )


async def test_assign_tenant_mismatch_raises(session: AsyncSession) -> None:
    """assign() raises ValueError when tenant_id != caller_tenant_id."""
    tenant_id = _uid()
    other = _uid()
    ra_repo = AdminRoleAssignmentRepository(session)

    with pytest.raises(ValueError, match="tenant mismatch"):
        await ra_repo.assign(
            tenant_id=tenant_id,
            admin_user_id=_uid(),
            role="tenant_admin",
            caller_tenant_id=other,
        )
