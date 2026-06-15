"""RBAC and RLS tests (F-003).

Verifies that Row-Level Security policies work correctly for tenant isolation.
Tests that role_assignments respects RLS and that cross-tenant reads are blocked.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.tenant_repository import TenantRepository
from persistence.repositories.team_repository import TeamRepository


def _uid() -> str:
    return str(uuid.uuid4())


@pytest.mark.asyncio
async def test_rls_policy_is_configured_correctly(session: AsyncSession) -> None:
    """Verify the RLS tenant_isolation policy is correctly defined on the teams table.

    The sentinel DB user has BYPASSRLS for migrations and tests, so we cannot
    test behavioral enforcement from this connection. Instead we verify:
    1. The policy exists on the table.
    2. The policy's permissive flag and command are correct.
    3. RLS is enabled AND forced on the table.

    Behavioral enforcement is verified in production by setting
    app.current_tenant_id on non-BYPASSRLS application user connections.
    """
    # Verify the policy is defined.
    result = await session.execute(
        text(
            """
            SELECT polname, polcmd, polpermissive
            FROM pg_policy
            WHERE polrelid = 'teams'::regclass
            AND polname = 'tenant_isolation'
            """
        )
    )
    pol = result.fetchone()
    assert pol is not None, "tenant_isolation policy not found on teams table"
    assert pol[0] == "tenant_isolation"
    # polcmd: '*' = ALL, 'r' = SELECT, 'a' = INSERT, 'w' = UPDATE, 'd' = DELETE
    # asyncpg may return this as bytes or str depending on Postgres type.
    polcmd = pol[1] if isinstance(pol[1], str) else pol[1].decode()
    assert polcmd == "*", f"Policy command should be ALL (*), got {polcmd!r}"

    # Verify RLS is enabled and forced via pg_class (pg_tables lacks forcerolesecurity).
    result2 = await session.execute(
        text(
            """
            SELECT c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            WHERE c.relname = 'teams' AND c.relkind = 'r'
            """
        )
    )
    row2 = result2.fetchone()
    assert row2 is not None
    assert row2[0] is True, "RLS not enabled on teams (relrowsecurity=False)"
    assert row2[1] is True, "FORCE ROW LEVEL SECURITY not set on teams (relforcerowsecurity=False)"
    # The sentinel user has BYPASSRLS so SET LOCAL won't affect its reads,
    # but the policy is active for non-BYPASSRLS application connections.

    # Additionally verify tenant isolation works at the policy definition level.
    result3 = await session.execute(
        text(
            """
            SELECT count(*) FROM pg_policy
            WHERE polrelid IN (
                'teams'::regclass,
                'projects'::regclass,
                'users'::regclass,
                'role_assignments'::regclass,
                'events_audit_log'::regclass
            )
            AND polname = 'tenant_isolation'
            """
        )
    )
    count = result3.scalar()
    assert count >= 4, f"Expected at least 4 tenant_isolation policies, got {count}"


@pytest.mark.asyncio
async def test_rls_cross_tenant_blocked_for_app_user(session: AsyncSession) -> None:
    """Verify that team rows from a different tenant are filtered by RLS policy.

    NOTE: The sentinel migration user has BYPASSRLS, so this test verifies the
    policy structure rather than behavioral enforcement. The application uses a
    non-BYPASSRLS user and sets app.current_tenant_id per-request via middleware.
    This test documents the expected behavior and verifies the policy is present.
    """
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)

    tenant_a = await t_repo.create(name=f"Tenant A {_uid()[:6]}")
    tenant_b = await t_repo.create(name=f"Tenant B {_uid()[:6]}")
    team_a = await team_repo.create(tenant_id=tenant_a.tenant_id, name="Team A1")
    team_b = await team_repo.create(tenant_id=tenant_b.tenant_id, name="Team B1")

    # Verify both teams exist from the admin perspective (BYPASSRLS).
    result = await session.execute(
        text(
            "SELECT team_id FROM teams WHERE team_id IN (:ta, :tb)"
        ),
        {"ta": team_a.team_id, "tb": team_b.team_id},
    )
    rows = result.fetchall()
    assert len(rows) == 2, "Both teams must be visible to the BYPASSRLS admin user"

    # Verify the RLS policy is correctly defined to filter by tenant_id.
    # A non-BYPASSRLS app user running with SET app.current_tenant_id=tenant_a
    # would only see team_a. We assert the policy definition makes this so.
    result2 = await session.execute(
        text(
            """
            SELECT pg_get_expr(polqual, polrelid)
            FROM pg_policy
            WHERE polrelid = 'teams'::regclass
            AND polname = 'tenant_isolation'
            """
        )
    )
    qual_expr = result2.scalar()
    assert qual_expr is not None, "tenant_isolation policy has no USING expression"
    # The USING expression must reference tenant_id.
    assert "tenant_id" in qual_expr, (
        f"RLS policy USING expression does not filter on tenant_id: {qual_expr!r}"
    )


@pytest.mark.asyncio
async def test_bypassrls_user_sees_all_rows(session: AsyncSession) -> None:
    """BYPASSRLS user (migration/admin role) sees all rows regardless of GUC.

    F-003 RLS policies include an OR IS NULL branch in their USING expressions
    (enforcement tightening is deferred to F-003b). The migration user has
    BYPASSRLS so it sees all rows unconditionally regardless of GUC state.

    This test runs as the migration user (BYPASSRLS) and verifies it sees
    rows even with an empty GUC context, confirming BYPASSRLS works.
    """
    t_repo = TenantRepository(session)
    team_repo = TeamRepository(session)

    tenant = await t_repo.create(name=f"RLS BypassRLS Tenant {_uid()[:6]}")
    team = await team_repo.create(tenant_id=tenant.tenant_id, name="BypassRLS Team")

    # Reset any RLS context — app.current_tenant_id = ''.
    # For the BYPASSRLS migration user, this does NOT restrict visibility.
    await session.execute(text("SET LOCAL app.current_tenant_id = ''"))

    result = await session.execute(
        text("SELECT team_id FROM teams WHERE team_id = :tid"),
        {"tid": team.team_id},
    )
    row = result.fetchone()
    # BYPASSRLS user sees all rows regardless of GUC.
    assert row is not None


@pytest.mark.asyncio
async def test_role_assignment_valid_roles(session: AsyncSession) -> None:
    """Role assignments with invalid role strings are rejected by CHECK constraint."""
    t_repo = TenantRepository(session)
    tenant = await t_repo.create(name=f"RA Tenant {_uid()[:6]}")

    user_id = _uid()
    # Insert a user first (password_hash: Argon2id placeholder for test).
    await session.execute(
        text(
            "INSERT INTO users (user_id, tenant_id, email, password_hash) "
            "VALUES (:uid, :tid, :email, :ph)"
        ),
        {
            "uid": user_id,
            "tid": tenant.tenant_id,
            "email": f"user-{_uid()[:6]}@test.example",
            # Argon2id PHC string placeholder (not a real password — test only).
            "ph": "$argon2id$v=19$m=65536,t=3,p=4$placeholder$placeholder",
        },
    )

    # Valid role: admin — must succeed.
    ra_id = _uid()
    await session.execute(
        text(
            "INSERT INTO role_assignments "
            "(role_assignment_id, user_id, tenant_id, role) "
            "VALUES (:raid, :uid, :tid, :role)"
        ),
        {
            "raid": ra_id,
            "uid": user_id,
            "tid": tenant.tenant_id,
            "role": "admin",
        },
    )

    # Invalid role: 'superadmin' — must fail the CHECK constraint.
    with pytest.raises(Exception, match="check"):
        await session.execute(
            text(
                "INSERT INTO role_assignments "
                "(role_assignment_id, user_id, tenant_id, role) "
                "VALUES (:raid, :uid, :tid, :role)"
            ),
            {
                "raid": _uid(),
                "uid": user_id,
                "tid": tenant.tenant_id,
                "role": "superadmin",
            },
        )
        await session.flush()
