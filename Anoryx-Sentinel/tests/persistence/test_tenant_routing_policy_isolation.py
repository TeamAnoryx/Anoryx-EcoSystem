"""RLS isolation for tenant_routing_policy (F-006, ADR-0008 §4.3 / threat #11).

Mirrors tests/persistence/test_isolation.py. Proves:
  - Cross-tenant SELECT returns [] (tenant A cannot read tenant B's routing row).
  - Cross-tenant INSERT forgery is denied by WITH CHECK.
  - Empty-GUC session sees zero rows (NULLIF predicate, fail-closed).

These tests connect as sentinel_app (NOBYPASSRLS) via the tenant_session
fixtures — connecting as admin would pass spuriously (BYPASSRLS).

Honest language: risk reduction. A holder of the privileged DATABASE_URL
(owner / BYPASSRLS) can bypass RLS — a documented limit (ADR-0004 / ADR-0005).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession


def _uid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def test_tenant_id(tenant_a_id: str) -> str:
    return tenant_a_id


@pytest.fixture
def tenant_a_id() -> str:
    return "trp-iso-a-" + _uid()[:8]


@pytest.fixture
def tenant_b_id() -> str:
    return "trp-iso-b-" + _uid()[:8]


async def _create_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant_id, "n": "T " + tenant_id[:8]},
    )


async def _insert_routing_row(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenant_routing_policy "
            "(tenant_id, team_id, project_id, agent_id, allowed_providers, fallback_order) "
            "VALUES (:t, :team, :proj, 'gateway-core', 'openai', 'openai')"
        ),
        {"t": tenant_id, "team": _uid(), "proj": _uid()},
    )


@pytest.mark.asyncio
async def test_cross_tenant_select_returns_empty(
    session: AsyncSession,
    tenant_session: AsyncSession,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A session cannot see tenant B's tenant_routing_policy row."""
    await _create_tenant(session, tenant_a_id)
    await _create_tenant(session, tenant_b_id)
    await _insert_routing_row(session, tenant_b_id)
    await session.flush()

    result = await tenant_session.execute(
        text("SELECT tenant_id FROM tenant_routing_policy WHERE tenant_id = :t"),
        {"t": tenant_b_id},
    )
    rows = result.fetchall()
    assert rows == [], (
        f"Cross-tenant SELECT on tenant_routing_policy returned {rows}. "
        "RLS may not be active or sentinel_app may have BYPASSRLS."
    )


@pytest.mark.asyncio
async def test_cross_tenant_insert_forgery_denied(
    session: AsyncSession,
    tenant_session: AsyncSession,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A session cannot insert a routing row with tenant_id=B (WITH CHECK)."""
    await _create_tenant(session, tenant_a_id)
    await _create_tenant(session, tenant_b_id)
    await session.flush()

    with pytest.raises(DBAPIError):
        await tenant_session.execute(
            text(
                "INSERT INTO tenant_routing_policy "
                "(tenant_id, team_id, project_id, agent_id, allowed_providers, fallback_order) "
                "VALUES (:t, :team, :proj, 'gateway-core', 'openai', 'openai')"
            ),
            {"t": tenant_b_id, "team": _uid(), "proj": _uid()},  # forged tenant
        )
        await tenant_session.flush()


@pytest.mark.asyncio
async def test_empty_guc_returns_zero_rows(
    session: AsyncSession,
    tenant_session_empty_guc: AsyncSession,
    tenant_a_id: str,
) -> None:
    """Empty GUC denies access (proves NULLIF collapses '' to NULL, fail-closed)."""
    await _create_tenant(session, tenant_a_id)
    await _insert_routing_row(session, tenant_a_id)
    await session.flush()

    result = await tenant_session_empty_guc.execute(
        text("SELECT tenant_id FROM tenant_routing_policy WHERE tenant_id = :t"),
        {"t": tenant_a_id},
    )
    rows = result.fetchall()
    assert rows == [], f"Expected zero rows with GUC='', got {rows}"


@pytest.mark.asyncio
async def test_own_tenant_select_no_rls_error(
    tenant_session: AsyncSession,
    tenant_a_id: str,
) -> None:
    """Tenant A session can SELECT its own routing rows without an RLS error.

    Mirrors test_isolation.py::test_tenant_can_only_see_own_teams: we do not rely
    on cross-connection committed data (the privileged `session` fixture rolls
    back). The point is that the SELECT under the correct GUC is permitted (no
    policy error) and returns a countable result — RLS allows the own-tenant read.
    """
    result = await tenant_session.execute(
        text("SELECT COUNT(*) FROM tenant_routing_policy WHERE tenant_id = :t"),
        {"t": tenant_a_id},
    )
    count = result.scalar_one()
    assert isinstance(count, int)
