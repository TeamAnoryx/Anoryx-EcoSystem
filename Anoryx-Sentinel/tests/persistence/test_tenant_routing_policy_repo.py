"""TenantRoutingPolicyRepository tests (F-006, ADR-0008 §4).

Covers the default-when-no-row behavior, row parsing/validation, the
defense-in-depth caller_tenant_id guard, and malformed-row fail-closed.

Uses the privileged `session` fixture for setup; the repo's WHERE clause is the
app-layer guard under test (RLS is exercised separately in test_isolation_*).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.tenant_routing_policy_repository import (
    RoutingPolicyValidationError,
    TenantRoutingPolicyRepository,
)


def _uid() -> str:
    return str(uuid.uuid4())


async def _create_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"t": tenant_id, "n": "T " + tenant_id[:8]},
    )


async def _insert_policy(
    session: AsyncSession,
    tenant_id: str,
    allowed: str,
    order: str,
    ceiling=None,
) -> None:
    await session.execute(
        text(
            "INSERT INTO tenant_routing_policy "
            "(tenant_id, team_id, project_id, agent_id, allowed_providers, "
            " fallback_order, cost_ceiling_cents) "
            "VALUES (:t, :team, :proj, 'gateway-core', :allowed, :order, :ceil)"
        ),
        {
            "t": tenant_id,
            "team": _uid(),
            "proj": _uid(),
            "allowed": allowed,
            "order": order,
            "ceil": ceiling,
        },
    )


@pytest.mark.asyncio
async def test_default_when_no_row(session: AsyncSession) -> None:
    """No row -> §4.2 default: all three providers, no ceiling, is_default True."""
    tid = "trp-default-" + _uid()[:8]
    repo = TenantRoutingPolicyRepository(session)
    pol = await repo.get_for_tenant(tid, caller_tenant_id=tid)
    assert pol.is_default is True
    assert set(pol.allowed_providers) == {"openai", "anthropic", "bedrock"}
    assert pol.fallback_order == ["openai", "anthropic", "bedrock"]
    assert pol.cost_ceiling_cents is None


@pytest.mark.asyncio
async def test_row_parsed_and_returned(session: AsyncSession) -> None:
    tid = "trp-row-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(session, tid, "openai,anthropic", "anthropic,openai", ceiling="12.5")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    pol = await repo.get_for_tenant(tid, caller_tenant_id=tid)
    assert pol.is_default is False
    assert set(pol.allowed_providers) == {"openai", "anthropic"}
    assert pol.fallback_order == ["anthropic", "openai"]
    assert pol.cost_ceiling_cents == 12.5


@pytest.mark.asyncio
async def test_caller_tenant_mismatch_returns_default(session: AsyncSession) -> None:
    """Defense-in-depth: a mismatched caller_tenant_id does not see the row."""
    tid = "trp-guard-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(session, tid, "openai", "openai")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    # Wrong caller -> WHERE tenant_id = caller_tenant_id excludes the row -> default.
    pol = await repo.get_for_tenant(tid, caller_tenant_id="some-other-tenant")
    assert pol.is_default is True


@pytest.mark.asyncio
async def test_malformed_fallback_order_fails_closed(session: AsyncSession) -> None:
    """fallback_order not a subset of allowed_providers -> validation error."""
    tid = "trp-bad-" + _uid()[:8]
    await _create_tenant(session, tid)
    # bedrock in fallback_order but not in allowed_providers.
    await _insert_policy(session, tid, "openai", "openai,bedrock")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    with pytest.raises(RoutingPolicyValidationError):
        await repo.get_for_tenant(tid, caller_tenant_id=tid)


@pytest.mark.asyncio
async def test_unknown_provider_token_fails_closed(session: AsyncSession) -> None:
    tid = "trp-unknown-" + _uid()[:8]
    await _create_tenant(session, tid)
    await _insert_policy(session, tid, "openai,gemini", "openai")
    await session.flush()

    repo = TenantRoutingPolicyRepository(session)
    with pytest.raises(RoutingPolicyValidationError):
        await repo.get_for_tenant(tid, caller_tenant_id=tid)
