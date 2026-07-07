"""Agent allow-list CRUD + RLS isolation (ADR-0006 §3.6, vectors 1, 6) — DB-backed."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_engine.definitions import create_budget
from delta.kill_switch.authorizations import (
    authorize_agent,
    clear_kill_switch,
    is_authorized,
    is_tenant_gated,
    revoke_agent,
)

from .conftest import db_required

pytestmark = db_required

_NOW = datetime(2026, 7, 7, 12, 0, 0, tzinfo=timezone.utc)


async def test_ungated_by_default(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        assert await is_tenant_gated(s, tenant_id) is False
        assert await is_authorized(s, tenant_id, "any-agent") is False


async def test_authorize_gates_and_authorizes(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        await authorize_agent(s, tenant_id=tenant_id, agent_id="gateway-core", now=_NOW)
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert await is_tenant_gated(s, tenant_id) is True
        assert await is_authorized(s, tenant_id, "gateway-core") is True
        assert await is_authorized(s, tenant_id, "someone-else") is False


async def test_authorize_is_idempotent(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        await authorize_agent(s, tenant_id=tenant_id, agent_id="gateway-core", now=_NOW)
        await authorize_agent(s, tenant_id=tenant_id, agent_id="gateway-core", now=_NOW)
        await s.commit()
    async with tenant_session(tenant_id) as s:
        rows = (
            await s.execute(
                text(
                    "SELECT count(*) FROM delta.agent_authorizations WHERE agent_id = "
                    "'gateway-core'"
                )
            )
        ).scalar_one()
        assert rows == 1


async def test_revoke_removes_authorization_going_forward(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        await authorize_agent(s, tenant_id=tenant_id, agent_id="gateway-core", now=_NOW)
        await s.commit()
    async with tenant_session(tenant_id) as s:
        await revoke_agent(s, tenant_id=tenant_id, agent_id="gateway-core")
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert await is_authorized(s, tenant_id, "gateway-core") is False
        # The tenant remains gated if OTHER agents are still allow-listed; here it is not.
        assert await is_tenant_gated(s, tenant_id) is False


async def test_authorizations_rls_isolation(tenant_id, other_tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        await authorize_agent(s, tenant_id=tenant_id, agent_id="gateway-core", now=_NOW)
        await s.commit()
    async with tenant_session(other_tenant_id) as s:
        assert await is_tenant_gated(s, other_tenant_id) is False
        assert await is_authorized(s, other_tenant_id, "gateway-core") is False


# ------------------------------------------------------------- vector 6: policy_id space
async def test_kill_switch_policy_id_space_independent_of_budget_definitions(
    tenant_id, tenant_session
):
    """A kill-switch policy_id is minted independently of budget_definitions.policy_id —
    the two enforcement layers never share or collide on a policy identity (vector 6)."""
    from delta.kill_switch.state import get_or_create_state

    concept = BudgetConcept(
        tenant_id=tenant_id,
        team_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        project_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        agent_id="gateway-core",
        scope=BudgetScope.AGENT,
        period=BudgetPeriod.DAILY,
        limit_cost_cents=1000,
    )
    async with tenant_session(tenant_id) as s:
        bd = await create_budget(s, concept, now=_NOW)
        await s.commit()
    async with tenant_session(tenant_id) as s:
        kss = await get_or_create_state(
            s,
            tenant_id=tenant_id,
            team_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            project_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            agent_id="gateway-core",
            now=_NOW,
        )
        await s.commit()
    assert kss.policy_id != bd.policy_id  # independently minted, never the same identity


async def test_clear_kill_switch_on_a_never_killed_scope_is_a_noop(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        cleared = await clear_kill_switch(
            s,
            tenant_id=tenant_id,
            team_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            project_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            agent_id="never-killed",
            now=_NOW,
        )
        await s.commit()
    assert cleared is False


async def test_concurrent_authorize_agent_clears_a_scope_exactly_once(tenant_id, tenant_session):
    """Two concurrent authorize_agent calls for the same rogue agent: the loser's
    ``_clear_scope`` conditional transition returns None (skipped, not double-counted) —
    exactly one call reports the scope as cleared."""
    import asyncio

    from delta.kill_switch.state import get_or_create_state, try_transition_to_killed
    from delta.persistence.database import get_tenant_session

    team = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    proj = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    async with tenant_session(tenant_id) as s:
        state = await get_or_create_state(
            s, tenant_id=tenant_id, team_id=team, project_id=proj, agent_id="rogue", now=_NOW
        )
        await try_transition_to_killed(
            s, tenant_id=tenant_id, kill_id=state.kill_id, reason="unauthorized_agent", now=_NOW
        )
        await s.commit()

    async def _authorize():
        async with get_tenant_session(tenant_id) as s:
            cleared = await authorize_agent(s, tenant_id=tenant_id, agent_id="rogue", now=_NOW)
            await s.commit()
            return cleared

    results = await asyncio.gather(_authorize(), _authorize(), _authorize())
    all_cleared = [kid for r in results for kid in r]
    assert all_cleared == [state.kill_id]  # exactly one call cleared it
