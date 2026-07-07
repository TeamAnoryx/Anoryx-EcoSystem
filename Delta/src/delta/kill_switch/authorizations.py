"""Tenant-wide agent allow-list + the un-kill recovery path (ADR-0006 §3.6, §2 fork 5).

An internal create/revoke path (function-level, like D-005's ``create_budget`` — a full
admin UI is deferred, mirroring D-007). While a tenant has zero rows here, the
unauthorized-agent trigger is INERT for it (opt-in — ADR-0006 §2 fork 2, vector 9): D-006
never imposes a new restriction on a tenant that has not configured an allow-list.

``authorize_agent`` is also the recovery path: allow-listing an agent immediately clears
EVERY currently-``killed`` scope for that ``(tenant, agent_id)`` — across all team/project
scopes it has ever offended under (vector 10) — in the SAME transaction, publishing a
refreshed (unblocking) version. This does not wait for a new inbound event, which cannot
arrive from a blocked scope (resolves the idle-tenant recovery gap D-005 §12 left open, for
this path).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import agent_authorizations as _aa
from .emit import build_clear_payload
from .outbox import enqueue_decision
from .state import KillSwitchState, killed_scopes_for_agent, try_transition_to_clear


async def is_tenant_gated(session: AsyncSession, tenant_id: str) -> bool:
    """True iff this tenant has opted in to the agent allow-list (>=1 row)."""
    row = (
        await session.execute(select(_aa.c.agent_id).where(_aa.c.tenant_id == tenant_id).limit(1))
    ).first()
    return row is not None


async def is_authorized(session: AsyncSession, tenant_id: str, agent_id: str) -> bool:
    row = (
        await session.execute(
            select(_aa.c.agent_id).where(
                and_(_aa.c.tenant_id == tenant_id, _aa.c.agent_id == agent_id)
            )
        )
    ).first()
    return row is not None


async def _clear_scope(session: AsyncSession, state: KillSwitchState, now: datetime) -> bool:
    """Transition one killed scope to clear + enqueue the unblocking decision."""
    version = await try_transition_to_clear(
        session, tenant_id=state.tenant_id, kill_id=state.kill_id, now=now
    )
    if version is None:
        return False  # already cleared by a concurrent caller
    payload = build_clear_payload(
        tenant_id=state.tenant_id,
        team_id=state.team_id,
        project_id=state.project_id,
        agent_id=state.agent_id,
        policy_id=state.policy_id,
        policy_version=version,
        effective_from=now,
    )
    await enqueue_decision(
        session,
        tenant_id=state.tenant_id,
        kill_id=state.kill_id,
        policy_id=state.policy_id,
        policy_version=version,
        transition="clear",
        policy_payload=payload,
        now=now,
    )
    return True


async def authorize_agent(
    session: AsyncSession, *, tenant_id: str, agent_id: str, now: datetime
) -> list[str]:
    """Allow-list ``agent_id`` for ``tenant_id`` (idempotent) and clear every currently
    ``killed`` scope for it. Does NOT commit (caller owns the transaction, then should
    drain the tenant to publish). Returns the ``kill_id``s cleared."""
    await session.execute(
        pg_insert(_aa)
        .values(tenant_id=tenant_id, agent_id=agent_id, authorized_at=now)
        .on_conflict_do_nothing(index_elements=["tenant_id", "agent_id"])
    )
    cleared: list[str] = []
    for state in await killed_scopes_for_agent(session, tenant_id=tenant_id, agent_id=agent_id):
        if await _clear_scope(session, state, now):
            cleared.append(state.kill_id)
    return cleared


async def revoke_agent(session: AsyncSession, *, tenant_id: str, agent_id: str) -> None:
    """Remove ``agent_id`` from the allow-list (idempotent). Does NOT retroactively kill
    anything — only future events are evaluated against the narrower allow-list, mirroring
    D-005's budget-raise path (effective going forward only). Does NOT commit."""
    await session.execute(
        delete(_aa).where(and_(_aa.c.tenant_id == tenant_id, _aa.c.agent_id == agent_id))
    )


async def clear_kill_switch(
    session: AsyncSession,
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    now: datetime,
) -> bool:
    """Operator override: clear one specific killed scope without touching the
    allow-list (e.g. an anomalous-single-tx kill the operator has reviewed and accepted).
    Does NOT commit. Returns True iff this call performed the transition."""
    from .state import get_or_create_state

    state = await get_or_create_state(
        session,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        now=now,
    )
    if state.state != "killed":
        return False
    return await _clear_scope(session, state, now)
