"""Tenant-wide agent allow-list + the un-kill recovery path (ADR-0006 §3.6, §2 fork 5).

An internal create/revoke path (function-level, like D-005's ``create_budget`` — a full
admin UI is deferred, mirroring D-007). While a tenant has zero rows here, the
unauthorized-agent trigger is INERT for it (opt-in — ADR-0006 §2 fork 2, vector 9): D-006
never imposes a new restriction on a tenant that has not configured an allow-list.

``authorize_agent`` is also the recovery path: allow-listing an agent clears EVERY
currently-``killed`` scope for that ``(tenant, agent_id)`` triggered by
``unauthorized_agent`` — across all team/project scopes it has ever offended under
(vector 10) — in the SAME transaction, publishing a refreshed (unblocking) version.
Scoped to that ONE reason: allow-listing an identity has no authority over a SEPARATE
``anomalous_single_tx`` kill for the same agent (security review M-2) — that is
``clear_kill_switch``'s job, an explicit, unscoped operator override.

Both ``authorize_agent``/``clear_kill_switch`` are transaction-scoped DB primitives (no
commit, no network) so tests and batched callers can compose them freely. The
``*_and_publish`` wrappers below are the real entry points: they open the tenant session,
run the primitive, commit, and immediately drain — so the decision does NOT wait for a new
inbound event, which cannot arrive from a still-blocked scope (this is what actually
resolves the idle-tenant recovery gap D-005 §12 left open; security review M-1: the bare
primitives alone do not self-deliver).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.database import get_tenant_session
from ..persistence.models import agent_authorizations as _aa
from .config import KillSwitchSettings
from .drainer import drain_tenant
from .emit import build_clear_payload
from .outbox import enqueue_decision
from .state import KillSwitchState, find_state, killed_scopes_for_agent, try_transition_to_clear
from .triggers import UNAUTHORIZED_AGENT


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
    ``unauthorized_agent``-killed scope for it (NOT other reasons — an identity allow-list
    has no authority over an ``anomalous_single_tx`` kill). Does NOT commit and does NOT
    drain (caller owns the transaction; use :func:`authorize_agent_and_publish` for the
    self-delivering entry point). Returns the ``kill_id``s cleared."""
    await session.execute(
        pg_insert(_aa)
        .values(tenant_id=tenant_id, agent_id=agent_id, authorized_at=now)
        .on_conflict_do_nothing(index_elements=["tenant_id", "agent_id"])
    )
    cleared: list[str] = []
    for state in await killed_scopes_for_agent(
        session, tenant_id=tenant_id, agent_id=agent_id, reason=UNAUTHORIZED_AGENT
    ):
        if await _clear_scope(session, state, now):
            cleared.append(state.kill_id)
    return cleared


async def authorize_agent_and_publish(
    *, tenant_id: str, agent_id: str, settings: KillSwitchSettings
) -> list[str]:
    """The real recovery entry point: allow-list ``agent_id`` and immediately deliver every
    unblocking decision — does not wait for a new inbound event (security review M-1)."""
    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as session:
        cleared = await authorize_agent(session, tenant_id=tenant_id, agent_id=agent_id, now=now)
        await session.commit()
    await drain_tenant(tenant_id, settings, now)
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
    """Operator override: clear one specific killed scope, of EITHER reason, without
    touching the allow-list. A read-only lookup (:func:`state.find_state`) — a
    mistyped/never-seen scope is a pure no-op, never a spurious state row (security review
    L-5). Does NOT commit and does NOT drain (use :func:`clear_kill_switch_and_publish` for
    the self-delivering entry point). Returns True iff this call performed the transition.
    """
    state = await find_state(
        session, tenant_id=tenant_id, team_id=team_id, project_id=project_id, agent_id=agent_id
    )
    if state is None or state.state != "killed":
        return False
    return await _clear_scope(session, state, now)


async def clear_kill_switch_and_publish(
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    settings: KillSwitchSettings,
) -> bool:
    """The real operator-override entry point: clear one scope and immediately deliver the
    unblocking decision — does not wait for a new inbound event (security review M-1)."""
    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as session:
        cleared = await clear_kill_switch(
            session,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            now=now,
        )
        await session.commit()
    if cleared:
        await drain_tenant(tenant_id, settings, now)
    return cleared
