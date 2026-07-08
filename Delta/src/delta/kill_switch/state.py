"""Kill-switch enforcement-state store — edge detection + idempotent publish (ADR-0006 §3.3).

One row per ``(tenant_id, team_id, project_id, agent_id)`` — the SAME granularity as
Sentinel's ``BudgetScope.AGENT`` (no period bucket: unlike D-005, the kill-switch is not
period-based, so once minted a scope's row and its ``policy_id`` persist for its lifetime).
The publish decision is gated by a conditional transition (``UPDATE ... WHERE state=...``),
identical in shape to ``budget_engine.state`` — under concurrent offending events for the
same scope, exactly one transaction flips the state and publishes (ADR-0005 vector 5,
reused here as ADR-0006 vector 5).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import kill_switch_state as _kss


@dataclass(frozen=True)
class KillSwitchState:
    kill_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    policy_id: str
    state: str
    reason: str | None
    last_published_version: int


def _row_to_state(row) -> KillSwitchState:
    return KillSwitchState(
        kill_id=row.kill_id,
        tenant_id=row.tenant_id,
        team_id=row.team_id,
        project_id=row.project_id,
        agent_id=row.agent_id,
        policy_id=row.policy_id,
        state=row.state,
        reason=row.reason,
        last_published_version=row.last_published_version,
    )


async def get_or_create_state(
    session: AsyncSession,
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    now: datetime,
) -> KillSwitchState:
    """Return the state row for this scope, creating it ``clear`` (with a fresh
    ``policy_id``) if new.

    Concurrent first-time creators race on the INSERT; the loser's ``ON CONFLICT DO
    NOTHING`` no-ops and the subsequent SELECT returns the SAME winning row (including its
    ``policy_id``), so the scope is never minted with two different policy identities.
    """
    await session.execute(
        pg_insert(_kss)
        .values(
            kill_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            policy_id=str(uuid.uuid4()),
            state="clear",
            reason=None,
            last_published_version=0,
            updated_at=now,
        )
        .on_conflict_do_nothing(
            index_elements=["tenant_id", "team_id", "project_id", "agent_id"],
        )
    )
    row = (
        await session.execute(
            select(_kss).where(
                and_(
                    _kss.c.tenant_id == tenant_id,
                    _kss.c.team_id == team_id,
                    _kss.c.project_id == project_id,
                    _kss.c.agent_id == agent_id,
                )
            )
        )
    ).one()
    return _row_to_state(row)


async def killed_scopes_for_agent(
    session: AsyncSession, *, tenant_id: str, agent_id: str, reason: str | None = None
) -> list[KillSwitchState]:
    """Every currently-``killed`` scope for this ``(tenant, agent_id)`` — across ALL
    team/project scopes that agent has ever offended under (ADR-0006 §3.6, vector 10).

    ``reason``, when given, narrows to kills triggered by that reason only — e.g.
    allow-listing an agent (which remedies ``unauthorized_agent``) must NOT also lift an
    unrelated ``anomalous_single_tx`` kill it has no authority over (security review M-2).
    """
    conds = [
        _kss.c.tenant_id == tenant_id,
        _kss.c.agent_id == agent_id,
        _kss.c.state == "killed",
    ]
    if reason is not None:
        conds.append(_kss.c.reason == reason)
    rows = (await session.execute(select(_kss).where(and_(*conds)))).all()
    return [_row_to_state(r) for r in rows]


async def find_state(
    session: AsyncSession, *, tenant_id: str, team_id: str, project_id: str, agent_id: str
) -> KillSwitchState | None:
    """Read-only lookup for this scope — unlike :func:`get_or_create_state`, never inserts
    a row. Used by operator-facing paths (``clear_kill_switch``) so a mistyped/never-seen
    scope is a pure no-op, not a spurious ``clear``-state row with a freshly minted, never
    corresponding, ``policy_id`` (security review L-5)."""
    row = (
        await session.execute(
            select(_kss).where(
                and_(
                    _kss.c.tenant_id == tenant_id,
                    _kss.c.team_id == team_id,
                    _kss.c.project_id == project_id,
                    _kss.c.agent_id == agent_id,
                )
            )
        )
    ).first()
    return _row_to_state(row) if row is not None else None


async def _conditional_transition(
    session: AsyncSession,
    *,
    tenant_id: str,
    kill_id: str,
    from_state: str,
    to_state: str,
    reason: str | None,
    now: datetime,
) -> int | None:
    """Flip from_state->to_state iff currently from_state; return the new version or None."""
    new_version = _kss.c.last_published_version + 1
    stmt = (
        update(_kss)
        .where(
            and_(
                _kss.c.tenant_id == tenant_id,
                _kss.c.kill_id == kill_id,
                _kss.c.state == from_state,
            )
        )
        .values(
            state=to_state,
            reason=reason,
            last_published_version=new_version,
            updated_at=now,
        )
        .returning(_kss.c.last_published_version)
    )
    row = (await session.execute(stmt)).first()
    return int(row[0]) if row is not None else None


async def try_transition_to_killed(
    session: AsyncSession, *, tenant_id: str, kill_id: str, reason: str, now: datetime
) -> int | None:
    """clear -> killed. Returns the new policy version to publish, or None if it lost."""
    return await _conditional_transition(
        session,
        tenant_id=tenant_id,
        kill_id=kill_id,
        from_state="clear",
        to_state="killed",
        reason=reason,
        now=now,
    )


async def try_transition_to_clear(
    session: AsyncSession, *, tenant_id: str, kill_id: str, now: datetime
) -> int | None:
    """killed -> clear (operator un-kill). Returns the new refresh version, or None if
    the scope was not currently killed (already cleared by a concurrent caller)."""
    # The last trigger reason is retained (not cleared) for audit — only `state` flips.
    row = (
        await session.execute(
            select(_kss.c.reason).where(
                and_(_kss.c.tenant_id == tenant_id, _kss.c.kill_id == kill_id)
            )
        )
    ).first()
    current_reason = row[0] if row is not None else None
    return await _conditional_transition(
        session,
        tenant_id=tenant_id,
        kill_id=kill_id,
        from_state="killed",
        to_state="clear",
        reason=current_reason,
        now=now,
    )
