"""Unified CRM persistence (D-013, ADR-0013).

Tenant-scoped reads/writes against ``clients``/``deals``/``stakeholders``/
``interactions`` (migration 0007). Every function takes an already-open
:class:`AsyncSession` (from ``delta.persistence.database.get_tenant_session``) and
does NOT commit — the caller (``service.py``) owns the transaction, exactly like
``allocation_admin.store``/``budget_engine.definitions``.

Stakeholder engagement (``interaction_count``/``last_interaction_at``) and a client's
relationship-score inputs are computed via bounded SQL aggregates (``COUNT``/``MAX``/
``FILTER``), never by loading every interaction row into Python — the same
O(1)-queries-per-request discipline D-011/D-012's security reviews established.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import clients, deals, interactions, stakeholders

# List-response bounds (mirrors D-007/D-008/D-011/D-012's own caps — an unbounded
# SELECT over a long-lived tenant table grows without limit).
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# Relationship-score recency window (delta.crm.scoring's ``interaction_count_90d``).
_RECENCY_WINDOW = timedelta(days=90)

_TERMINAL_STAGES = ("won", "lost")


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    tenant_id: str
    name: str
    primary_contact_name: str | None
    primary_contact_email: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class DealRecord:
    deal_id: str
    client_id: str
    tenant_id: str
    name: str
    stage: str
    value_minor_units: int | None
    currency: str | None
    expected_close_date: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class InteractionRecord:
    interaction_id: str
    client_id: str
    deal_id: str | None
    stakeholder_id: str | None
    tenant_id: str
    interaction_type: str
    occurred_at: datetime
    summary: str
    created_by: str
    created_at: datetime


@dataclass(frozen=True)
class StakeholderWithEngagement:
    stakeholder_id: str
    client_id: str
    deal_id: str | None
    tenant_id: str
    name: str
    role: str
    email: str | None
    created_at: datetime
    updated_at: datetime
    interaction_count: int
    last_interaction_at: datetime | None


@dataclass(frozen=True)
class ClientEngagementSummary:
    """Bounded aggregate inputs to ``delta.crm.scoring.compute_relationship_score`` —
    never a full interaction list."""

    interaction_count_90d: int
    last_interaction_at: datetime | None
    open_deal_count: int


def _client_from_row(row) -> ClientRecord:
    return ClientRecord(
        client_id=row.client_id,
        tenant_id=row.tenant_id,
        name=row.name,
        primary_contact_name=row.primary_contact_name,
        primary_contact_email=row.primary_contact_email,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _deal_from_row(row) -> DealRecord:
    return DealRecord(
        deal_id=row.deal_id,
        client_id=row.client_id,
        tenant_id=row.tenant_id,
        name=row.name,
        stage=row.stage,
        value_minor_units=row.value_minor_units,
        currency=row.currency,
        expected_close_date=row.expected_close_date,
        closed_at=row.closed_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _interaction_from_row(row) -> InteractionRecord:
    return InteractionRecord(
        interaction_id=row.interaction_id,
        client_id=row.client_id,
        deal_id=row.deal_id,
        stakeholder_id=row.stakeholder_id,
        tenant_id=row.tenant_id,
        interaction_type=row.interaction_type,
        occurred_at=row.occurred_at,
        summary=row.summary,
        created_by=row.created_by,
        created_at=row.created_at,
    )


# ------------------------------------------------------------------------- clients


async def create_client(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    primary_contact_name: str | None,
    primary_contact_email: str | None,
    now: datetime,
    client_id: str | None = None,
) -> ClientRecord:
    cid = client_id or str(uuid.uuid4())
    await session.execute(
        insert(clients).values(
            client_id=cid,
            tenant_id=tenant_id,
            name=name,
            primary_contact_name=primary_contact_name,
            primary_contact_email=primary_contact_email,
            created_at=now,
            updated_at=now,
        )
    )
    return ClientRecord(
        client_id=cid,
        tenant_id=tenant_id,
        name=name,
        primary_contact_name=primary_contact_name,
        primary_contact_email=primary_contact_email,
        created_at=now,
        updated_at=now,
    )


async def get_client(session: AsyncSession, *, client_id: str) -> ClientRecord | None:
    row = (await session.execute(select(clients).where(clients.c.client_id == client_id))).first()
    return None if row is None else _client_from_row(row)


async def list_clients(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[ClientRecord]:
    stmt = select(clients).order_by(clients.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_client_from_row(r) for r in rows]


# --------------------------------------------------------------------------- deals


async def create_deal(
    session: AsyncSession,
    *,
    tenant_id: str,
    client_id: str,
    name: str,
    value_minor_units: int | None,
    currency: str | None,
    expected_close_date: datetime | None,
    now: datetime,
    deal_id: str | None = None,
) -> DealRecord:
    did = deal_id or str(uuid.uuid4())
    await session.execute(
        insert(deals).values(
            deal_id=did,
            client_id=client_id,
            tenant_id=tenant_id,
            name=name,
            stage="lead",
            value_minor_units=value_minor_units,
            currency=currency,
            expected_close_date=expected_close_date,
            closed_at=None,
            created_at=now,
            updated_at=now,
        )
    )
    return DealRecord(
        deal_id=did,
        client_id=client_id,
        tenant_id=tenant_id,
        name=name,
        stage="lead",
        value_minor_units=value_minor_units,
        currency=currency,
        expected_close_date=expected_close_date,
        closed_at=None,
        created_at=now,
        updated_at=now,
    )


async def get_deal(session: AsyncSession, *, deal_id: str) -> DealRecord | None:
    row = (await session.execute(select(deals).where(deals.c.deal_id == deal_id))).first()
    return None if row is None else _deal_from_row(row)


async def list_deals_for_client(
    session: AsyncSession, *, client_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[DealRecord]:
    stmt = (
        select(deals)
        .where(deals.c.client_id == client_id)
        .order_by(deals.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_deal_from_row(r) for r in rows]


async def try_transition_deal_stage(
    session: AsyncSession, *, deal_id: str, new_stage: str, now: datetime
) -> bool:
    """Conditionally move a deal to ``new_stage``. Does NOT commit.

    Guards a deal already in a terminal stage ('won'/'lost'): the WHERE clause only
    matches a row whose current stage is non-terminal, so a call against an
    already-terminal deal affects zero rows (the same conditional-UPDATE race-guard
    shape as D-007's ``try_decide_allocation`` / D-005's ``UPDATE ... WHERE
    state='under'``). Returns True iff this call performed the transition.
    """
    closed_at = now if new_stage in _TERMINAL_STAGES else None
    stmt = (
        update(deals)
        .where(deals.c.deal_id == deal_id)
        .where(deals.c.stage.notin_(_TERMINAL_STAGES))
        .values(stage=new_stage, updated_at=now, closed_at=closed_at)
    )
    result = await session.execute(stmt)
    return result.rowcount == 1


# -------------------------------------------------------------------- stakeholders


async def create_stakeholder(
    session: AsyncSession,
    *,
    tenant_id: str,
    client_id: str,
    deal_id: str | None,
    name: str,
    role: str,
    email: str | None,
    now: datetime,
    stakeholder_id: str | None = None,
) -> StakeholderWithEngagement:
    sid = stakeholder_id or str(uuid.uuid4())
    await session.execute(
        insert(stakeholders).values(
            stakeholder_id=sid,
            client_id=client_id,
            deal_id=deal_id,
            tenant_id=tenant_id,
            name=name,
            role=role,
            email=email,
            created_at=now,
            updated_at=now,
        )
    )
    return StakeholderWithEngagement(
        stakeholder_id=sid,
        client_id=client_id,
        deal_id=deal_id,
        tenant_id=tenant_id,
        name=name,
        role=role,
        email=email,
        created_at=now,
        updated_at=now,
        interaction_count=0,
        last_interaction_at=None,
    )


async def get_stakeholder(session: AsyncSession, *, stakeholder_id: str):
    return (
        await session.execute(
            select(stakeholders).where(stakeholders.c.stakeholder_id == stakeholder_id)
        )
    ).first()


async def list_stakeholders_for_client(
    session: AsyncSession, *, client_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[StakeholderWithEngagement]:
    """One query, not one-per-stakeholder: engagement is a LEFT JOIN + GROUP BY
    against ``interactions`` (grouped by the stakeholder primary key, so every other
    stakeholder column is selectable via Postgres's functional-dependency rule —
    no need to list them all in GROUP BY)."""
    join_cond = and_(
        interactions.c.stakeholder_id == stakeholders.c.stakeholder_id,
        interactions.c.tenant_id == stakeholders.c.tenant_id,
    )
    stmt = (
        select(
            stakeholders,
            func.count(interactions.c.interaction_id).label("interaction_count"),
            func.max(interactions.c.occurred_at).label("last_interaction_at"),
        )
        .select_from(stakeholders.outerjoin(interactions, join_cond))
        .where(stakeholders.c.client_id == client_id)
        .group_by(stakeholders.c.stakeholder_id)
        .order_by(stakeholders.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [
        StakeholderWithEngagement(
            stakeholder_id=r.stakeholder_id,
            client_id=r.client_id,
            deal_id=r.deal_id,
            tenant_id=r.tenant_id,
            name=r.name,
            role=r.role,
            email=r.email,
            created_at=r.created_at,
            updated_at=r.updated_at,
            interaction_count=r.interaction_count,
            last_interaction_at=r.last_interaction_at,
        )
        for r in rows
    ]


# -------------------------------------------------------------------- interactions


async def create_interaction(
    session: AsyncSession,
    *,
    tenant_id: str,
    client_id: str,
    deal_id: str | None,
    stakeholder_id: str | None,
    interaction_type: str,
    occurred_at: datetime,
    summary: str,
    created_by: str,
    now: datetime,
    interaction_id: str | None = None,
) -> InteractionRecord:
    iid = interaction_id or str(uuid.uuid4())
    await session.execute(
        insert(interactions).values(
            interaction_id=iid,
            client_id=client_id,
            deal_id=deal_id,
            stakeholder_id=stakeholder_id,
            tenant_id=tenant_id,
            interaction_type=interaction_type,
            occurred_at=occurred_at,
            summary=summary,
            created_by=created_by,
            created_at=now,
        )
    )
    return InteractionRecord(
        interaction_id=iid,
        client_id=client_id,
        deal_id=deal_id,
        stakeholder_id=stakeholder_id,
        tenant_id=tenant_id,
        interaction_type=interaction_type,
        occurred_at=occurred_at,
        summary=summary,
        created_by=created_by,
        created_at=now,
    )


async def list_interactions_for_client(
    session: AsyncSession, *, client_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[InteractionRecord]:
    stmt = (
        select(interactions)
        .where(interactions.c.client_id == client_id)
        .order_by(interactions.c.occurred_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_interaction_from_row(r) for r in rows]


# ---------------------------------------------------------- relationship-score inputs


async def get_client_engagement_summary(
    session: AsyncSession, *, client_id: str, now: datetime
) -> ClientEngagementSummary:
    """Bounded aggregate inputs for ``delta.crm.scoring.compute_relationship_score`` —
    two small aggregate queries (COUNT/MAX with a FILTER, and a deal-stage COUNT),
    never a scan of every interaction/deal row into Python."""
    cutoff = now - _RECENCY_WINDOW
    interaction_row = (
        await session.execute(
            select(
                func.count(interactions.c.interaction_id).filter(
                    interactions.c.occurred_at >= cutoff
                ),
                func.max(interactions.c.occurred_at),
            ).where(interactions.c.client_id == client_id)
        )
    ).first()
    interaction_count_90d = interaction_row[0] if interaction_row is not None else 0
    last_interaction_at = interaction_row[1] if interaction_row is not None else None

    open_deal_count = (
        await session.execute(
            select(func.count(deals.c.deal_id))
            .where(deals.c.client_id == client_id)
            .where(deals.c.stage.notin_(_TERMINAL_STAGES))
        )
    ).scalar_one()

    return ClientEngagementSummary(
        interaction_count_90d=interaction_count_90d,
        last_interaction_at=last_interaction_at,
        open_deal_count=open_deal_count,
    )
