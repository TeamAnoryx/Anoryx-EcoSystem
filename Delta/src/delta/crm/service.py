"""Unified CRM orchestration (D-013, ADR-0013).

DTO <-> store mapping + the cross-entity checks the DB's FK constraints don't cover on
their own (an FK proves a deal/stakeholder belongs to the caller's TENANT; it does not
prove it belongs to the specific CLIENT a request is scoped to — that's checked here).
Mirrors ``allocation_admin.service``: store functions never commit, this layer commits
once per mutating call.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..money import DEFAULT_CURRENCY
from . import store
from .schemas import (
    ClientCreateRequest,
    ClientDetailView,
    ClientView,
    DealCreateRequest,
    DealStageTransitionRequest,
    DealView,
    InteractionCreateRequest,
    InteractionView,
    RelationshipScoreView,
    StakeholderCreateRequest,
    StakeholderView,
)
from .scoring import compute_relationship_score, days_since


class ClientNotFoundError(LookupError):
    pass


class DealNotFoundError(LookupError):
    pass


class StakeholderNotFoundError(LookupError):
    pass


class DealAlreadyTerminalError(RuntimeError):
    """A stage transition was attempted on a deal already 'won'/'lost'."""


class CrmScopeMismatchError(ValueError):
    """A supplied deal_id/stakeholder_id exists but belongs to a different client."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _client_to_view(record: store.ClientRecord) -> ClientView:
    return ClientView(
        client_id=record.client_id,
        tenant_id=record.tenant_id,
        name=record.name,
        primary_contact_name=record.primary_contact_name,
        primary_contact_email=record.primary_contact_email,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _deal_to_view(record: store.DealRecord) -> DealView:
    return DealView(
        deal_id=record.deal_id,
        client_id=record.client_id,
        tenant_id=record.tenant_id,
        name=record.name,
        stage=record.stage,  # type: ignore[arg-type]
        value_minor_units=record.value_minor_units,
        currency=record.currency,
        expected_close_date=record.expected_close_date,
        closed_at=record.closed_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _interaction_to_view(record: store.InteractionRecord) -> InteractionView:
    return InteractionView(
        interaction_id=record.interaction_id,
        client_id=record.client_id,
        deal_id=record.deal_id,
        stakeholder_id=record.stakeholder_id,
        tenant_id=record.tenant_id,
        interaction_type=record.interaction_type,  # type: ignore[arg-type]
        occurred_at=record.occurred_at,
        summary=record.summary,
        created_by=record.created_by,
        created_at=record.created_at,
    )


def _stakeholder_to_view(record: store.StakeholderWithEngagement) -> StakeholderView:
    return StakeholderView(
        stakeholder_id=record.stakeholder_id,
        client_id=record.client_id,
        deal_id=record.deal_id,
        tenant_id=record.tenant_id,
        name=record.name,
        role=record.role,  # type: ignore[arg-type]
        email=record.email,
        created_at=record.created_at,
        updated_at=record.updated_at,
        interaction_count=record.interaction_count,
        last_interaction_at=record.last_interaction_at,
    )


async def _require_client(session: AsyncSession, *, client_id: str) -> store.ClientRecord:
    record = await store.get_client(session, client_id=client_id)
    if record is None:
        raise ClientNotFoundError(client_id)
    return record


async def _check_deal_scope(session: AsyncSession, *, deal_id: str, client_id: str) -> None:
    deal = await store.get_deal(session, deal_id=deal_id)
    if deal is None:
        raise DealNotFoundError(deal_id)
    if deal.client_id != client_id:
        raise CrmScopeMismatchError(f"deal {deal_id} does not belong to client {client_id}")


async def _check_stakeholder_scope(
    session: AsyncSession, *, stakeholder_id: str, client_id: str
) -> None:
    row = await store.get_stakeholder(session, stakeholder_id=stakeholder_id)
    if row is None:
        raise StakeholderNotFoundError(stakeholder_id)
    if row.client_id != client_id:
        raise CrmScopeMismatchError(
            f"stakeholder {stakeholder_id} does not belong to client {client_id}"
        )


# ------------------------------------------------------------------------- clients


async def create_client(session: AsyncSession, req: ClientCreateRequest) -> ClientView:
    record = await store.create_client(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        primary_contact_name=req.primary_contact_name,
        primary_contact_email=req.primary_contact_email,
        now=_now(),
    )
    await session.commit()
    return _client_to_view(record)


async def get_client_view(session: AsyncSession, *, client_id: str) -> ClientView | None:
    record = await store.get_client(session, client_id=client_id)
    return None if record is None else _client_to_view(record)


async def list_client_views(session: AsyncSession, *, limit: int) -> list[ClientView]:
    records = await store.list_clients(session, limit=limit)
    return [_client_to_view(r) for r in records]


# --------------------------------------------------------------------------- deals


async def create_deal(session: AsyncSession, *, client_id: str, req: DealCreateRequest) -> DealView:
    await _require_client(session, client_id=client_id)
    # A deal with a value always carries a currency (defaulting a caller-supplied
    # `null` to DEFAULT_CURRENCY, not just an unset field); a deal without a value
    # carries none. The two always travel together in both directions — a bare DB
    # CHECK backs this up as a second, independent layer (migration 0007).
    currency = (req.currency or DEFAULT_CURRENCY) if req.value_minor_units is not None else None
    record = await store.create_deal(
        session,
        tenant_id=req.tenant_id,
        client_id=client_id,
        name=req.name,
        value_minor_units=req.value_minor_units,
        currency=currency,
        expected_close_date=req.expected_close_date,
        now=_now(),
    )
    await session.commit()
    return _deal_to_view(record)


async def list_deal_views(session: AsyncSession, *, client_id: str, limit: int) -> list[DealView]:
    records = await store.list_deals_for_client(session, client_id=client_id, limit=limit)
    return [_deal_to_view(r) for r in records]


async def transition_deal_stage(
    session: AsyncSession, *, deal_id: str, req: DealStageTransitionRequest
) -> DealView:
    existing = await store.get_deal(session, deal_id=deal_id)
    if existing is None:
        raise DealNotFoundError(deal_id)
    now = _now()
    moved = await store.try_transition_deal_stage(
        session, deal_id=deal_id, new_stage=req.stage, now=now
    )
    if not moved:
        raise DealAlreadyTerminalError(deal_id)
    record = await store.get_deal(session, deal_id=deal_id)
    await session.commit()
    if record is None:
        raise DealNotFoundError(deal_id)  # unreachable: just wrote it in this transaction
    return _deal_to_view(record)


# -------------------------------------------------------------------- stakeholders


async def create_stakeholder(
    session: AsyncSession, *, client_id: str, req: StakeholderCreateRequest
) -> StakeholderView:
    await _require_client(session, client_id=client_id)
    if req.deal_id is not None:
        await _check_deal_scope(session, deal_id=req.deal_id, client_id=client_id)
    record = await store.create_stakeholder(
        session,
        tenant_id=req.tenant_id,
        client_id=client_id,
        deal_id=req.deal_id,
        name=req.name,
        role=req.role,
        email=req.email,
        now=_now(),
    )
    await session.commit()
    return _stakeholder_to_view(record)


async def list_stakeholder_views(
    session: AsyncSession, *, client_id: str, limit: int
) -> list[StakeholderView]:
    records = await store.list_stakeholders_for_client(session, client_id=client_id, limit=limit)
    return [_stakeholder_to_view(r) for r in records]


# -------------------------------------------------------------------- interactions


async def create_interaction(
    session: AsyncSession, *, client_id: str, req: InteractionCreateRequest
) -> InteractionView:
    await _require_client(session, client_id=client_id)
    if req.deal_id is not None:
        await _check_deal_scope(session, deal_id=req.deal_id, client_id=client_id)
    if req.stakeholder_id is not None:
        await _check_stakeholder_scope(
            session, stakeholder_id=req.stakeholder_id, client_id=client_id
        )
    record = await store.create_interaction(
        session,
        tenant_id=req.tenant_id,
        client_id=client_id,
        deal_id=req.deal_id,
        stakeholder_id=req.stakeholder_id,
        interaction_type=req.interaction_type,
        occurred_at=req.occurred_at,
        summary=req.summary,
        created_by=req.created_by,
        now=_now(),
    )
    await session.commit()
    return _interaction_to_view(record)


async def list_interaction_views(
    session: AsyncSession, *, client_id: str, limit: int
) -> list[InteractionView]:
    records = await store.list_interactions_for_client(session, client_id=client_id, limit=limit)
    return [_interaction_to_view(r) for r in records]


# --------------------------------------------------------------- relationship score


async def get_relationship_score(session: AsyncSession, *, client_id: str) -> RelationshipScoreView:
    now = _now()
    summary = await store.get_client_engagement_summary(session, client_id=client_id, now=now)
    result = compute_relationship_score(
        interaction_count_90d=summary.interaction_count_90d,
        days_since_last_interaction=days_since(
            now=now, last_interaction_at=summary.last_interaction_at
        ),
        open_deal_count=summary.open_deal_count,
    )
    return RelationshipScoreView(
        client_id=client_id,
        score=result.score,
        interaction_count_90d=summary.interaction_count_90d,
        days_since_last_interaction=days_since(
            now=now, last_interaction_at=summary.last_interaction_at
        ),
        open_deal_count=summary.open_deal_count,
        method=result.method,
    )


# ------------------------------------------------------------------ composed detail

# Bounded, not the same as the list endpoints' own (potentially larger) limits — a
# detail page shows a summary, not a full history (mirrors D-011's forecast detail
# view being a single bounded read, not a paginated list).
_DETAIL_DEALS_LIMIT = 25
_DETAIL_INTERACTIONS_LIMIT = 10
_DETAIL_STAKEHOLDERS_LIMIT = 25


async def get_client_detail(session: AsyncSession, *, client_id: str) -> ClientDetailView:
    client_record = await _require_client(session, client_id=client_id)
    deal_views = await list_deal_views(session, client_id=client_id, limit=_DETAIL_DEALS_LIMIT)
    interaction_views = await list_interaction_views(
        session, client_id=client_id, limit=_DETAIL_INTERACTIONS_LIMIT
    )
    stakeholder_views = await list_stakeholder_views(
        session, client_id=client_id, limit=_DETAIL_STAKEHOLDERS_LIMIT
    )
    score_view = await get_relationship_score(session, client_id=client_id)
    return ClientDetailView(
        client=_client_to_view(client_record),
        deals=deal_views,
        recent_interactions=interaction_views,
        stakeholders=stakeholder_views,
        relationship_score=score_view,
    )
