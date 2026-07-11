"""Investment-holding persistence (D-023, ADR-0023).

Tenant-scoped reads/writes against ``investment_holdings`` (migration 0017). Every
function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like every prior Delta store module.

``investment_holdings`` is INSERT-only (mirrors D-021's ``personal_budgets``): a
holding value change is a new snapshot row for that (account_id, asset_class) pair,
so :func:`get_latest_holdings` reads the most recent row per pair.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import investment_holdings

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class HoldingRecord:
    holding_id: str
    tenant_id: str
    account_id: str
    asset_class: str
    value_minor_units: int
    currency: str
    created_at: datetime


def _holding_from_row(row) -> HoldingRecord:
    return HoldingRecord(
        holding_id=row.holding_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        asset_class=row.asset_class,
        value_minor_units=row.value_minor_units,
        currency=row.currency,
        created_at=row.created_at,
    )


async def create_holding(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    asset_class: str,
    value_minor_units: int,
    currency: str,
    now: datetime,
) -> HoldingRecord:
    holding_id = str(uuid.uuid4())
    await session.execute(
        insert(investment_holdings).values(
            holding_id=holding_id,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class=asset_class,
            value_minor_units=value_minor_units,
            currency=currency,
            created_at=now,
        )
    )
    return HoldingRecord(
        holding_id=holding_id,
        tenant_id=tenant_id,
        account_id=account_id,
        asset_class=asset_class,
        value_minor_units=value_minor_units,
        currency=currency,
        created_at=now,
    )


async def get_latest_holdings(
    session: AsyncSession,
    *,
    account_id: str | None = None,
    currency: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[HoldingRecord]:
    """One row per (account_id, asset_class, currency): the most recently created
    snapshot. ``currency`` is included in the "latest per group" grouping (security
    audit finding) — without it, an account holding the SAME asset class in two
    currencies would have the older currency's row silently hidden by the newer
    one's ``MAX(created_at)``.

    ``currency`` (the filter param) scopes the result to one reporting currency —
    the allocation-recommendation path MUST pass it: summing mixed-currency
    holdings into one portfolio total would silently corrupt the total (the same
    "single reporting currency" rule D-021's health-score path enforces, ADR-0021
    §2 Fork 9). ``None`` returns every currency (the plain list-holdings endpoint,
    where each row carries its own currency label).

    This is a LIST-shaped, ``limit``-bounded query — the allocation-recommendation
    path's portfolio TOTAL must never be computed from this function (a display
    limit must never silently truncate a monetary aggregate); use
    :func:`get_total_value_by_asset_class` for that instead (security audit
    finding).
    """
    latest_filter = select(
        investment_holdings.c.account_id,
        investment_holdings.c.asset_class,
        investment_holdings.c.currency,
        func.max(investment_holdings.c.created_at).label("latest_created_at"),
    )
    if account_id is not None:
        latest_filter = latest_filter.where(investment_holdings.c.account_id == account_id)
    if currency is not None:
        latest_filter = latest_filter.where(investment_holdings.c.currency == currency)
    latest_per_pair = latest_filter.group_by(
        investment_holdings.c.account_id,
        investment_holdings.c.asset_class,
        investment_holdings.c.currency,
    ).subquery()

    stmt = select(investment_holdings).join(
        latest_per_pair,
        (investment_holdings.c.account_id == latest_per_pair.c.account_id)
        & (investment_holdings.c.asset_class == latest_per_pair.c.asset_class)
        & (investment_holdings.c.currency == latest_per_pair.c.currency)
        & (investment_holdings.c.created_at == latest_per_pair.c.latest_created_at),
    )
    if account_id is not None:
        stmt = stmt.where(investment_holdings.c.account_id == account_id)
    if currency is not None:
        stmt = stmt.where(investment_holdings.c.currency == currency)
    stmt = stmt.order_by(investment_holdings.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_holding_from_row(r) for r in rows]


async def get_total_value_by_asset_class(session: AsyncSession, *, currency: str) -> dict[str, int]:
    """SUM of the latest snapshot's value per asset_class, across every account, in
    ONE reporting currency — a genuine SQL aggregate, deliberately UNBOUNDED by any
    row ``limit`` (unlike :func:`get_latest_holdings`, which is list-endpoint-shaped
    and caps at ``MAX_LIST_LIMIT``). A tenant with more than 500 distinct
    (account_id, asset_class) snapshots must still get an exact portfolio total —
    a display limit must never silently truncate a monetary aggregate (security
    audit finding). Only asset classes with at least one holding appear in the
    result; the caller fills in zero for the rest.
    """
    latest_per_pair = (
        select(
            investment_holdings.c.account_id,
            investment_holdings.c.asset_class,
            func.max(investment_holdings.c.created_at).label("latest_created_at"),
        )
        .where(investment_holdings.c.currency == currency)
        .group_by(investment_holdings.c.account_id, investment_holdings.c.asset_class)
        .subquery()
    )
    stmt = (
        select(
            investment_holdings.c.asset_class,
            func.sum(investment_holdings.c.value_minor_units).label("total"),
        )
        .join(
            latest_per_pair,
            (investment_holdings.c.account_id == latest_per_pair.c.account_id)
            & (investment_holdings.c.asset_class == latest_per_pair.c.asset_class)
            & (investment_holdings.c.created_at == latest_per_pair.c.latest_created_at),
        )
        .where(investment_holdings.c.currency == currency)
        .group_by(investment_holdings.c.asset_class)
    )
    rows = (await session.execute(stmt)).all()
    return {r.asset_class: int(r.total) for r in rows}
