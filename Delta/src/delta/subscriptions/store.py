"""Subscription registry + charge-ledger persistence (D-022, ADR-0021).

Tenant-scoped reads/writes against ``subscriptions``/``subscription_charges``
(migration 0014). Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like ``erp.store``/``invoicing.store``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import subscription_charges, subscriptions, vendors

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# A subscription's own trailing baseline can never look back further than this many
# prior charges in one windowed-query round trip (ADR-0021 Fork 2) — bounds the
# per-subscription result set the same way `chargeback.schemas.MAX_BASELINE_PERIODS`
# bounds D-012's calendar-window baseline.
MAX_RECENT_CHARGES_WINDOW = 25


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class SubscriptionRecord:
    subscription_id: str
    tenant_id: str
    vendor_id: str | None
    name: str
    expected_amount_minor_units: int | None
    currency: str | None
    cadence: str
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    cancelled_at: datetime | None


@dataclass(frozen=True)
class ChargeRecord:
    charge_id: str
    tenant_id: str
    subscription_id: str
    amount_minor_units: int
    currency: str
    charged_at: datetime
    recorded_by: str
    note: str | None
    created_at: datetime


def _subscription_from_row(row) -> SubscriptionRecord:
    return SubscriptionRecord(
        subscription_id=row.subscription_id,
        tenant_id=row.tenant_id,
        vendor_id=row.vendor_id,
        name=row.name,
        expected_amount_minor_units=row.expected_amount_minor_units,
        currency=row.currency,
        cadence=row.cadence,
        status=row.status,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        cancelled_at=row.cancelled_at,
    )


def _charge_from_row(row) -> ChargeRecord:
    return ChargeRecord(
        charge_id=row.charge_id,
        tenant_id=row.tenant_id,
        subscription_id=row.subscription_id,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        charged_at=row.charged_at,
        recorded_by=row.recorded_by,
        note=row.note,
        created_at=row.created_at,
    )


# --------------------------------------------------------------------- vendor lookup


async def get_vendor_status(session: AsyncSession, *, vendor_id: str) -> str | None:
    """Mirrors ``erp.store.get_vendor``/``invoicing.store.get_vendor_status`` — a
    friendly existence check for the optional vendor link, not a cross-package import
    of ``erp.store`` (every prior Delta package that references a vendor queries the
    shared ``vendors`` table directly rather than reaching into another feature's
    store module)."""
    row = (
        await session.execute(select(vendors.c.status).where(vendors.c.vendor_id == vendor_id))
    ).first()
    return None if row is None else row[0]


# --------------------------------------------------------------------- subscriptions


async def create_subscription(
    session: AsyncSession,
    *,
    tenant_id: str,
    vendor_id: str | None,
    name: str,
    expected_amount_minor_units: int | None,
    currency: str | None,
    cadence: str,
    created_by: str,
    now: datetime,
    subscription_id: str | None = None,
) -> SubscriptionRecord:
    sid = subscription_id or str(uuid.uuid4())
    await session.execute(
        insert(subscriptions).values(
            subscription_id=sid,
            tenant_id=tenant_id,
            vendor_id=vendor_id,
            name=name,
            expected_amount_minor_units=expected_amount_minor_units,
            currency=currency,
            cadence=cadence,
            status="active",
            created_by=created_by,
            created_at=now,
            updated_at=now,
            cancelled_at=None,
        )
    )
    return SubscriptionRecord(
        subscription_id=sid,
        tenant_id=tenant_id,
        vendor_id=vendor_id,
        name=name,
        expected_amount_minor_units=expected_amount_minor_units,
        currency=currency,
        cadence=cadence,
        status="active",
        created_by=created_by,
        created_at=now,
        updated_at=now,
        cancelled_at=None,
    )


async def get_subscription(
    session: AsyncSession, *, subscription_id: str
) -> SubscriptionRecord | None:
    row = (
        await session.execute(
            select(subscriptions).where(subscriptions.c.subscription_id == subscription_id)
        )
    ).first()
    return None if row is None else _subscription_from_row(row)


async def list_subscriptions(
    session: AsyncSession, *, status: str | None = None, limit: int = DEFAULT_LIST_LIMIT
) -> list[SubscriptionRecord]:
    stmt = select(subscriptions)
    if status is not None:
        stmt = stmt.where(subscriptions.c.status == status)
    stmt = stmt.order_by(subscriptions.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_subscription_from_row(r) for r in rows]


async def try_cancel_subscription(
    session: AsyncSession, *, subscription_id: str, actor: str, now: datetime
) -> bool:
    """Conditionally transition 'active' -> 'cancelled'. Does NOT commit.

    Same conditional-UPDATE shape as D-014's ``try_transition_asset_status``: the
    WHERE clause only matches a row currently 'active', guarding a concurrent
    double-cancel. Returns True iff this call performed the transition.
    """
    result = await session.execute(
        update(subscriptions)
        .where(subscriptions.c.subscription_id == subscription_id)
        .where(subscriptions.c.status == "active")
        .values(status="cancelled", updated_at=now, cancelled_at=now)
    )
    return result.rowcount == 1


# ---------------------------------------------------------------------------- charges


async def create_charge(
    session: AsyncSession,
    *,
    tenant_id: str,
    subscription_id: str,
    amount_minor_units: int,
    currency: str,
    charged_at: datetime,
    recorded_by: str,
    note: str | None,
    now: datetime,
    charge_id: str | None = None,
) -> ChargeRecord:
    cid = charge_id or str(uuid.uuid4())
    await session.execute(
        insert(subscription_charges).values(
            charge_id=cid,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            amount_minor_units=amount_minor_units,
            currency=currency,
            charged_at=charged_at,
            recorded_by=recorded_by,
            note=note,
            created_at=now,
        )
    )
    return ChargeRecord(
        charge_id=cid,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        amount_minor_units=amount_minor_units,
        currency=currency,
        charged_at=charged_at,
        recorded_by=recorded_by,
        note=note,
        created_at=now,
    )


async def list_charges(
    session: AsyncSession, *, subscription_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[ChargeRecord]:
    stmt = (
        select(subscription_charges)
        .where(subscription_charges.c.subscription_id == subscription_id)
        .order_by(subscription_charges.c.charged_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_charge_from_row(r) for r in rows]


async def list_recent_charges_by_subscription(
    session: AsyncSession, *, subscription_ids: list[str], window_size: int
) -> dict[str, list[ChargeRecord]]:
    """The `window_size + 1` most recent charges for EACH of ``subscription_ids``, one
    query total regardless of how many subscriptions are passed (ADR-0021 Fork 2 —
    mirrors D-012 Fork 2's "never N+1 per group" discipline, adapted with a SQL
    ``ROW_NUMBER() OVER (PARTITION BY subscription_id ...)`` window function instead
    of D-012's two-bulk-query shape, since here each group's own baseline window is
    "however many of ITS OWN prior charges exist," not a shared calendar window).

    Returned lists are newest-first; the caller treats index 0 as the current charge
    and the rest as the trailing baseline.
    """
    window_size = max(1, min(window_size, MAX_RECENT_CHARGES_WINDOW))
    if not subscription_ids:
        return {}

    rn = (
        func.row_number()
        .over(
            partition_by=subscription_charges.c.subscription_id,
            order_by=subscription_charges.c.charged_at.desc(),
        )
        .label("rn")
    )
    ranked = (
        select(subscription_charges, rn)
        .where(subscription_charges.c.subscription_id.in_(subscription_ids))
        .subquery()
    )
    stmt = (
        select(ranked)
        .where(ranked.c.rn <= window_size + 1)
        .order_by(ranked.c.subscription_id, ranked.c.rn)
    )
    rows = (await session.execute(stmt)).all()

    by_subscription: dict[str, list[ChargeRecord]] = {}
    for row in rows:
        by_subscription.setdefault(row.subscription_id, []).append(_charge_from_row(row))
    return by_subscription
