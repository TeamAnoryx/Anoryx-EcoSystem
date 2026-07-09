"""ERP persistence (D-014, ADR-0014).

Tenant-scoped reads/writes against ``vendors``/``assets``/``purchase_orders``
(migration 0008). Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like ``allocation_admin.store``/
``crm.store``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import assets, purchase_orders, vendors

# List-response bounds (mirrors D-007/D-013's own caps).
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# Forward-only asset lifecycle: a transition is valid only from the exact prior status.
REQUIRED_PRIOR_STATUS: dict[str, str] = {"retired": "active", "disposed": "retired"}


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class VendorRecord:
    vendor_id: str
    tenant_id: str
    name: str
    contact_email: str | None
    status: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class AssetRecord:
    asset_id: str
    tenant_id: str
    name: str
    category: str
    status: str
    acquisition_cost_minor_units: int | None
    currency: str | None
    acquired_at: datetime | None
    assigned_team_id: str | None
    retired_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class PurchaseOrderRecord:
    po_id: str
    tenant_id: str
    vendor_id: str
    asset_id: str | None
    description: str
    amount_minor_units: int
    currency: str
    status: str
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None


def _vendor_from_row(row) -> VendorRecord:
    return VendorRecord(
        vendor_id=row.vendor_id,
        tenant_id=row.tenant_id,
        name=row.name,
        contact_email=row.contact_email,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _asset_from_row(row) -> AssetRecord:
    return AssetRecord(
        asset_id=row.asset_id,
        tenant_id=row.tenant_id,
        name=row.name,
        category=row.category,
        status=row.status,
        acquisition_cost_minor_units=row.acquisition_cost_minor_units,
        currency=row.currency,
        acquired_at=row.acquired_at,
        assigned_team_id=row.assigned_team_id,
        retired_at=row.retired_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _po_from_row(row) -> PurchaseOrderRecord:
    return PurchaseOrderRecord(
        po_id=row.po_id,
        tenant_id=row.tenant_id,
        vendor_id=row.vendor_id,
        asset_id=row.asset_id,
        description=row.description,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        status=row.status,
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
    )


# ------------------------------------------------------------------------- vendors


async def create_vendor(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    contact_email: str | None,
    now: datetime,
    vendor_id: str | None = None,
) -> VendorRecord:
    vid = vendor_id or str(uuid.uuid4())
    await session.execute(
        insert(vendors).values(
            vendor_id=vid,
            tenant_id=tenant_id,
            name=name,
            contact_email=contact_email,
            status="active",
            created_at=now,
            updated_at=now,
        )
    )
    return VendorRecord(
        vendor_id=vid,
        tenant_id=tenant_id,
        name=name,
        contact_email=contact_email,
        status="active",
        created_at=now,
        updated_at=now,
    )


async def get_vendor(session: AsyncSession, *, vendor_id: str) -> VendorRecord | None:
    row = (await session.execute(select(vendors).where(vendors.c.vendor_id == vendor_id))).first()
    return None if row is None else _vendor_from_row(row)


async def list_vendors(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[VendorRecord]:
    stmt = select(vendors).order_by(vendors.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_vendor_from_row(r) for r in rows]


# -------------------------------------------------------------------------- assets


async def create_asset(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    category: str,
    acquisition_cost_minor_units: int | None,
    currency: str | None,
    acquired_at: datetime | None,
    assigned_team_id: str | None,
    now: datetime,
    asset_id: str | None = None,
) -> AssetRecord:
    aid = asset_id or str(uuid.uuid4())
    await session.execute(
        insert(assets).values(
            asset_id=aid,
            tenant_id=tenant_id,
            name=name,
            category=category,
            status="active",
            acquisition_cost_minor_units=acquisition_cost_minor_units,
            currency=currency,
            acquired_at=acquired_at,
            assigned_team_id=assigned_team_id,
            retired_at=None,
            created_at=now,
            updated_at=now,
        )
    )
    return AssetRecord(
        asset_id=aid,
        tenant_id=tenant_id,
        name=name,
        category=category,
        status="active",
        acquisition_cost_minor_units=acquisition_cost_minor_units,
        currency=currency,
        acquired_at=acquired_at,
        assigned_team_id=assigned_team_id,
        retired_at=None,
        created_at=now,
        updated_at=now,
    )


async def get_asset(session: AsyncSession, *, asset_id: str) -> AssetRecord | None:
    row = (await session.execute(select(assets).where(assets.c.asset_id == asset_id))).first()
    return None if row is None else _asset_from_row(row)


async def list_assets(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[AssetRecord]:
    stmt = select(assets).order_by(assets.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_asset_from_row(r) for r in rows]


async def try_transition_asset_status(
    session: AsyncSession, *, asset_id: str, target_status: str, required_prior: str, now: datetime
) -> bool:
    """Conditionally move ``required_prior`` -> ``target_status``. Does NOT commit.

    Guards both "already at/past this status" and "skipping a step": the WHERE clause
    only matches a row whose CURRENT status is EXACTLY ``required_prior``, the same
    conditional-UPDATE shape as D-007's ``try_decide_allocation``/D-013's
    ``try_transition_deal_stage``. Returns True iff this call performed the transition.
    """
    retired_at = now if target_status in ("retired", "disposed") else None
    stmt = (
        update(assets)
        .where(assets.c.asset_id == asset_id)
        .where(assets.c.status == required_prior)
        .values(
            status=target_status,
            updated_at=now,
            # retired_at is set on the first non-active status and never cleared —
            # it records "when this asset stopped being active," not "when it was
            # disposed" specifically.
            retired_at=assets.c.retired_at if target_status == "active" else retired_at,
        )
    )
    result = await session.execute(stmt)
    return result.rowcount == 1


# ------------------------------------------------------------------ purchase_orders


async def create_purchase_order(
    session: AsyncSession,
    *,
    tenant_id: str,
    vendor_id: str,
    asset_id: str | None,
    description: str,
    amount_minor_units: int,
    currency: str,
    requested_by: str,
    now: datetime,
    po_id: str | None = None,
) -> PurchaseOrderRecord:
    pid = po_id or str(uuid.uuid4())
    await session.execute(
        insert(purchase_orders).values(
            po_id=pid,
            tenant_id=tenant_id,
            vendor_id=vendor_id,
            asset_id=asset_id,
            description=description,
            amount_minor_units=amount_minor_units,
            currency=currency,
            status="requested",
            requested_by=requested_by,
            requested_at=now,
            decided_by=None,
            decided_at=None,
        )
    )
    return PurchaseOrderRecord(
        po_id=pid,
        tenant_id=tenant_id,
        vendor_id=vendor_id,
        asset_id=asset_id,
        description=description,
        amount_minor_units=amount_minor_units,
        currency=currency,
        status="requested",
        requested_by=requested_by,
        requested_at=now,
        decided_by=None,
        decided_at=None,
    )


async def get_purchase_order(session: AsyncSession, *, po_id: str) -> PurchaseOrderRecord | None:
    row = (
        await session.execute(select(purchase_orders).where(purchase_orders.c.po_id == po_id))
    ).first()
    return None if row is None else _po_from_row(row)


async def list_purchase_orders(
    session: AsyncSession, *, status: str | None = None, limit: int = DEFAULT_LIST_LIMIT
) -> list[PurchaseOrderRecord]:
    stmt = select(purchase_orders)
    if status is not None:
        stmt = stmt.where(purchase_orders.c.status == status)
    stmt = stmt.order_by(purchase_orders.c.requested_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_po_from_row(r) for r in rows]


async def try_decide_purchase_order(
    session: AsyncSession,
    *,
    po_id: str,
    new_status: str,
    decided_by: str,
    now: datetime,
) -> bool:
    """Conditionally transition 'requested' -> ``new_status``. Does NOT commit.

    Guards concurrent double-decision — identical shape to D-007's
    ``try_decide_allocation``: the WHERE clause only matches a row still 'requested'.
    Returns True iff this call performed the transition.
    """
    result = await session.execute(
        update(purchase_orders)
        .where(purchase_orders.c.po_id == po_id)
        .where(purchase_orders.c.status == "requested")
        .values(status=new_status, decided_by=decided_by, decided_at=now)
    )
    return result.rowcount == 1
