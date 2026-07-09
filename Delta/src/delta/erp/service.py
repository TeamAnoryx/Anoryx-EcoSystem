"""ERP orchestration (D-014, ADR-0014).

DTO <-> store mapping + the vendor/asset existence checks the DB's FK constraints
enforce structurally at the tenant level but that still need a friendly 404 rather
than a raw IntegrityError. Mirrors ``allocation_admin.service``/``crm.service``: store
functions never commit, this layer commits once per mutating call.

A purchase-order DECISION is wired into D-009's hash-chained audit log
(``delta.persistence.audit_log.append_history``) in the SAME transaction as the store
write — unlike D-013's CRM edits (business-process data), a PO decision is a genuine
financial commitment, matching the roadmap's own "Depends on: D-009" for this task.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..money import DEFAULT_CURRENCY
from ..persistence.audit_log import append_history
from . import store
from .schemas import (
    AssetCreateRequest,
    AssetStatusTransitionRequest,
    AssetView,
    PurchaseOrderCreateRequest,
    PurchaseOrderDecisionRequest,
    PurchaseOrderView,
    VendorCreateRequest,
    VendorView,
)


class VendorNotFoundError(LookupError):
    pass


class AssetNotFoundError(LookupError):
    pass


class PurchaseOrderNotFoundError(LookupError):
    pass


class PurchaseOrderAlreadyDecidedError(RuntimeError):
    """A decision was attempted on a PO that is no longer 'requested'."""


class InvalidAssetTransitionError(ValueError):
    """The requested asset status is not the immediate next step in its lifecycle."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _vendor_to_view(record: store.VendorRecord) -> VendorView:
    return VendorView(
        vendor_id=record.vendor_id,
        tenant_id=record.tenant_id,
        name=record.name,
        contact_email=record.contact_email,
        status=record.status,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _asset_to_view(record: store.AssetRecord) -> AssetView:
    return AssetView(
        asset_id=record.asset_id,
        tenant_id=record.tenant_id,
        name=record.name,
        category=record.category,  # type: ignore[arg-type]
        status=record.status,  # type: ignore[arg-type]
        acquisition_cost_minor_units=record.acquisition_cost_minor_units,
        currency=record.currency,
        acquired_at=record.acquired_at,
        assigned_team_id=record.assigned_team_id,
        retired_at=record.retired_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _po_to_view(record: store.PurchaseOrderRecord) -> PurchaseOrderView:
    return PurchaseOrderView(
        po_id=record.po_id,
        tenant_id=record.tenant_id,
        vendor_id=record.vendor_id,
        asset_id=record.asset_id,
        description=record.description,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,
        status=record.status,  # type: ignore[arg-type]
        requested_by=record.requested_by,
        requested_at=record.requested_at,
        decided_by=record.decided_by,
        decided_at=record.decided_at,
    )


# ------------------------------------------------------------------------- vendors


async def create_vendor(session: AsyncSession, req: VendorCreateRequest) -> VendorView:
    record = await store.create_vendor(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        contact_email=req.contact_email,
        now=_now(),
    )
    await session.commit()
    return _vendor_to_view(record)


async def list_vendor_views(session: AsyncSession, *, limit: int) -> list[VendorView]:
    records = await store.list_vendors(session, limit=limit)
    return [_vendor_to_view(r) for r in records]


# -------------------------------------------------------------------------- assets


async def create_asset(session: AsyncSession, req: AssetCreateRequest) -> AssetView:
    # An asset with an acquisition cost always carries a currency, and vice versa —
    # same pairing discipline as D-013's deal value/currency fix (ADR-0013 §4 finding
    # #1), applied here from the start (also backed by a DB CHECK, migration 0008).
    currency = (
        (req.currency or DEFAULT_CURRENCY) if req.acquisition_cost_minor_units is not None else None
    )
    record = await store.create_asset(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        category=req.category,
        acquisition_cost_minor_units=req.acquisition_cost_minor_units,
        currency=currency,
        acquired_at=req.acquired_at,
        assigned_team_id=req.assigned_team_id,
        now=_now(),
    )
    await session.commit()
    return _asset_to_view(record)


async def list_asset_views(session: AsyncSession, *, limit: int) -> list[AssetView]:
    records = await store.list_assets(session, limit=limit)
    return [_asset_to_view(r) for r in records]


async def transition_asset_status(
    session: AsyncSession, *, asset_id: str, req: AssetStatusTransitionRequest
) -> AssetView:
    existing = await store.get_asset(session, asset_id=asset_id)
    if existing is None:
        raise AssetNotFoundError(asset_id)
    required_prior = store.REQUIRED_PRIOR_STATUS.get(req.status)
    if required_prior is None:
        # req.status == "active" (not a valid forward target) or an otherwise
        # unrecognized target the Literal type already rejects at the schema layer.
        raise InvalidAssetTransitionError(f"{req.status} is not a valid forward transition target")
    now = _now()
    moved = await store.try_transition_asset_status(
        session,
        asset_id=asset_id,
        target_status=req.status,
        required_prior=required_prior,
        now=now,
    )
    if not moved:
        raise InvalidAssetTransitionError(
            f"asset {asset_id} is not currently '{required_prior}' — cannot move to '{req.status}'"
        )
    record = await store.get_asset(session, asset_id=asset_id)
    await session.commit()
    if record is None:
        raise AssetNotFoundError(asset_id)  # unreachable: just wrote it in this transaction
    return _asset_to_view(record)


# ------------------------------------------------------------------ purchase_orders


async def create_purchase_order(
    session: AsyncSession, req: PurchaseOrderCreateRequest
) -> PurchaseOrderView:
    vendor = await store.get_vendor(session, vendor_id=req.vendor_id)
    if vendor is None:
        raise VendorNotFoundError(req.vendor_id)
    if req.asset_id is not None:
        asset = await store.get_asset(session, asset_id=req.asset_id)
        if asset is None:
            raise AssetNotFoundError(req.asset_id)
    now = _now()
    record = await store.create_purchase_order(
        session,
        tenant_id=req.tenant_id,
        vendor_id=req.vendor_id,
        asset_id=req.asset_id,
        description=req.description,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        requested_by=req.requested_by,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="purchase_order",
        entity_id=record.po_id,
        action="requested",
        actor=req.requested_by,
        now=now,
    )
    await session.commit()
    return _po_to_view(record)


async def list_purchase_order_views(
    session: AsyncSession, *, status: str | None, limit: int
) -> list[PurchaseOrderView]:
    records = await store.list_purchase_orders(session, status=status, limit=limit)
    return [_po_to_view(r) for r in records]


async def decide_purchase_order(
    session: AsyncSession, *, po_id: str, decision: PurchaseOrderDecisionRequest
) -> PurchaseOrderView:
    existing = await store.get_purchase_order(session, po_id=po_id)
    if existing is None:
        raise PurchaseOrderNotFoundError(po_id)
    new_status = "approved" if decision.action == "approve" else "rejected"
    now = _now()
    decided = await store.try_decide_purchase_order(
        session, po_id=po_id, new_status=new_status, decided_by=decision.actor, now=now
    )
    if not decided:
        raise PurchaseOrderAlreadyDecidedError(po_id)
    await append_history(
        session,
        tenant_id=decision.tenant_id,
        entity_type="purchase_order",
        entity_id=po_id,
        action=new_status,
        actor=decision.actor,
        now=now,
        note=decision.note,
    )
    record = await store.get_purchase_order(session, po_id=po_id)
    await session.commit()
    if record is None:
        raise PurchaseOrderNotFoundError(po_id)  # unreachable: just wrote it in this transaction
    return _po_to_view(record)
