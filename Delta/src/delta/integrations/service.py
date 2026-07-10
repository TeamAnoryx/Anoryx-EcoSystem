"""Corporate ERP/procurement/cloud-cost sync orchestration (D-019, ADR-0019).

DTO <-> store mapping + the reconciliation-matching logic: each ingested line item is
matched against a D-014 purchase order or D-018 invoice by exact ID + amount/currency
comparison — a precise ID-based match, not fuzzy string/amount heuristics (ADR-0019
Fork 2). Mirrors ``invoicing.service``: store functions never commit, this layer
commits once per mutating call.

A sync run (the information-integrity event — what did the external system report,
and did it match Delta's own records) is wired into D-009's hash-chained audit log.
External-system registration is NOT audited, mirroring D-014's vendor creation
(directory/config metadata, not itself a financial or integrity event).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.audit_log import append_history
from . import store
from .schemas import (
    ExternalSystemCreateRequest,
    ExternalSystemView,
    SyncLineItemView,
    SyncRunCreateRequest,
    SyncRunView,
    SystemReconciliationView,
)


class SystemNotFoundError(LookupError):
    pass


class SystemDisabledError(RuntimeError):
    """A sync was attempted against a 'disabled' external system."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _system_to_view(record: store.ExternalSystemRecord) -> ExternalSystemView:
    return ExternalSystemView(
        system_id=record.system_id,
        tenant_id=record.tenant_id,
        name=record.name,
        system_type=record.system_type,  # type: ignore[arg-type]
        vendor_label=record.vendor_label,
        status=record.status,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _run_to_view(record: store.SyncRunRecord) -> SyncRunView:
    return SyncRunView(
        sync_run_id=record.sync_run_id,
        tenant_id=record.tenant_id,
        system_id=record.system_id,
        triggered_by=record.triggered_by,
        started_at=record.started_at,
        completed_at=record.completed_at,
        records_ingested=record.records_ingested,
        records_matched=record.records_matched,
        records_mismatched=record.records_mismatched,
        records_not_found=record.records_not_found,
        records_unreconciled=record.records_unreconciled,
        note=record.note,
    )


def _line_item_to_view(record: store.SyncLineItemRecord) -> SyncLineItemView:
    return SyncLineItemView(
        line_item_id=record.line_item_id,
        tenant_id=record.tenant_id,
        sync_run_id=record.sync_run_id,
        external_reference=record.external_reference,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,  # type: ignore[arg-type]
        matched_status=record.matched_status,  # type: ignore[arg-type]
        matched_entity_type=record.matched_entity_type,  # type: ignore[arg-type]
        matched_entity_id=record.matched_entity_id,
    )


# ------------------------------------------------------------------ external_systems


async def create_external_system(
    session: AsyncSession, req: ExternalSystemCreateRequest
) -> ExternalSystemView:
    now = _now()
    record = await store.create_external_system(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        system_type=req.system_type,
        vendor_label=req.vendor_label,
        now=now,
    )
    await session.commit()
    return _system_to_view(record)


async def list_external_system_views(
    session: AsyncSession, *, limit: int
) -> list[ExternalSystemView]:
    records = await store.list_external_systems(session, limit=limit)
    return [_system_to_view(r) for r in records]


# ------------------------------------------------------------------------ sync_runs


async def _match_line_item(session: AsyncSession, item) -> tuple[str, str | None, str | None]:
    """Returns (matched_status, matched_entity_type, matched_entity_id)."""
    if item.po_id is not None:
        target = await store.get_purchase_order_for_match(session, po_id=item.po_id)
        if target is None:
            return "not_found", None, None
        status = (
            "matched"
            if target.amount_minor_units == item.amount_minor_units
            and target.currency == item.currency
            else "amount_mismatch"
        )
        return status, "purchase_order", item.po_id
    if item.invoice_id is not None:
        target = await store.get_invoice_for_match(session, invoice_id=item.invoice_id)
        if target is None:
            return "not_found", None, None
        status = (
            "matched"
            if target.amount_minor_units == item.amount_minor_units
            and target.currency == item.currency
            else "amount_mismatch"
        )
        return status, "invoice", item.invoice_id
    return "unreconciled", None, None


async def run_sync(
    session: AsyncSession, *, system_id: str, req: SyncRunCreateRequest
) -> SyncRunView:
    system = await store.get_external_system(session, system_id=system_id)
    if system is None:
        raise SystemNotFoundError(system_id)
    if system.status != "active":
        raise SystemDisabledError(f"external_system {system_id} is '{system.status}', not 'active'")

    started_at = _now()
    counts = {"matched": 0, "amount_mismatch": 0, "not_found": 0, "unreconciled": 0}

    now = started_at
    matched_items: list[tuple] = []
    for item in req.line_items:
        matched_status, entity_type, entity_id = await _match_line_item(session, item)
        counts[matched_status] += 1
        matched_items.append((item, matched_status, entity_type, entity_id))

    completed_at = _now()
    run = await store.create_sync_run(
        session,
        tenant_id=req.tenant_id,
        system_id=system_id,
        triggered_by=req.triggered_by,
        started_at=started_at,
        completed_at=completed_at,
        records_matched=counts["matched"],
        records_mismatched=counts["amount_mismatch"],
        records_not_found=counts["not_found"],
        records_unreconciled=counts["unreconciled"],
        note=req.note,
    )
    for item, matched_status, entity_type, entity_id in matched_items:
        await store.create_sync_line_item(
            session,
            tenant_id=req.tenant_id,
            sync_run_id=run.sync_run_id,
            external_reference=item.external_reference,
            amount_minor_units=item.amount_minor_units,
            currency=item.currency,
            matched_status=matched_status,
            matched_entity_type=entity_type,
            matched_entity_id=entity_id,
            now=now,
        )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="sync_run",
        entity_id=run.sync_run_id,
        action="completed",
        actor=req.triggered_by,
        now=completed_at,
        note=(
            f"ingested={run.records_ingested} matched={run.records_matched} "
            f"mismatched={run.records_mismatched} not_found={run.records_not_found} "
            f"unreconciled={run.records_unreconciled}"
        ),
    )
    await session.commit()
    return _run_to_view(run)


async def list_sync_run_views(
    session: AsyncSession, *, system_id: str, limit: int
) -> list[SyncRunView]:
    records = await store.list_sync_runs(session, system_id=system_id, limit=limit)
    return [_run_to_view(r) for r in records]


async def list_sync_line_item_views(
    session: AsyncSession, *, sync_run_id: str, limit: int
) -> list[SyncLineItemView]:
    records = await store.list_sync_line_items(session, sync_run_id=sync_run_id, limit=limit)
    return [_line_item_to_view(r) for r in records]


# ------------------------------------------------------------------ reconciliation


async def get_system_reconciliation(
    session: AsyncSession, *, system_id: str
) -> SystemReconciliationView:
    system = await store.get_external_system(session, system_id=system_id)
    if system is None:
        raise SystemNotFoundError(system_id)
    row = await store.compute_system_reconciliation(session, system_id=system_id)
    return SystemReconciliationView(
        system_id=row.system_id,
        total_runs=row.total_runs,
        matched_count=row.matched_count,
        mismatched_count=row.mismatched_count,
        not_found_count=row.not_found_count,
        unreconciled_count=row.unreconciled_count,
        mismatched_amount_minor_units=row.mismatched_amount_minor_units,
    )
