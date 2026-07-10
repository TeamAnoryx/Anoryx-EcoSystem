"""Corporate ERP/procurement/cloud-cost sync persistence (D-019, ADR-0019).

Tenant-scoped reads/writes against ``external_systems``/``sync_runs``/
``sync_line_items`` (migration 0013). Every function takes an already-open
:class:`AsyncSession` (from ``delta.persistence.database.get_tenant_session``) and
does NOT commit — the caller (``service.py``) owns the transaction, exactly like
``erp.store``/``invoicing.store``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import (
    external_systems,
    invoices,
    purchase_orders,
    sync_line_items,
    sync_runs,
)

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class ExternalSystemRecord:
    system_id: str
    tenant_id: str
    name: str
    system_type: str
    vendor_label: str
    status: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SyncRunRecord:
    sync_run_id: str
    tenant_id: str
    system_id: str
    triggered_by: str
    started_at: datetime
    completed_at: datetime
    records_ingested: int
    records_matched: int
    records_mismatched: int
    records_not_found: int
    records_unreconciled: int
    note: str | None


@dataclass(frozen=True)
class SyncLineItemRecord:
    line_item_id: str
    tenant_id: str
    sync_run_id: str
    external_reference: str
    amount_minor_units: int
    currency: str
    matched_status: str
    matched_entity_type: str | None
    matched_entity_id: str | None


def _system_from_row(row) -> ExternalSystemRecord:
    return ExternalSystemRecord(
        system_id=row.system_id,
        tenant_id=row.tenant_id,
        name=row.name,
        system_type=row.system_type,
        vendor_label=row.vendor_label,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _run_from_row(row) -> SyncRunRecord:
    return SyncRunRecord(
        sync_run_id=row.sync_run_id,
        tenant_id=row.tenant_id,
        system_id=row.system_id,
        triggered_by=row.triggered_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        records_ingested=row.records_ingested,
        records_matched=row.records_matched,
        records_mismatched=row.records_mismatched,
        records_not_found=row.records_not_found,
        records_unreconciled=row.records_unreconciled,
        note=row.note,
    )


def _line_item_from_row(row) -> SyncLineItemRecord:
    return SyncLineItemRecord(
        line_item_id=row.line_item_id,
        tenant_id=row.tenant_id,
        sync_run_id=row.sync_run_id,
        external_reference=row.external_reference,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        matched_status=row.matched_status,
        matched_entity_type=row.matched_entity_type,
        matched_entity_id=row.matched_entity_id,
    )


# ------------------------------------------------------------------ external_systems


async def create_external_system(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    system_type: str,
    vendor_label: str,
    now: datetime,
    system_id: str | None = None,
) -> ExternalSystemRecord:
    sid = system_id or str(uuid.uuid4())
    await session.execute(
        insert(external_systems).values(
            system_id=sid,
            tenant_id=tenant_id,
            name=name,
            system_type=system_type,
            vendor_label=vendor_label,
            status="active",
            created_at=now,
            updated_at=now,
        )
    )
    return ExternalSystemRecord(
        system_id=sid,
        tenant_id=tenant_id,
        name=name,
        system_type=system_type,
        vendor_label=vendor_label,
        status="active",
        created_at=now,
        updated_at=now,
    )


async def get_external_system(
    session: AsyncSession, *, system_id: str
) -> ExternalSystemRecord | None:
    row = (
        await session.execute(
            select(external_systems).where(external_systems.c.system_id == system_id)
        )
    ).first()
    return None if row is None else _system_from_row(row)


async def list_external_systems(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[ExternalSystemRecord]:
    stmt = (
        select(external_systems)
        .order_by(external_systems.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_system_from_row(r) for r in rows]


# --------------------------------------------------------- reconciliation targets
# Reads the shared `purchase_orders`/`invoices` tables directly rather than
# importing `erp.store`/`invoicing.store` — mirrors D-018's `invoicing.store`
# precedent of querying another task's tables via `persistence.models` directly.


@dataclass(frozen=True)
class ReconciliationTarget:
    amount_minor_units: int
    currency: str


async def get_purchase_order_for_match(
    session: AsyncSession, *, po_id: str
) -> ReconciliationTarget | None:
    row = (
        await session.execute(
            select(purchase_orders.c.amount_minor_units, purchase_orders.c.currency).where(
                purchase_orders.c.po_id == po_id
            )
        )
    ).first()
    return None if row is None else ReconciliationTarget(row.amount_minor_units, row.currency)


async def get_invoice_for_match(
    session: AsyncSession, *, invoice_id: str
) -> ReconciliationTarget | None:
    row = (
        await session.execute(
            select(invoices.c.amount_minor_units, invoices.c.currency).where(
                invoices.c.invoice_id == invoice_id
            )
        )
    ).first()
    return None if row is None else ReconciliationTarget(row.amount_minor_units, row.currency)


# ------------------------------------------------------------------------ sync_runs


async def create_sync_run(
    session: AsyncSession,
    *,
    tenant_id: str,
    system_id: str,
    triggered_by: str,
    started_at: datetime,
    completed_at: datetime,
    records_matched: int,
    records_mismatched: int,
    records_not_found: int,
    records_unreconciled: int,
    note: str | None,
    sync_run_id: str | None = None,
) -> SyncRunRecord:
    rid = sync_run_id or str(uuid.uuid4())
    records_ingested = (
        records_matched + records_mismatched + records_not_found + records_unreconciled
    )
    await session.execute(
        insert(sync_runs).values(
            sync_run_id=rid,
            tenant_id=tenant_id,
            system_id=system_id,
            triggered_by=triggered_by,
            started_at=started_at,
            completed_at=completed_at,
            records_ingested=records_ingested,
            records_matched=records_matched,
            records_mismatched=records_mismatched,
            records_not_found=records_not_found,
            records_unreconciled=records_unreconciled,
            note=note,
        )
    )
    return SyncRunRecord(
        sync_run_id=rid,
        tenant_id=tenant_id,
        system_id=system_id,
        triggered_by=triggered_by,
        started_at=started_at,
        completed_at=completed_at,
        records_ingested=records_ingested,
        records_matched=records_matched,
        records_mismatched=records_mismatched,
        records_not_found=records_not_found,
        records_unreconciled=records_unreconciled,
        note=note,
    )


async def get_sync_run(session: AsyncSession, *, sync_run_id: str) -> SyncRunRecord | None:
    row = (
        await session.execute(select(sync_runs).where(sync_runs.c.sync_run_id == sync_run_id))
    ).first()
    return None if row is None else _run_from_row(row)


async def list_sync_runs(
    session: AsyncSession, *, system_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[SyncRunRecord]:
    stmt = (
        select(sync_runs)
        .where(sync_runs.c.system_id == system_id)
        .order_by(sync_runs.c.started_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_run_from_row(r) for r in rows]


# ------------------------------------------------------------------ sync_line_items


async def create_sync_line_item(
    session: AsyncSession,
    *,
    tenant_id: str,
    sync_run_id: str,
    external_reference: str,
    amount_minor_units: int,
    currency: str,
    matched_status: str,
    matched_entity_type: str | None,
    matched_entity_id: str | None,
    now: datetime,
    line_item_id: str | None = None,
) -> SyncLineItemRecord:
    lid = line_item_id or str(uuid.uuid4())
    await session.execute(
        insert(sync_line_items).values(
            line_item_id=lid,
            tenant_id=tenant_id,
            sync_run_id=sync_run_id,
            external_reference=external_reference,
            amount_minor_units=amount_minor_units,
            currency=currency,
            matched_status=matched_status,
            matched_entity_type=matched_entity_type,
            matched_entity_id=matched_entity_id,
            created_at=now,
        )
    )
    return SyncLineItemRecord(
        line_item_id=lid,
        tenant_id=tenant_id,
        sync_run_id=sync_run_id,
        external_reference=external_reference,
        amount_minor_units=amount_minor_units,
        currency=currency,
        matched_status=matched_status,
        matched_entity_type=matched_entity_type,
        matched_entity_id=matched_entity_id,
    )


async def list_sync_line_items(
    session: AsyncSession, *, sync_run_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[SyncLineItemRecord]:
    stmt = (
        select(sync_line_items)
        .where(sync_line_items.c.sync_run_id == sync_run_id)
        .order_by(sync_line_items.c.created_at.asc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_line_item_from_row(r) for r in rows]


# ------------------------------------------------------------------ reconciliation


@dataclass(frozen=True)
class SystemReconciliationRow:
    system_id: str
    total_runs: int
    matched_count: int
    mismatched_count: int
    not_found_count: int
    unreconciled_count: int
    mismatched_amount_minor_units: int


async def compute_system_reconciliation(
    session: AsyncSession, *, system_id: str
) -> SystemReconciliationRow:
    runs_stmt = select(func.count()).where(sync_runs.c.system_id == system_id)
    total_runs = (await session.execute(runs_stmt)).scalar_one()

    joined = sync_line_items.join(
        sync_runs, sync_line_items.c.sync_run_id == sync_runs.c.sync_run_id
    )
    counts_stmt = (
        select(
            sync_line_items.c.matched_status,
            func.count(),
            func.coalesce(func.sum(sync_line_items.c.amount_minor_units), 0),
        )
        .select_from(joined)
        .where(sync_runs.c.system_id == system_id)
        .group_by(sync_line_items.c.matched_status)
    )
    rows = (await session.execute(counts_stmt)).all()
    counts = {status: count for status, count, _amount in rows}
    mismatched_amount = next(
        (amount for status, _count, amount in rows if status == "amount_mismatch"), 0
    )
    return SystemReconciliationRow(
        system_id=system_id,
        total_runs=total_runs,
        matched_count=counts.get("matched", 0),
        mismatched_count=counts.get("amount_mismatch", 0),
        not_found_count=counts.get("not_found", 0),
        unreconciled_count=counts.get("unreconciled", 0),
        mismatched_amount_minor_units=mismatched_amount,
    )
