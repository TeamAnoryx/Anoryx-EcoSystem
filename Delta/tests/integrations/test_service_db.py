"""D-019 service-layer DB tests: the reconciliation-matching logic (matched/
amount_mismatch/not_found/unreconciled), exception mapping, and the D-009 audit-chain
wiring on sync-run completion.

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as
``tests/invoicing/test_service_db.py``).
"""

from __future__ import annotations

import uuid

import pytest

from delta.integrations.schemas import ExternalSystemCreateRequest, SyncRunCreateRequest
from delta.integrations.service import (
    SystemDisabledError,
    SystemNotFoundError,
    create_external_system,
    get_system_reconciliation,
    list_sync_line_item_views,
    run_sync,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_tenant_session

from .conftest import db_required, seed_approved_invoice, seed_approved_po


async def _create_system(tenant_id, system_type="corporate_erp", vendor_label="NetSuite"):
    async with get_tenant_session(tenant_id) as session:
        system = await create_external_system(
            session,
            ExternalSystemCreateRequest(
                tenant_id=tenant_id,
                name="Corp System",
                system_type=system_type,
                vendor_label=vendor_label,
            ),
        )
    return system


@db_required
async def test_run_sync_against_missing_system_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SystemNotFoundError):
            await run_sync(
                session,
                system_id=str(uuid.uuid4()),
                req=SyncRunCreateRequest(
                    tenant_id=tenant_id,
                    triggered_by="ops@example.com",
                    line_items=[
                        {"external_reference": "X", "amount_minor_units": 100, "currency": "USD"}
                    ],
                ),
            )


@db_required
async def test_run_sync_matches_po_with_exact_amount(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=50_000, currency="USD"
        )
    system = await _create_system(tenant_id, system_type="corporate_erp")

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "NETSUITE-PO-1",
                        "amount_minor_units": 50_000,
                        "currency": "USD",
                        "po_id": po_id,
                    }
                ],
            ),
        )
    assert run.records_matched == 1
    assert run.records_mismatched == 0
    assert run.records_ingested == 1

    async with get_tenant_session(tenant_id) as session:
        items = await list_sync_line_item_views(session, sync_run_id=run.sync_run_id, limit=10)
    assert items[0].matched_status == "matched"
    assert items[0].matched_entity_type == "purchase_order"
    assert items[0].matched_entity_id == po_id


@db_required
async def test_run_sync_flags_amount_mismatch(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=50_000, currency="USD"
        )
    system = await _create_system(tenant_id, system_type="corporate_erp")

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "NETSUITE-PO-1",
                        "amount_minor_units": 49_999,
                        "currency": "USD",
                        "po_id": po_id,
                    }
                ],
            ),
        )
    assert run.records_mismatched == 1
    assert run.records_matched == 0


@db_required
async def test_run_sync_flags_not_found_for_bogus_po(tenant_id) -> None:
    system = await _create_system(tenant_id, system_type="corporate_erp")

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "NETSUITE-PO-GHOST",
                        "amount_minor_units": 100,
                        "currency": "USD",
                        "po_id": str(uuid.uuid4()),
                    }
                ],
            ),
        )
    assert run.records_not_found == 1


@db_required
async def test_run_sync_matches_invoice(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)
    invoice_id = await seed_approved_invoice(
        tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount_minor_units=25_000
    )
    system = await _create_system(tenant_id, system_type="corporate_erp")

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "NETSUITE-INV-1",
                        "amount_minor_units": 25_000,
                        "currency": "USD",
                        "invoice_id": invoice_id,
                    }
                ],
            ),
        )
    assert run.records_matched == 1


@db_required
async def test_run_sync_cloud_cost_line_item_is_unreconciled_by_default(tenant_id) -> None:
    system = await _create_system(tenant_id, system_type="cloud_cost", vendor_label="AWS")

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "EC2-INSTANCE-1",
                        "amount_minor_units": 500,
                        "currency": "USD",
                    }
                ],
            ),
        )
    assert run.records_unreconciled == 1
    assert run.records_matched == 0


@db_required
async def test_run_sync_against_disabled_system_raises(tenant_id) -> None:
    from sqlalchemy import update

    from delta.persistence.database import get_privileged_session
    from delta.persistence.models import external_systems as est

    system = await _create_system(tenant_id)

    # Directly flip status via a privileged (BYPASSRLS) session to simulate a
    # disabled system — there is no service-level "disable" action in this bounded
    # slice yet, and (correctly) `delta_app` has no UPDATE grant on this table at
    # all (ADR-0019 Fork 3 — every row in this feature is written once and never
    # revised), so the ordinary tenant-scoped session cannot perform this update.
    async with get_privileged_session() as session:
        await session.execute(
            update(est).where(est.c.system_id == system.system_id).values(status="disabled")
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SystemDisabledError):
            await run_sync(
                session,
                system_id=system.system_id,
                req=SyncRunCreateRequest(
                    tenant_id=tenant_id,
                    triggered_by="ops@example.com",
                    line_items=[
                        {"external_reference": "X", "amount_minor_units": 100, "currency": "USD"}
                    ],
                ),
            )


@db_required
async def test_run_sync_is_audited(tenant_id) -> None:
    system = await _create_system(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {"external_reference": "X", "amount_minor_units": 100, "currency": "USD"}
                ],
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        history = await list_history(session, entity_type="sync_run", entity_id=run.sync_run_id)
    assert len(history) == 1
    assert history[0].action == "completed"


@db_required
async def test_reconciliation_against_missing_system_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SystemNotFoundError):
            await get_system_reconciliation(session, system_id=str(uuid.uuid4()))


@db_required
async def test_reconciliation_reflects_multiple_line_item_outcomes(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=50_000, currency="USD"
        )
    system = await _create_system(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "MATCHED",
                        "amount_minor_units": 50_000,
                        "currency": "USD",
                        "po_id": po_id,
                    },
                    {
                        "external_reference": "NO-REF",
                        "amount_minor_units": 10,
                        "currency": "USD",
                    },
                    {
                        "external_reference": "GHOST",
                        "amount_minor_units": 10,
                        "currency": "USD",
                        "po_id": str(uuid.uuid4()),
                    },
                ],
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_system_reconciliation(session, system_id=system.system_id)
    assert report.total_runs == 1
    assert report.matched_count == 1
    assert report.not_found_count == 1
    assert report.unreconciled_count == 1
    assert report.mismatched_count == 0


@db_required
async def test_run_sync_cannot_match_a_different_tenants_po(tenant_id, other_tenant_id) -> None:
    """A sync line item referencing another tenant's PO must resolve 'not_found', not
    'matched' — the lookup runs inside THIS tenant's RLS session, so a foreign-tenant
    PO is structurally invisible (mirrors D-018's own cross-tenant milestone-task
    check)."""
    async with get_tenant_session(other_tenant_id) as session:
        _vendor_id, foreign_po_id = await seed_approved_po(
            session, tenant_id=other_tenant_id, amount_minor_units=50_000, currency="USD"
        )
    system = await _create_system(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        run = await run_sync(
            session,
            system_id=system.system_id,
            req=SyncRunCreateRequest(
                tenant_id=tenant_id,
                triggered_by="ops@example.com",
                line_items=[
                    {
                        "external_reference": "CROSS-TENANT-PO",
                        "amount_minor_units": 50_000,
                        "currency": "USD",
                        "po_id": foreign_po_id,
                    }
                ],
            ),
        )
    assert run.records_not_found == 1
    assert run.records_matched == 0
