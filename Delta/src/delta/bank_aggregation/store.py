"""Bank-aggregation persistence (D-025, ADR-0025).

Tenant-scoped reads/writes against ``linked_institutions``/``aggregation_sync_runs``/
``aggregation_ingested_references`` (migration 0018). Every function takes an
already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like every prior Delta store module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import (
    aggregation_ingested_references,
    aggregation_sync_runs,
    linked_institutions,
)

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


class AccountAlreadyLinkedError(RuntimeError):
    """Raised when an account already has an active ('linked') linked_institution row."""


@dataclass(frozen=True)
class LinkRecord:
    link_id: str
    tenant_id: str
    account_id: str
    institution_name: str
    masked_account_last4: str
    status: str
    consent_granted_at: datetime
    consent_revoked_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class SyncRunRecord:
    sync_run_id: str
    tenant_id: str
    link_id: str
    triggered_by: str
    started_at: datetime
    completed_at: datetime
    records_received: int
    records_written: int
    records_deduplicated: int
    records_rejected: int
    note: str | None


def _link_from_row(row) -> LinkRecord:
    return LinkRecord(
        link_id=row.link_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        institution_name=row.institution_name,
        masked_account_last4=row.masked_account_last4,
        status=row.status,
        consent_granted_at=row.consent_granted_at,
        consent_revoked_at=row.consent_revoked_at,
        created_at=row.created_at,
    )


def _run_from_row(row) -> SyncRunRecord:
    return SyncRunRecord(
        sync_run_id=row.sync_run_id,
        tenant_id=row.tenant_id,
        link_id=row.link_id,
        triggered_by=row.triggered_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        records_received=row.records_received,
        records_written=row.records_written,
        records_deduplicated=row.records_deduplicated,
        records_rejected=row.records_rejected,
        note=row.note,
    )


async def acquire_account_link_lock(session: AsyncSession, *, account_id: str) -> None:
    """Transaction-scoped advisory lock serializing the active-link check -> insert
    critical section for ONE account (auto-released at commit/rollback) — same
    ``pg_advisory_xact_lock(hashtext(...))`` shape D-024's execution engine uses,
    closing the identical TOCTOU race class for account-scoped mutual exclusion: two
    concurrent link-creation requests for the same account must not both pass the
    "no active link exists" check and both insert."""
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:a))"), {"a": account_id})


async def get_active_link_for_account(
    session: AsyncSession, *, account_id: str
) -> LinkRecord | None:
    row = (
        await session.execute(
            select(linked_institutions).where(
                linked_institutions.c.account_id == account_id,
                linked_institutions.c.status == "linked",
            )
        )
    ).first()
    return None if row is None else _link_from_row(row)


async def create_link(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    institution_name: str,
    masked_account_last4: str,
    now: datetime,
) -> LinkRecord:
    await acquire_account_link_lock(session, account_id=account_id)
    if await get_active_link_for_account(session, account_id=account_id) is not None:
        raise AccountAlreadyLinkedError(account_id)

    link_id = str(uuid.uuid4())
    await session.execute(
        insert(linked_institutions).values(
            link_id=link_id,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name=institution_name,
            masked_account_last4=masked_account_last4,
            status="linked",
            consent_granted_at=now,
            consent_revoked_at=None,
            created_at=now,
        )
    )
    return LinkRecord(
        link_id=link_id,
        tenant_id=tenant_id,
        account_id=account_id,
        institution_name=institution_name,
        masked_account_last4=masked_account_last4,
        status="linked",
        consent_granted_at=now,
        consent_revoked_at=None,
        created_at=now,
    )


async def list_links(session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT) -> list[LinkRecord]:
    stmt = (
        select(linked_institutions)
        .order_by(linked_institutions.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_link_from_row(r) for r in rows]


async def get_link(session: AsyncSession, *, link_id: str) -> LinkRecord | None:
    row = (
        await session.execute(
            select(linked_institutions).where(linked_institutions.c.link_id == link_id)
        )
    ).first()
    return None if row is None else _link_from_row(row)


async def try_revoke_link(session: AsyncSession, *, link_id: str, now: datetime) -> bool:
    """Conditionally transition 'linked' -> 'revoked'. Does NOT commit.

    Same conditional-UPDATE shape as D-022's ``try_cancel_subscription`` / D-014's
    ``try_transition_asset_status``: the WHERE clause only matches a row currently
    'linked', guarding a concurrent double-revoke. Returns True iff this call
    performed the transition."""
    result = await session.execute(
        update(linked_institutions)
        .where(linked_institutions.c.link_id == link_id)
        .where(linked_institutions.c.status == "linked")
        .values(status="revoked", consent_revoked_at=now)
    )
    return result.rowcount == 1


async def is_reference_ingested(
    session: AsyncSession, *, link_id: str, external_reference: str
) -> bool:
    row = (
        await session.execute(
            select(aggregation_ingested_references.c.link_id).where(
                aggregation_ingested_references.c.link_id == link_id,
                aggregation_ingested_references.c.external_reference == external_reference,
            )
        )
    ).first()
    return row is not None


async def create_ingested_reference(
    session: AsyncSession,
    *,
    tenant_id: str,
    link_id: str,
    external_reference: str,
    txn_id: str,
    now: datetime,
) -> None:
    await session.execute(
        insert(aggregation_ingested_references).values(
            link_id=link_id,
            external_reference=external_reference,
            tenant_id=tenant_id,
            txn_id=txn_id,
            ingested_at=now,
        )
    )


async def create_sync_run(
    session: AsyncSession,
    *,
    tenant_id: str,
    link_id: str,
    triggered_by: str,
    started_at: datetime,
    completed_at: datetime,
    records_received: int,
    records_written: int,
    records_deduplicated: int,
    records_rejected: int,
    note: str | None,
) -> SyncRunRecord:
    sync_run_id = str(uuid.uuid4())
    await session.execute(
        insert(aggregation_sync_runs).values(
            sync_run_id=sync_run_id,
            tenant_id=tenant_id,
            link_id=link_id,
            triggered_by=triggered_by,
            started_at=started_at,
            completed_at=completed_at,
            records_received=records_received,
            records_written=records_written,
            records_deduplicated=records_deduplicated,
            records_rejected=records_rejected,
            note=note,
        )
    )
    return SyncRunRecord(
        sync_run_id=sync_run_id,
        tenant_id=tenant_id,
        link_id=link_id,
        triggered_by=triggered_by,
        started_at=started_at,
        completed_at=completed_at,
        records_received=records_received,
        records_written=records_written,
        records_deduplicated=records_deduplicated,
        records_rejected=records_rejected,
        note=note,
    )


async def list_sync_runs(
    session: AsyncSession, *, link_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[SyncRunRecord]:
    stmt = (
        select(aggregation_sync_runs)
        .where(aggregation_sync_runs.c.link_id == link_id)
        .order_by(aggregation_sync_runs.c.started_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_run_from_row(r) for r in rows]
