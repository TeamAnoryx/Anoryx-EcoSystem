"""Privacy-first multi-bank aggregation orchestration (D-025, ADR-0025).

``sync_link`` is the whole ingestion feature: a caller posts a normalized batch of
already-Plaid-shaped line items — this task builds and tests the RECEIVING half only
(ADR-0025 Sec 1/3: no live bank/OAuth connector exists anywhere in this codebase or
environment). For each item:

1. **Consent gate** — a sync against a 'revoked' link is rejected outright
   (:class:`LinkRevokedError`), never silently accepted.
2. **Dedup** — an item whose ``(link_id, external_reference)`` was already ingested
   by a prior sync is skipped (counted as deduplicated, never re-written). The
   composite PRIMARY KEY on ``aggregation_ingested_references`` is the structural
   backstop that makes a duplicate-insert race impossible, mirroring D-024's
   idempotency-key UNIQUE constraint.
3. **Currency mismatch** — an item whose currency does not match the linked
   account's own currency is REJECTED (counted, never converted — D-001's no-FX
   rule, mirrors D-024's identical ``currency_mismatch`` handling).
4. **Ingestion** — an item that passes both gates writes a REAL D-021
   ``personal_transactions`` row (``source='aggregated'``) — an aggregated
   transaction that D-021's budgets/health score could not see would be a dishonest
   ledger, exactly the reasoning ADR-0024 Fork 3 already established for execution
   rows.

Every sync run (the information-integrity event) AND every consent-lifecycle change
(link created/revoked) lands in D-009's hash-chained audit log — a privacy-first
feature's consent state IS a compliance-relevant event a caller must be able to
prove happened, not directory metadata (a deliberate divergence from D-019's own
"registration not audited" precedent, named explicitly in ADR-0025).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.audit_log import append_history
from ..personal_finance import store as personal_finance_store
from . import store
from .schemas import (
    LinkCreateRequest,
    LinkRevokeRequest,
    LinkView,
    SyncRunCreateRequest,
    SyncRunView,
)


class AccountNotFoundError(LookupError):
    pass


class LinkNotFoundError(LookupError):
    pass


class AccountAlreadyLinkedError(RuntimeError):
    """A link was requested for an account that already has an active link."""


class LinkAlreadyRevokedError(RuntimeError):
    """A revoke was attempted on a link that is already 'revoked'."""


class LinkRevokedError(RuntimeError):
    """A sync was attempted against a 'revoked' link."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _link_to_view(record: store.LinkRecord) -> LinkView:
    return LinkView(
        link_id=record.link_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        institution_name=record.institution_name,
        masked_account_last4=record.masked_account_last4,
        status=record.status,  # type: ignore[arg-type]
        consent_granted_at=record.consent_granted_at,
        consent_revoked_at=record.consent_revoked_at,
        created_at=record.created_at,
    )


def _run_to_view(record: store.SyncRunRecord) -> SyncRunView:
    return SyncRunView(
        sync_run_id=record.sync_run_id,
        tenant_id=record.tenant_id,
        link_id=record.link_id,
        triggered_by=record.triggered_by,
        started_at=record.started_at,
        completed_at=record.completed_at,
        records_received=record.records_received,
        records_written=record.records_written,
        records_deduplicated=record.records_deduplicated,
        records_rejected=record.records_rejected,
        note=record.note,
    )


async def create_link(session: AsyncSession, req: LinkCreateRequest) -> LinkView:
    account = await personal_finance_store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        raise AccountNotFoundError(req.account_id)

    now = _now()
    try:
        record = await store.create_link(
            session,
            tenant_id=req.tenant_id,
            account_id=req.account_id,
            institution_name=req.institution_name,
            masked_account_last4=req.masked_account_last4,
            now=now,
        )
    except store.AccountAlreadyLinkedError as exc:
        raise AccountAlreadyLinkedError(req.account_id) from exc

    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="linked_institution",
        entity_id=record.link_id,
        action="linked",
        actor=req.requested_by,
        now=now,
        note=req.institution_name,
    )
    await session.commit()
    return _link_to_view(record)


async def list_link_views(session: AsyncSession, *, limit: int) -> list[LinkView]:
    records = await store.list_links(session, limit=limit)
    return [_link_to_view(r) for r in records]


async def revoke_link(session: AsyncSession, *, link_id: str, req: LinkRevokeRequest) -> LinkView:
    existing = await store.get_link(session, link_id=link_id)
    if existing is None or existing.tenant_id != req.tenant_id:
        raise LinkNotFoundError(link_id)
    now = _now()
    revoked = await store.try_revoke_link(session, link_id=link_id, now=now)
    if not revoked:
        raise LinkAlreadyRevokedError(link_id)
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="linked_institution",
        entity_id=link_id,
        action="revoked",
        actor=req.requested_by,
        now=now,
    )
    record = await store.get_link(session, link_id=link_id)
    await session.commit()
    if record is None:
        raise LinkNotFoundError(link_id)  # unreachable: just wrote it
    return _link_to_view(record)


async def sync_link(
    session: AsyncSession, *, link_id: str, req: SyncRunCreateRequest
) -> SyncRunView:
    link = await store.get_link(session, link_id=link_id)
    if link is None or link.tenant_id != req.tenant_id:
        raise LinkNotFoundError(link_id)
    if link.status != "linked":
        raise LinkRevokedError(f"linked_institution {link_id} is '{link.status}', not 'linked'")

    account = await personal_finance_store.get_account(session, account_id=link.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        # Unreachable under normal operation: the composite FK guarantees the linked
        # account exists for this tenant. Guarded explicitly anyway, mirroring every
        # other Delta package's "never trust a bare FK silently" discipline.
        raise AccountNotFoundError(link.account_id)

    started_at = _now()
    written = 0
    deduplicated = 0
    rejected = 0

    for item in req.line_items:
        if await store.is_reference_ingested(
            session, link_id=link_id, external_reference=item.external_reference
        ):
            deduplicated += 1
            continue
        if item.currency != account.currency:
            rejected += 1
            continue

        now = _now()
        txn = await personal_finance_store.create_transaction(
            session,
            tenant_id=req.tenant_id,
            account_id=link.account_id,
            category=item.category,
            amount_minor_units=item.amount_minor_units,
            currency=item.currency,
            description=item.description,
            merchant=item.merchant,
            occurred_at=item.occurred_at,
            now=now,
            source="aggregated",
        )
        await store.create_ingested_reference(
            session,
            tenant_id=req.tenant_id,
            link_id=link_id,
            external_reference=item.external_reference,
            txn_id=txn.txn_id,
            now=now,
        )
        written += 1

    completed_at = _now()
    run = await store.create_sync_run(
        session,
        tenant_id=req.tenant_id,
        link_id=link_id,
        triggered_by=req.triggered_by,
        started_at=started_at,
        completed_at=completed_at,
        records_received=len(req.line_items),
        records_written=written,
        records_deduplicated=deduplicated,
        records_rejected=rejected,
        note=req.note,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="aggregation_sync_run",
        entity_id=run.sync_run_id,
        action="completed",
        actor=req.triggered_by,
        now=completed_at,
        note=(
            f"received={run.records_received} written={run.records_written} "
            f"deduplicated={run.records_deduplicated} rejected={run.records_rejected}"
        ),
    )
    await session.commit()
    return _run_to_view(run)


async def list_sync_run_views(
    session: AsyncSession, *, link_id: str, limit: int
) -> list[SyncRunView]:
    records = await store.list_sync_runs(session, link_id=link_id, limit=limit)
    return [_run_to_view(r) for r in records]
