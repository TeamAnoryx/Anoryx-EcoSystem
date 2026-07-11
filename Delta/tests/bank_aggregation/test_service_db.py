"""D-025 service-layer DB tests: consent lifecycle, sync ingestion (dedup/currency-
mismatch/write), cross-tenant isolation, and the D-009 audit-chain rows — all
against a real Postgres (real RLS, real constraints), never stubbed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from delta.bank_aggregation.schemas import (
    LinkCreateRequest,
    LinkRevokeRequest,
    SyncLineItemInput,
    SyncRunCreateRequest,
)
from delta.bank_aggregation.service import (
    AccountAlreadyLinkedError,
    AccountNotFoundError,
    LinkAlreadyRevokedError,
    LinkNotFoundError,
    LinkRevokedError,
    create_link,
    list_link_views,
    list_sync_run_views,
    revoke_link,
    sync_link,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_tenant_session
from delta.personal_finance.schemas import AccountCreateRequest
from delta.personal_finance.service import create_account
from delta.personal_finance.store import list_transactions

from .conftest import db_required


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _make_account(tenant_id: str, *, currency: str = "USD") -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await create_account(
            session,
            AccountCreateRequest(
                tenant_id=tenant_id, type="checking", currency=currency, name="Main"
            ),
            now=_now(),
        )
    return account.account_id


def _link_request(tenant_id: str, account_id: str, **overrides) -> LinkCreateRequest:
    payload = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "institution_name": "First Bank",
        "masked_account_last4": "1234",
        "consent_confirmed": True,
        "requested_by": "Jane",
    }
    payload.update(overrides)
    return LinkCreateRequest(**payload)


def _sync_request(tenant_id: str, items: list[dict], **overrides) -> SyncRunCreateRequest:
    payload = {
        "tenant_id": tenant_id,
        "triggered_by": "cron",
        "line_items": [SyncLineItemInput(**i) for i in items],
    }
    payload.update(overrides)
    return SyncRunCreateRequest(**payload)


def _item(**overrides) -> dict:
    payload = {
        "external_reference": "bank-txn-1",
        "category": "groceries",
        "amount_minor_units": -500,
        "currency": "USD",
        "occurred_at": _now(),
    }
    payload.update(overrides)
    return payload


@db_required
async def test_create_link_returns_view(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await create_link(session, _link_request(tenant_id, account_id))
    assert view.status == "linked"
    assert view.consent_revoked_at is None


@db_required
async def test_create_link_unknown_account_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await create_link(
                session,
                _link_request(tenant_id, "99999999-9999-4999-8999-999999999999"),
            )


@db_required
async def test_create_link_cross_tenant_account_raises(tenant_id, other_tenant_id) -> None:
    victim_account = await _make_account(other_tenant_id)
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await create_link(session, _link_request(tenant_id, victim_account))


@db_required
async def test_create_link_against_already_linked_account_raises(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountAlreadyLinkedError):
            await create_link(session, _link_request(tenant_id, account_id))


@db_required
async def test_create_link_lands_in_d009_audit_chain(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        rows = await list_history(session, entity_type="linked_institution", entity_id=view.link_id)
    assert {r.action for r in rows} == {"linked"}


@db_required
async def test_revoke_link_transitions_status(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        revoked = await revoke_link(
            session,
            link_id=view.link_id,
            req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
        )
    assert revoked.status == "revoked"
    assert revoked.consent_revoked_at is not None


@db_required
async def test_revoke_already_revoked_link_raises(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        await revoke_link(
            session,
            link_id=view.link_id,
            req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
        )
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(LinkAlreadyRevokedError):
            await revoke_link(
                session,
                link_id=view.link_id,
                req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
            )


@db_required
async def test_revoke_unknown_link_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(LinkNotFoundError):
            await revoke_link(
                session,
                link_id="99999999-9999-4999-8999-999999999999",
                req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
            )


@db_required
async def test_revoke_link_lands_in_d009_audit_chain(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        await revoke_link(
            session,
            link_id=view.link_id,
            req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
        )
    async with get_tenant_session(tenant_id) as session:
        rows = await list_history(session, entity_type="linked_institution", entity_id=view.link_id)
    assert {r.action for r in rows} == {"linked", "revoked"}


@db_required
async def test_sync_writes_ledger_row_visible_to_d021(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(tenant_id) as session:
        run = await sync_link(
            session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()])
        )
    assert run.records_received == 1
    assert run.records_written == 1
    assert run.records_deduplicated == 0
    assert run.records_rejected == 0

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 1
    assert txns[0].amount_minor_units == -500
    assert txns[0].source == "aggregated"


@db_required
async def test_sync_dedups_repeated_external_reference(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(tenant_id) as session:
        await sync_link(session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()]))

    # A retried sync with the SAME external_reference must not double-write.
    async with get_tenant_session(tenant_id) as session:
        second = await sync_link(
            session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()])
        )
    assert second.records_written == 0
    assert second.records_deduplicated == 1

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 1


@db_required
async def test_sync_currency_mismatch_is_rejected_not_written(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(tenant_id) as session:
        run = await sync_link(
            session,
            link_id=link.link_id,
            req=_sync_request(tenant_id, [_item(currency="EUR")]),
        )
    assert run.records_written == 0
    assert run.records_rejected == 1

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert txns == []


@db_required
async def test_sync_against_revoked_link_raises(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        await revoke_link(
            session,
            link_id=link.link_id,
            req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
        )
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(LinkRevokedError):
            await sync_link(session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()]))


@db_required
async def test_sync_unknown_link_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(LinkNotFoundError):
            await sync_link(
                session,
                link_id="99999999-9999-4999-8999-999999999999",
                req=_sync_request(tenant_id, [_item()]),
            )


@db_required
async def test_sync_mixed_batch_counts_are_consistent(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(tenant_id) as session:
        await sync_link(
            session,
            link_id=link.link_id,
            req=_sync_request(tenant_id, [_item(external_reference="dup-1")]),
        )

    items = [
        _item(external_reference="dup-1"),  # deduplicated
        _item(external_reference="new-1", currency="EUR"),  # rejected (currency)
        _item(external_reference="new-2", category="income", amount_minor_units=200000),  # written
    ]
    async with get_tenant_session(tenant_id) as session:
        run = await sync_link(session, link_id=link.link_id, req=_sync_request(tenant_id, items))
    assert run.records_received == 3
    assert run.records_written == 1
    assert run.records_deduplicated == 1
    assert run.records_rejected == 1


@db_required
async def test_sync_lands_in_d009_audit_chain(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        run = await sync_link(
            session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()])
        )
    async with get_tenant_session(tenant_id) as session:
        rows = await list_history(
            session, entity_type="aggregation_sync_run", entity_id=run.sync_run_id
        )
    assert {r.action for r in rows} == {"completed"}


@db_required
async def test_concurrent_revoke_and_sync_never_ingest_after_revocation(tenant_id) -> None:
    """Regression test for the independent security-auditor's Medium finding: a
    sync in flight must not keep writing ledger rows after a concurrent revoke has
    already committed. `store.acquire_link_lock` (ADR-0025) serializes revoke_link
    and sync_link on the same link -- whichever commits first wins the race, and
    the loser either raises LinkRevokedError (0 rows written) or completes fully
    BEFORE the revoke proceeds (exactly 1 row written). Never a partial/mixed
    outcome. Repeated across several fresh links to make the race likely to
    actually interleave under real concurrency."""
    for i in range(10):
        account_id = await _make_account(tenant_id)
        async with get_tenant_session(tenant_id) as session:
            link = await create_link(session, _link_request(tenant_id, account_id))

        async def _sync(link_id: str = link.link_id, race_ref: str = f"race-{i}"):
            async with get_tenant_session(tenant_id) as session:
                try:
                    return await sync_link(
                        session,
                        link_id=link_id,
                        req=_sync_request(tenant_id, [_item(external_reference=race_ref)]),
                    )
                except LinkRevokedError:
                    return None

        async def _revoke(link_id: str = link.link_id):
            async with get_tenant_session(tenant_id) as session:
                return await revoke_link(
                    session,
                    link_id=link_id,
                    req=LinkRevokeRequest(tenant_id=tenant_id, requested_by="Jane"),
                )

        sync_result, revoke_result = await asyncio.gather(_sync(), _revoke())

        assert revoke_result.status == "revoked"  # revoke always eventually succeeds
        async with get_tenant_session(tenant_id) as session:
            txns = await list_transactions(session, account_id=account_id, limit=10)
        if sync_result is None:
            assert txns == []  # revoke won: sync must not have written anything
        else:
            assert len(txns) == 1  # sync won: it fully completed before the revoke
            assert txns[0].source == "aggregated"


@db_required
async def test_cross_tenant_link_list_isolated(tenant_id, other_tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(other_tenant_id) as session:
        views = await list_link_views(session, limit=10)
    assert views == []


@db_required
async def test_cross_tenant_sync_against_other_tenants_link_is_404(
    tenant_id, other_tenant_id
) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))

    async with get_tenant_session(other_tenant_id) as session:
        with pytest.raises(LinkNotFoundError):
            await sync_link(
                session, link_id=link.link_id, req=_sync_request(other_tenant_id, [_item()])
            )


@db_required
async def test_list_sync_run_views(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await create_link(session, _link_request(tenant_id, account_id))
    async with get_tenant_session(tenant_id) as session:
        await sync_link(session, link_id=link.link_id, req=_sync_request(tenant_id, [_item()]))
    async with get_tenant_session(tenant_id) as session:
        runs = await list_sync_run_views(session, link_id=link.link_id, limit=10)
    assert len(runs) == 1
