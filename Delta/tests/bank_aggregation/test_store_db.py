"""D-025 store-layer DB tests: real Postgres, real RLS, real constraints — never
stubbed."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from delta.bank_aggregation import store
from delta.persistence.database import get_privileged_session, get_tenant_session
from delta.personal_finance.schemas import AccountCreateRequest
from delta.personal_finance.service import create_account

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


@db_required
async def test_create_link_roundtrip(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        record = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()
    assert record.status == "linked"
    assert record.masked_account_last4 == "1234"


@db_required
async def test_create_link_against_already_linked_account_raises(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(store.AccountAlreadyLinkedError):
            await store.create_link(
                session,
                tenant_id=tenant_id,
                account_id=account_id,
                institution_name="Second Bank",
                masked_account_last4="5678",
                now=_now(),
            )


@db_required
async def test_masked_last4_check_constraint_rejects_full_account_number(tenant_id) -> None:
    """Bypasses the schema layer entirely by calling the store function directly with
    a too-long value -- the DB layer itself (the column's VARCHAR(4) width, backed by
    the CHECK regex too) rejects it, proving this is a structural guarantee, not just
    a Pydantic convention."""
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(DBAPIError):
            await store.create_link(
                session,
                tenant_id=tenant_id,
                account_id=account_id,
                institution_name="First Bank",
                masked_account_last4="12345678",  # bypasses the store's own str length only
                now=_now(),
            )


@db_required
async def test_active_link_partial_unique_index_enforced_at_db_layer(tenant_id) -> None:
    """Bypasses the app-layer advisory-lock check to prove the DB's own partial
    UNIQUE index (not just app-layer logic) is the real backstop against two
    simultaneously 'linked' rows for one account."""
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_privileged_session() as session:
        with pytest.raises(IntegrityError):
            await session.execute(
                text(
                    "INSERT INTO delta.linked_institutions "
                    "(link_id, tenant_id, account_id, institution_name, "
                    "masked_account_last4, status, consent_granted_at, created_at) "
                    "VALUES (gen_random_uuid()::text, :tenant_id, :account_id, "
                    "'Second Bank', '5678', 'linked', now(), now())"
                ),
                {"tenant_id": tenant_id, "account_id": account_id},
            )


@db_required
async def test_try_revoke_link_transitions_forward_only(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        record = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        revoked = await store.try_revoke_link(session, link_id=record.link_id, now=_now())
        await session.commit()
    assert revoked is True

    async with get_tenant_session(tenant_id) as session:
        second = await store.try_revoke_link(session, link_id=record.link_id, now=_now())
        await session.commit()
    assert second is False  # already revoked — no double transition


@db_required
async def test_revoked_link_frees_the_account_for_a_new_link(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        first = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.try_revoke_link(session, link_id=first.link_id, now=_now())
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        second = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="Second Bank",
            masked_account_last4="5678",
            now=_now(),
        )
        await session.commit()
    assert second.link_id != first.link_id
    assert second.status == "linked"


@db_required
async def test_ingested_reference_dedup_backstop(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    from delta.personal_finance.store import create_transaction

    async with get_tenant_session(tenant_id) as session:
        txn = await create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="groceries",
            amount_minor_units=-500,
            currency="USD",
            description="",
            merchant=None,
            occurred_at=_now(),
            now=_now(),
            source="aggregated",
        )
        assert (
            await store.is_reference_ingested(
                session, link_id=link.link_id, external_reference="bank-txn-1"
            )
            is False
        )
        await store.create_ingested_reference(
            session,
            tenant_id=tenant_id,
            link_id=link.link_id,
            external_reference="bank-txn-1",
            txn_id=txn.txn_id,
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        assert (
            await store.is_reference_ingested(
                session, link_id=link.link_id, external_reference="bank-txn-1"
            )
            is True
        )
        with pytest.raises(IntegrityError):
            await store.create_ingested_reference(
                session,
                tenant_id=tenant_id,
                link_id=link.link_id,
                external_reference="bank-txn-1",
                txn_id=txn.txn_id,
                now=_now(),
            )


@db_required
async def test_sync_run_roundtrip_and_list(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        link = await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        run = await store.create_sync_run(
            session,
            tenant_id=tenant_id,
            link_id=link.link_id,
            triggered_by="cron",
            started_at=_now(),
            completed_at=_now(),
            records_received=3,
            records_written=1,
            records_deduplicated=1,
            records_rejected=1,
            note=None,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        runs = await store.list_sync_runs(session, link_id=link.link_id)
    assert len(runs) == 1
    assert runs[0].sync_run_id == run.sync_run_id


@db_required
async def test_cross_tenant_links_isolated(tenant_id, other_tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_link(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_name="First Bank",
            masked_account_last4="1234",
            now=_now(),
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        links = await store.list_links(session)
    assert links == []


@db_required
async def test_aggregation_sync_runs_table_has_no_update_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' "
                    "AND table_name = 'aggregation_sync_runs' "
                    "AND grantee = 'delta_app'"
                )
            )
        ).all()
    assert {r[0] for r in rows} == {"SELECT", "INSERT"}


@db_required
async def test_aggregation_ingested_references_table_has_no_update_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' "
                    "AND table_name = 'aggregation_ingested_references' "
                    "AND grantee = 'delta_app'"
                )
            )
        ).all()
    assert {r[0] for r in rows} == {"SELECT", "INSERT"}


@db_required
async def test_linked_institutions_table_has_no_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' "
                    "AND table_name = 'linked_institutions' "
                    "AND grantee = 'delta_app'"
                )
            )
        ).all()
    assert {r[0] for r in rows} == {"SELECT", "INSERT", "UPDATE"}
