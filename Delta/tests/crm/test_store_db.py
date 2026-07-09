"""D-013 non-stubbed CRM persistence suite: real store writes -> real SQL reads/
aggregates, real RLS. Mirrors ``tests/dashboards/test_store_db.py``'s shape."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from delta.crm import store
from delta.persistence.database import get_tenant_session

from .conftest import db_required

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


@db_required
async def test_deal_value_without_currency_rejected_by_db_check(tenant_id) -> None:
    # Security-review finding (ADR-0013 §4): the value/currency pairing is enforced
    # by a DB CHECK constraint as an independent second layer, not just app logic —
    # this bypasses delta.crm.service (which defaults the currency) to prove the
    # database itself refuses the mismatched row.
    async with get_tenant_session(tenant_id) as session:
        client = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        # asyncpg evaluates CHECK constraints immediately at INSERT, not deferred to
        # COMMIT — the exception surfaces from the INSERT itself.
        with pytest.raises(IntegrityError):
            await store.create_deal(
                session,
                tenant_id=tenant_id,
                client_id=client.client_id,
                name="Mismatched Deal",
                value_minor_units=5_000_00,
                currency=None,
                expected_close_date=None,
                now=_NOW,
            )


@db_required
async def test_create_and_get_client_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme Corp",
            primary_contact_name="Jane Doe",
            primary_contact_email="jane@acme.example",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_client(session, client_id=created.client_id)

    assert fetched is not None
    assert fetched.name == "Acme Corp"
    assert fetched.primary_contact_email == "jane@acme.example"


@db_required
async def test_list_clients_ordered_newest_first(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_client(
            session,
            tenant_id=tenant_id,
            name="First",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Second",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW + timedelta(minutes=1),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_clients(session)

    assert [r.name for r in rows] == ["Second", "First"]


@db_required
async def test_deal_stage_transition_succeeds_once_then_blocked_when_terminal(
    tenant_id,
) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        deal = await store.create_deal(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            name="Big Deal",
            value_minor_units=50_000_00,
            currency="USD",
            expected_close_date=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        moved = await store.try_transition_deal_stage(
            session, deal_id=deal.deal_id, new_stage="won", now=_NOW
        )
        await session.commit()
    assert moved is True

    # A second transition attempt on an already-terminal deal affects zero rows.
    async with get_tenant_session(tenant_id) as session:
        moved_again = await store.try_transition_deal_stage(
            session, deal_id=deal.deal_id, new_stage="lost", now=_NOW
        )
        await session.commit()
    assert moved_again is False

    async with get_tenant_session(tenant_id) as session:
        final = await store.get_deal(session, deal_id=deal.deal_id)
    assert final is not None
    assert final.stage == "won"
    assert final.closed_at is not None


@db_required
async def test_stakeholder_engagement_computed_via_interaction_join(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        stakeholder = await store.create_stakeholder(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            name="Bob Smith",
            role="decision_maker",
            email=None,
            now=_NOW,
        )
        other_stakeholder = await store.create_stakeholder(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            name="No Engagement",
            role="unknown",
            email=None,
            now=_NOW,
        )
        await store.create_interaction(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            stakeholder_id=stakeholder.stakeholder_id,
            interaction_type="call",
            occurred_at=_NOW - timedelta(days=5),
            summary="First call",
            created_by="Jane",
            now=_NOW,
        )
        await store.create_interaction(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            stakeholder_id=stakeholder.stakeholder_id,
            interaction_type="email",
            occurred_at=_NOW - timedelta(days=1),
            summary="Follow-up email",
            created_by="Jane",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_stakeholders_for_client(session, client_id=client.client_id)

    by_id = {r.stakeholder_id: r for r in rows}
    assert by_id[stakeholder.stakeholder_id].interaction_count == 2
    assert by_id[stakeholder.stakeholder_id].last_interaction_at == _NOW - timedelta(days=1)
    assert by_id[other_stakeholder.stakeholder_id].interaction_count == 0
    assert by_id[other_stakeholder.stakeholder_id].last_interaction_at is None


@db_required
async def test_engagement_summary_counts_within_90_day_window_only(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        await store.create_interaction(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            stakeholder_id=None,
            interaction_type="note",
            occurred_at=_NOW - timedelta(days=10),
            summary="Within window",
            created_by="Jane",
            now=_NOW,
        )
        await store.create_interaction(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            deal_id=None,
            stakeholder_id=None,
            interaction_type="note",
            occurred_at=_NOW - timedelta(days=200),
            summary="Outside window",
            created_by="Jane",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        summary = await store.get_client_engagement_summary(
            session, client_id=client.client_id, now=_NOW
        )

    assert summary.interaction_count_90d == 1
    assert summary.last_interaction_at == _NOW - timedelta(days=10)


@db_required
async def test_engagement_summary_open_deal_count_excludes_terminal_stages(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        open_deal = await store.create_deal(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            name="Open Deal",
            value_minor_units=None,
            currency=None,
            expected_close_date=None,
            now=_NOW,
        )
        closed_deal = await store.create_deal(
            session,
            tenant_id=tenant_id,
            client_id=client.client_id,
            name="Closed Deal",
            value_minor_units=None,
            currency=None,
            expected_close_date=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.try_transition_deal_stage(
            session, deal_id=closed_deal.deal_id, new_stage="won", now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        summary = await store.get_client_engagement_summary(
            session, client_id=client.client_id, now=_NOW
        )

    assert summary.open_deal_count == 1
    assert open_deal.stage == "lead"


@db_required
async def test_cross_tenant_isolation_clients_invisible_to_other_tenant(
    tenant_id, other_tenant_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_client(
            session,
            tenant_id=tenant_id,
            name="Acme",
            primary_contact_name=None,
            primary_contact_email=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_client(session, client_id=created.client_id)
        listed = await store.list_clients(session)

    assert fetched is None
    assert listed == []
