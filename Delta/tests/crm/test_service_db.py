"""D-013 service-layer DB tests: exception mapping + cross-entity scope checks that
live above the store layer (delta.crm.service).

Each mutating service call commits (mirrors D-007's ``allocation_admin.service``) —
``get_tenant_session``'s tenant GUC is transaction-local and clears at commit, so a
new ``get_tenant_session`` block is opened per commit, never reused across two writes
(the same discipline ``test_store_db.py`` follows).
"""

from __future__ import annotations

import pytest

from delta.crm.schemas import (
    ClientCreateRequest,
    DealCreateRequest,
    DealStageTransitionRequest,
    InteractionCreateRequest,
    StakeholderCreateRequest,
)
from delta.crm.service import (
    ClientNotFoundError,
    CrmScopeMismatchError,
    DealAlreadyTerminalError,
    DealNotFoundError,
    create_client,
    create_deal,
    create_interaction,
    create_stakeholder,
    get_relationship_score,
    transition_deal_stage,
)
from delta.persistence.database import get_tenant_session

from .conftest import db_required


@db_required
async def test_create_deal_with_value_defaults_currency_when_null(tenant_id) -> None:
    # Security-review finding (ADR-0013 §4): a caller-supplied `currency: null` must
    # not survive alongside a non-null value_minor_units — the two always travel
    # together. Regression test for the fix in delta.crm.service.create_deal.
    async with get_tenant_session(tenant_id) as session:
        client = await create_client(session, ClientCreateRequest(tenant_id=tenant_id, name="A"))

    async with get_tenant_session(tenant_id) as session:
        deal = await create_deal(
            session,
            client_id=client.client_id,
            req=DealCreateRequest(
                tenant_id=tenant_id, name="Big Deal", value_minor_units=5_000_00, currency=None
            ),
        )

    assert deal.value_minor_units == 5_000_00
    assert deal.currency == "USD"


@db_required
async def test_create_deal_against_missing_client_raises(tenant_id) -> None:
    req = DealCreateRequest(tenant_id=tenant_id, name="Ghost Deal")
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(ClientNotFoundError):
            await create_deal(session, client_id="99999999-9999-4999-8999-999999999999", req=req)


@db_required
async def test_transition_deal_stage_already_terminal_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await create_client(session, ClientCreateRequest(tenant_id=tenant_id, name="A"))

    async with get_tenant_session(tenant_id) as session:
        deal = await create_deal(
            session,
            client_id=client.client_id,
            req=DealCreateRequest(tenant_id=tenant_id, name="D"),
        )

    async with get_tenant_session(tenant_id) as session:
        await transition_deal_stage(
            session,
            deal_id=deal.deal_id,
            req=DealStageTransitionRequest(tenant_id=tenant_id, stage="lost", actor="Jane"),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(DealAlreadyTerminalError):
            await transition_deal_stage(
                session,
                deal_id=deal.deal_id,
                req=DealStageTransitionRequest(tenant_id=tenant_id, stage="won", actor="Jane"),
            )


@db_required
async def test_transition_deal_stage_missing_deal_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(DealNotFoundError):
            await transition_deal_stage(
                session,
                deal_id="99999999-9999-4999-8999-999999999999",
                req=DealStageTransitionRequest(tenant_id=tenant_id, stage="won", actor="Jane"),
            )


@db_required
async def test_interaction_tagged_to_deal_from_another_client_rejected(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client_a = await create_client(
            session, ClientCreateRequest(tenant_id=tenant_id, name="Client A")
        )

    async with get_tenant_session(tenant_id) as session:
        client_b = await create_client(
            session, ClientCreateRequest(tenant_id=tenant_id, name="Client B")
        )

    async with get_tenant_session(tenant_id) as session:
        deal_for_b = await create_deal(
            session,
            client_id=client_b.client_id,
            req=DealCreateRequest(tenant_id=tenant_id, name="B's Deal"),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(CrmScopeMismatchError):
            await create_interaction(
                session,
                client_id=client_a.client_id,
                req=InteractionCreateRequest(
                    tenant_id=tenant_id,
                    deal_id=deal_for_b.deal_id,
                    interaction_type="note",
                    occurred_at="2026-07-08T12:00:00Z",
                    summary="Should be rejected",
                    created_by="Jane",
                ),
            )


@db_required
async def test_stakeholder_from_another_client_rejected_on_interaction(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client_a = await create_client(
            session, ClientCreateRequest(tenant_id=tenant_id, name="Client A")
        )

    async with get_tenant_session(tenant_id) as session:
        client_b = await create_client(
            session, ClientCreateRequest(tenant_id=tenant_id, name="Client B")
        )

    async with get_tenant_session(tenant_id) as session:
        stakeholder_for_b = await create_stakeholder(
            session,
            client_id=client_b.client_id,
            req=StakeholderCreateRequest(tenant_id=tenant_id, name="Bob"),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(CrmScopeMismatchError):
            await create_interaction(
                session,
                client_id=client_a.client_id,
                req=InteractionCreateRequest(
                    tenant_id=tenant_id,
                    stakeholder_id=stakeholder_for_b.stakeholder_id,
                    interaction_type="note",
                    occurred_at="2026-07-08T12:00:00Z",
                    summary="Should be rejected",
                    created_by="Jane",
                ),
            )


@db_required
async def test_relationship_score_for_untouched_client_is_zero(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        client = await create_client(
            session, ClientCreateRequest(tenant_id=tenant_id, name="Untouched")
        )

    async with get_tenant_session(tenant_id) as session:
        score = await get_relationship_score(session, client_id=client.client_id)

    assert score.score == 0.0
    assert score.method == "recency_frequency_v1"
    assert score.days_since_last_interaction is None
