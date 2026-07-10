"""D-020 non-stubbed pipeline-rollup persistence suite: real store writes -> real SQL
reads, real RLS."""

from __future__ import annotations

from delta.executive import store

from .conftest import db_required, open_tenant_session, seed_client_and_deal


@db_required
async def test_pipeline_summary_excludes_terminal_deals(tenant_id) -> None:
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=50_000, stage="qualified")
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=100_000, stage="won")
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=200_000, stage="lost")

    async with open_tenant_session(tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    assert summary.client_count == 3
    assert summary.open_deal_count == 1
    assert summary.open_pipeline_value_minor_units == 50_000


@db_required
async def test_pipeline_summary_excludes_null_value_deals_from_sum(tenant_id) -> None:
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=None, stage="lead")

    async with open_tenant_session(tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    assert summary.open_deal_count == 1  # counted...
    assert summary.open_pipeline_value_minor_units == 0  # ...but contributes no value


@db_required
async def test_pipeline_summary_scoped_to_currency(tenant_id) -> None:
    await seed_client_and_deal(
        tenant_id=tenant_id, value_minor_units=50_000, stage="qualified", currency="USD"
    )
    await seed_client_and_deal(
        tenant_id=tenant_id, value_minor_units=999_999, stage="qualified", currency="EUR"
    )

    async with open_tenant_session(tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    assert summary.open_pipeline_value_minor_units == 50_000  # the EUR deal excluded
    # open_deal_count and the value sum describe the SAME deal set — the EUR deal is
    # excluded from both, not counted-but-unsummed (security audit finding).
    assert summary.open_deal_count == 1


@db_required
async def test_pipeline_summary_null_currency_deal_still_counted_with_other_currency_present(
    tenant_id,
) -> None:
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=None, stage="lead")
    await seed_client_and_deal(
        tenant_id=tenant_id, value_minor_units=999_999, stage="qualified", currency="EUR"
    )

    async with open_tenant_session(tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    # the null-value/null-currency lead still counts (D-013's own pairing discipline);
    # the EUR deal does not.
    assert summary.open_deal_count == 1
    assert summary.open_pipeline_value_minor_units == 0


@db_required
async def test_pipeline_summary_zero_for_tenant_with_no_data(tenant_id) -> None:
    async with open_tenant_session(tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    assert summary.client_count == 0
    assert summary.open_deal_count == 0
    assert summary.open_pipeline_value_minor_units == 0


@db_required
async def test_pipeline_summary_cross_tenant_isolated(tenant_id, other_tenant_id) -> None:
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=50_000, stage="qualified")

    async with open_tenant_session(other_tenant_id) as session:
        summary = await store.get_pipeline_summary(session, currency="USD")

    assert summary.client_count == 0
    assert summary.open_deal_count == 0
