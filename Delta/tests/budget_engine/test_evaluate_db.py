"""End-to-end evaluation with a stubbed publisher (vectors 6,7,8,10) — DB-backed.

Drives the real ``evaluate_after_post`` against a live ledger; the O-004 POST is stubbed so
these assert the DECISION + outbox + state, not the network. The non-stubbed real-O-004
proof lives in ``test_o004_e2e``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_engine import drainer
from delta.budget_engine.definitions import create_budget, raise_budget_cost_cap
from delta.budget_engine.evaluator import evaluate_after_post
from delta.budget_engine.publisher import Distributed, PermanentPublishError, TransientPublishError

from .conftest import db_required

pytestmark = db_required

_TEAM = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_PROJ = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _recent_ts() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def stub_publish(monkeypatch):
    calls: list[dict] = []
    state = {"mode": "ok"}

    async def _fake(signed, settings):
        calls.append(signed)
        if state["mode"] == "transient":
            raise TransientPublishError("o004 down")
        if state["mode"] == "permanent":
            raise PermanentPublishError("rejected")
        return Distributed(distribution_id=f"dist-{len(calls)}")

    monkeypatch.setattr(drainer, "publish_signed_policy", _fake)
    return SimpleNamespace(calls=calls, state=state)


async def _make_budget(tenant_session, tenant_id, *, cap, scope=BudgetScope.TENANT):
    concept = BudgetConcept(
        tenant_id=tenant_id,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=scope,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=cap,
    )
    async with tenant_session(tenant_id) as s:
        bd = await create_budget(s, concept, now=datetime.now(timezone.utc))
        await s.commit()
    return bd


async def test_under_cap_no_publish(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    await _make_budget(tenant_session, tenant_id, cap=1_000_000)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=500) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)
    assert stub_publish.calls == []  # real no-op
    assert await read_outbox(tenant_id) == []
    states = await read_state(tenant_id)
    assert len(states) == 1 and states[0]["state"] == "under"


async def test_over_cap_publishes_exactly_once(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
    read_history,
):
    bd = await _make_budget(tenant_session, tenant_id, cap=1000)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=1500) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)

    assert len(stub_publish.calls) == 1
    signed = stub_publish.calls[0]
    assert signed["policy_type"] == "budget_limit"
    assert signed["scope"] == "tenant"
    assert signed["tenant_id"] == tenant_id
    assert signed["policy_id"] == bd.policy_id
    assert signed["policy_version"] == 1
    assert signed["max_cost_cents_per_period"] == 1000
    # Really signed (not the placeholder) and three compact-JWS segments.
    assert signed["signature"] != "AAAAAAAAAAAA.BBBBBBBBBBBB.CCCCCCCCCCCC"
    assert len(signed["signature"].split(".")) == 3

    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1 and outbox[0]["state"] == "distributed"
    assert outbox[0]["distribution_id"] == "dist-1"
    states = await read_state(tenant_id)
    assert states[0]["state"] == "enforced" and states[0]["enforced_policy_version"] == 1
    # D-009: the enforcement decision is hash-chain audited in the same transaction.
    history = await read_history(tenant_id, entity_id=bd.budget_id)
    assert history == [{"entity_id": bd.budget_id, "action": "enforce", "actor": "budget-engine"}]


async def test_repeated_over_cap_does_not_republish(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
):
    await _make_budget(tenant_session, tenant_id, cap=1000)
    r1 = await post_debit(
        make_usage_payload(tenant_id, cost=1500) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r1, engine_settings)
    r2 = await post_debit(
        make_usage_payload(tenant_id, cost=200) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r2, engine_settings)  # still over cap, already enforced
    assert len(stub_publish.calls) == 1  # no flapping / re-publish (vector 6)
    assert len(await read_outbox(tenant_id)) == 1


async def test_cross_tenant_overage_does_not_enforce_other(
    tenant_id,
    other_tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    await _make_budget(tenant_session, tenant_id, cap=1000)
    await _make_budget(tenant_session, other_tenant_id, cap=1000)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)
    # Only tenant A's policy is published; B is untouched (vector 8).
    assert len(stub_publish.calls) == 1
    assert stub_publish.calls[0]["tenant_id"] == tenant_id
    assert len(await read_outbox(tenant_id)) == 1
    assert await read_outbox(other_tenant_id) == []
    assert await read_state(other_tenant_id) == []


async def test_warning_threshold_never_publishes(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    await _make_budget(tenant_session, tenant_id, cap=1000)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=850) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)  # 85% -> warning, NOT enforcement
    assert stub_publish.calls == []  # vector 10: warning never publishes
    assert await read_outbox(tenant_id) == []
    states = await read_state(tenant_id)
    assert states[0]["state"] == "under" and states[0]["last_warned_pct"] == 80


async def test_budget_raise_lifts_enforcement(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
    read_history,
):
    bd = await _make_budget(tenant_session, tenant_id, cap=1000)
    r1 = await post_debit(
        make_usage_payload(tenant_id, cost=1500) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r1, engine_settings)  # enforce v1
    assert len(stub_publish.calls) == 1

    # Raise the cap above current spend.
    async with tenant_session(tenant_id) as s:
        await raise_budget_cost_cap(s, budget_id=bd.budget_id, new_limit_cost_cents=10_000)
        await s.commit()

    r2 = await post_debit(
        make_usage_payload(tenant_id, cost=100) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r2, engine_settings)  # spend 1600 < 10000 -> un-enforce (refresh v2)

    assert len(stub_publish.calls) == 2
    refresh = stub_publish.calls[1]
    assert refresh["policy_version"] == 2
    assert refresh["max_cost_cents_per_period"] == 10_000  # the raised cap
    states = await read_state(tenant_id)
    assert states[0]["state"] == "under"
    outbox = await read_outbox(tenant_id)
    assert [o["transition"] for o in outbox] == ["enforce", "refresh"]
    # D-009: both decisions are hash-chain audited, in the same order as the outbox.
    history = await read_history(tenant_id, entity_id=bd.budget_id)
    assert [h["action"] for h in history] == ["enforce", "refresh"]
    assert all(h["actor"] == "budget-engine" for h in history)
