"""Fail posture (vectors 11+12) — DB-backed.

The two catastrophic directions:
  * MISSED enforcement — a real decision must NEVER be silently dropped if O-004 is down /
    rejects / the signing key is missing (vector 11): it is retained in the outbox + retried
    + dead-lettered, never lost.
  * FALSE enforcement — a transient ledger-read error must NEVER publish an enforcement on
    an under-or-over-budget tenant (vector 12): no read, no decision.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_engine import drainer, evaluator
from delta.budget_engine.definitions import create_budget
from delta.budget_engine.evaluator import evaluate_after_post
from delta.budget_engine.publisher import Distributed, PermanentPublishError, TransientPublishError

from .conftest import db_required

pytestmark = db_required


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


async def _budget_over_cap(tenant_session, tenant_id, *, cap=1000):
    concept = BudgetConcept(
        tenant_id=tenant_id,
        team_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        project_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        agent_id="gateway-core",
        scope=BudgetScope.TENANT,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=cap,
    )
    async with tenant_session(tenant_id) as s:
        await create_budget(s, concept, now=datetime.now(timezone.utc))
        await s.commit()


# ---------------------------------------------------------------- vector 11: never lost
async def test_o004_down_decision_retained_not_lost(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    stub_publish.state["mode"] = "transient"  # O-004 down
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)

    # Decision was made (state flipped) AND retained pending — NOT dropped.
    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1
    assert outbox[0]["state"] == "pending"
    assert outbox[0]["attempts"] >= 1
    assert "o004 down" in (outbox[0]["last_error"] or "")
    assert (await read_state(tenant_id))[0]["state"] == "enforced"


async def test_recovers_when_o004_returns(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
):
    stub_publish.state["mode"] = "transient"
    await _budget_over_cap(tenant_session, tenant_id)
    r1 = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r1, engine_settings)
    assert (await read_outbox(tenant_id))[0]["state"] == "pending"

    # O-004 recovers; a later event re-drains the pending decision (event-driven retry).
    stub_publish.state["mode"] = "ok"
    r2 = await post_debit(
        make_usage_payload(tenant_id, cost=100) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(r2, engine_settings)
    outbox = await read_outbox(tenant_id)
    assert outbox[0]["state"] == "distributed"
    assert outbox[0]["distribution_id"] is not None


async def test_retries_exhausted_dead_letters_retained(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
):
    stub_publish.state["mode"] = "transient"  # never recovers
    await _budget_over_cap(tenant_session, tenant_id)
    # max_publish_attempts=3: three drains exhaust retries -> failed (the DLQ), retained.
    for _ in range(3):
        rec = await post_debit(
            make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
        )
        await evaluate_after_post(rec, engine_settings)
    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1
    assert outbox[0]["state"] == "failed"  # dead-lettered, NOT silently dropped
    assert outbox[0]["attempts"] == 3


async def test_permanent_rejection_dead_letters(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
):
    stub_publish.state["mode"] = "permanent"  # O-004 rejects the policy/token (4xx)
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)
    outbox = await read_outbox(tenant_id)
    assert outbox[0]["state"] == "failed"  # dead-lettered immediately, not retried, not lost


async def test_missing_signing_key_retains_decision_not_fail_open(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    monkeypatch,
):
    """A missing signing key is a publish failure: decision queued + nothing published."""
    monkeypatch.delenv("DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM", raising=False)
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, engine_settings)
    # Nothing was published (the drainer never reached publish), but the decision is retained.
    assert stub_publish.calls == []
    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1 and outbox[0]["state"] == "pending"


# ---------------------------------------------------------------- vector 12: no false enforce
async def test_transient_eval_error_no_false_enforce(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    read_state,
    monkeypatch,
):
    """A transient ledger-read error never publishes an enforcement (vector 12)."""
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )

    async def _boom(*a, **k):
        raise ConnectionRefusedError("db down")  # an OSError subclass -> transient

    monkeypatch.setattr(evaluator, "scope_spend_cents", _boom)
    # Must not raise, must not publish, must not enforce.
    await evaluate_after_post(rec, engine_settings)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []
    # No enforcement-state row was flipped (the read failed before any decision).
    states = await read_state(tenant_id)
    assert states == [] or all(s["state"] == "under" for s in states)


async def test_non_transient_eval_error_no_fail_open(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    engine_settings,
    stub_publish,
    read_outbox,
    monkeypatch,
):
    """A non-transient eval error is swallowed (logged loud) — never a fail-open publish."""
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )

    async def _boom(*a, **k):
        raise ValueError("unexpected")

    monkeypatch.setattr(evaluator, "scope_spend_cents", _boom)
    await evaluate_after_post(rec, engine_settings)  # never raises
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []


async def test_engine_disabled_is_noop(
    tenant_id, tenant_session, make_usage_payload, post_debit, stub_publish, read_outbox
):
    from delta.budget_engine.config import EngineSettings

    disabled = EngineSettings(enabled=False, distribution_url="", service_token="")
    await _budget_over_cap(tenant_session, tenant_id)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_after_post(rec, disabled)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []
