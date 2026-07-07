"""Kill-switch fail posture (ADR-0006 §3.7, vectors 3+4) — DB-backed.

The two dangerous directions, mirrored from ADR-0005 §3.5/vectors 11+12:
  * MISSED kill — a real decision must NEVER be silently dropped if O-004 is down /
    rejects / the signing key is missing (vector 4): retained, retried, dead-lettered.
  * FALSE kill — a transient detection-read error must NEVER publish a kill on an
    authorized/normal agent (vector 3): no read, no decision.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from delta.budget_engine.publisher import Distributed, PermanentPublishError, TransientPublishError
from delta.kill_switch import drainer, evaluator
from delta.kill_switch.config import KillSwitchSettings
from delta.kill_switch.evaluator import evaluate_kill_switch

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


@pytest.fixture
def anomaly_settings() -> KillSwitchSettings:
    return KillSwitchSettings(
        enabled=True,
        distribution_url="http://orch.invalid:9",
        service_token="test-token",
        max_publish_attempts=3,
        backoff_base_seconds=0.0,
        max_single_tx_cost_cents=100,
    )


# ---------------------------------------------------------------- vector 4: never lost
async def test_o004_down_decision_retained_not_lost(
    tenant_id,
    make_usage_payload,
    post_debit,
    anomaly_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    stub_publish.state["mode"] = "transient"  # O-004 down
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, anomaly_settings)

    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1
    assert outbox[0]["state"] == "pending"
    assert outbox[0]["attempts"] >= 1
    assert "o004 down" in (outbox[0]["last_error"] or "")
    assert (await read_state(tenant_id))[0]["state"] == "killed"


async def test_recovers_when_o004_returns(
    tenant_id, make_usage_payload, post_debit, anomaly_settings, stub_publish, read_outbox
):
    stub_publish.state["mode"] = "transient"
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, anomaly_settings)
    assert (await read_outbox(tenant_id))[0]["state"] == "pending"

    stub_publish.state["mode"] = "ok"
    await drainer.drain_tenant(tenant_id, anomaly_settings, datetime.now(timezone.utc))
    outbox = await read_outbox(tenant_id)
    assert outbox[0]["state"] == "distributed"
    assert outbox[0]["distribution_id"] is not None


async def test_retries_exhausted_dead_letters_retained(
    tenant_id, make_usage_payload, post_debit, anomaly_settings, stub_publish, read_outbox
):
    stub_publish.state["mode"] = "transient"  # never recovers
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, anomaly_settings)  # attempt 1 (inline drain)
    for _ in range(2):
        await drainer.drain_tenant(tenant_id, anomaly_settings, datetime.now(timezone.utc))
    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1
    assert outbox[0]["state"] == "failed"  # dead-lettered, NOT silently dropped
    assert outbox[0]["attempts"] == 3


async def test_permanent_rejection_dead_letters(
    tenant_id, make_usage_payload, post_debit, anomaly_settings, stub_publish, read_outbox
):
    stub_publish.state["mode"] = "permanent"
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, anomaly_settings)
    outbox = await read_outbox(tenant_id)
    assert outbox[0]["state"] == "failed"


async def test_missing_signing_key_retains_decision_not_fail_open(
    tenant_id,
    make_usage_payload,
    post_debit,
    anomaly_settings,
    stub_publish,
    read_outbox,
    monkeypatch,
):
    monkeypatch.delenv("DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM", raising=False)
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, anomaly_settings)
    assert stub_publish.calls == []
    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1 and outbox[0]["state"] == "pending"


# ---------------------------------------------------------------- vector 3: no false kill
async def test_transient_detect_error_no_false_kill(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
    read_state,
    monkeypatch,
):
    from delta.kill_switch.authorizations import authorize_agent

    async with tenant_session(tenant_id) as s:
        await authorize_agent(
            s, tenant_id=tenant_id, agent_id="gateway-core", now=datetime.now(timezone.utc)
        )
        await s.commit()

    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="rogue-agent", cost=1)
        | {"event_timestamp": _recent_ts()}
    )

    async def _boom(*a, **k):
        raise ConnectionRefusedError("db down")  # an OSError subclass -> transient

    monkeypatch.setattr(evaluator, "is_tenant_gated", _boom)
    await evaluate_kill_switch(rec, kill_switch_settings)  # must not raise, must not kill
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []
    states = await read_state(tenant_id)
    assert states == [] or all(s["state"] == "clear" for s in states)


async def test_non_transient_detect_error_no_fail_open(
    tenant_id,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
    monkeypatch,
):
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="rogue-agent", cost=1)
        | {"event_timestamp": _recent_ts()}
    )

    async def _boom(*a, **k):
        raise ValueError("unexpected")

    monkeypatch.setattr(evaluator, "is_tenant_gated", _boom)
    await evaluate_kill_switch(rec, kill_switch_settings)  # never raises
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []


async def test_kill_switch_disabled_is_noop(
    tenant_id, make_usage_payload, post_debit, stub_publish, read_outbox
):
    disabled = KillSwitchSettings(enabled=False, distribution_url="", service_token="")
    rec = await post_debit(
        make_usage_payload(tenant_id, cost=5000) | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, disabled)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []
