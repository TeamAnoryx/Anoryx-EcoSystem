"""End-to-end kill-switch evaluation with a stubbed publisher — DB-backed.

Drives the real ``evaluate_kill_switch`` against a live ledger; the O-004 POST is stubbed
so these assert the DECISION + outbox + state, not the network (ADR-0006 §6).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from delta.budget_engine.publisher import Distributed, PermanentPublishError, TransientPublishError
from delta.kill_switch import drainer
from delta.kill_switch.authorizations import authorize_agent, clear_kill_switch
from delta.kill_switch.config import KillSwitchSettings
from delta.kill_switch.evaluator import evaluate_kill_switch
from delta.persistence.database import get_tenant_session

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


async def _authorize(tenant_session, tenant_id, agent_id):
    async with tenant_session(tenant_id) as s:
        await authorize_agent(
            s, tenant_id=tenant_id, agent_id=agent_id, now=datetime.now(timezone.utc)
        )
        await s.commit()


# ------------------------------------------------------------- unauthorized-agent trigger
async def test_ungated_tenant_never_killed_for_identity(
    tenant_id, make_usage_payload, post_debit, kill_switch_settings, stub_publish, read_outbox
):
    # vector 9: zero agent_authorizations rows -> the identity trigger is inert.
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="never-authorized", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, kill_switch_settings)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []


async def test_authorized_agent_not_killed(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
):
    await _authorize(tenant_session, tenant_id, "gateway-core")
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="gateway-core", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, kill_switch_settings)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []


async def test_unauthorized_agent_killed_exactly_once(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    # Gate the tenant (authorize a DIFFERENT agent) so "rogue-agent" is unauthorized.
    await _authorize(tenant_session, tenant_id, "gateway-core")
    team = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    proj = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    r1 = await post_debit(
        make_usage_payload(tenant_id, team_id=team, project_id=proj, agent_id="rogue-agent", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(r1, kill_switch_settings)

    assert len(stub_publish.calls) == 1
    signed = stub_publish.calls[0]
    assert signed["policy_type"] == "budget_limit"
    assert signed["scope"] == "agent"
    assert signed["agent_id"] == "rogue-agent"
    assert signed["max_cost_cents_per_period"] == 0
    assert signed["max_tokens_per_period"] == 0
    assert signed["policy_version"] == 1
    assert len(signed["signature"].split(".")) == 3

    outbox = await read_outbox(tenant_id)
    assert len(outbox) == 1
    assert outbox[0]["state"] == "distributed"
    assert outbox[0]["transition"] == "kill"
    states = await read_state(tenant_id)
    assert states[0]["state"] == "killed" and states[0]["reason"] == "unauthorized_agent"

    # A second offending event for the SAME scope must not re-publish (idempotent).
    r2 = await post_debit(
        make_usage_payload(tenant_id, team_id=team, project_id=proj, agent_id="rogue-agent", cost=2)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(r2, kill_switch_settings)
    assert len(stub_publish.calls) == 1  # no flapping / re-publish


# ------------------------------------------------------------- anomalous single-tx trigger
async def test_anomalous_single_tx_killed(
    tenant_id, make_usage_payload, post_debit, stub_publish, read_outbox, read_state
):
    settings = KillSwitchSettings(
        enabled=True,
        distribution_url="http://orch.invalid:9",
        service_token="test-token",
        max_publish_attempts=3,
        backoff_base_seconds=0.0,
        max_single_tx_cost_cents=1000,
    )
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="normal-agent", cost=50_000)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, settings)
    assert len(stub_publish.calls) == 1
    assert stub_publish.calls[0]["max_cost_cents_per_period"] == 0
    states = await read_state(tenant_id)
    assert states[0]["state"] == "killed" and states[0]["reason"] == "anomalous_single_tx"


async def test_single_tx_under_ceiling_not_killed(
    tenant_id, make_usage_payload, post_debit, stub_publish, read_outbox
):
    settings = KillSwitchSettings(
        enabled=True,
        distribution_url="http://orch.invalid:9",
        service_token="test-token",
        max_single_tx_cost_cents=100_000,
    )
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="normal-agent", cost=50_000)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, settings)
    assert stub_publish.calls == []
    assert await read_outbox(tenant_id) == []


# ------------------------------------------------------------------------- tenant isolation
async def test_cross_tenant_offense_does_not_kill_other(
    tenant_id,
    other_tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    await _authorize(tenant_session, tenant_id, "gateway-core")
    await _authorize(tenant_session, other_tenant_id, "gateway-core")
    rec = await post_debit(
        make_usage_payload(tenant_id, agent_id="rogue-agent", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, kill_switch_settings)
    assert len(stub_publish.calls) == 1
    assert stub_publish.calls[0]["tenant_id"] == tenant_id
    assert len(await read_outbox(tenant_id)) == 1
    assert await read_outbox(other_tenant_id) == []
    assert await read_state(other_tenant_id) == []


# --------------------------------------------------------------------------------- un-kill
async def test_authorize_clears_all_scopes_for_agent(
    tenant_id,
    tenant_session,
    make_usage_payload,
    post_debit,
    kill_switch_settings,
    stub_publish,
    read_outbox,
    read_state,
):
    """vector 10: a rogue agent_id offending under TWO different team/project scopes is
    cleared everywhere by a single authorize_agent call, not just the last-seen scope."""
    await _authorize(tenant_session, tenant_id, "gateway-core")  # gate the tenant
    team_a, proj_a = "aaaaaaaa-0000-4aaa-8aaa-aaaaaaaaaaaa", "cccccccc-0000-4ccc-8ccc-cccccccccccc"
    team_b, proj_b = "bbbbbbbb-0000-4bbb-8bbb-bbbbbbbbbbbb", "dddddddd-0000-4ddd-8ddd-dddddddddddd"

    r_a = await post_debit(
        make_usage_payload(tenant_id, team_id=team_a, project_id=proj_a, agent_id="rogue", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(r_a, kill_switch_settings)
    r_b = await post_debit(
        make_usage_payload(tenant_id, team_id=team_b, project_id=proj_b, agent_id="rogue", cost=1)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(r_b, kill_switch_settings)
    assert len(stub_publish.calls) == 2  # two independent kills, two independent scopes
    killed_before = await read_state(tenant_id)
    assert len(killed_before) == 2
    assert all(
        s["state"] == "killed" and s["reason"] == "unauthorized_agent" for s in killed_before
    )

    await _authorize(tenant_session, tenant_id, "rogue")
    await drainer.drain_tenant(tenant_id, kill_switch_settings, datetime.now(timezone.utc))

    states_after = await read_state(tenant_id)
    assert len(states_after) == 2
    assert all(s["state"] == "clear" for s in states_after)  # both scopes cleared, not just one

    outbox = await read_outbox(tenant_id)
    clears = [o for o in outbox if o["transition"] == "clear"]
    assert len(clears) == 2  # one clear decision per scope
    assert all(o["state"] == "distributed" for o in clears)


async def test_clear_kill_switch_operator_override(
    tenant_id,
    make_usage_payload,
    post_debit,
    stub_publish,
    read_outbox,
    read_state,
):
    """An anomalous-tx kill can be cleared directly without touching the allow-list."""
    settings = KillSwitchSettings(
        enabled=True,
        distribution_url="http://orch.invalid:9",
        service_token="test-token",
        max_single_tx_cost_cents=1000,
    )
    team = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    proj = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    rec = await post_debit(
        make_usage_payload(tenant_id, team_id=team, project_id=proj, agent_id="bursty", cost=50_000)
        | {"event_timestamp": _recent_ts()}
    )
    await evaluate_kill_switch(rec, settings)
    assert (await read_state(tenant_id))[0]["state"] == "killed"

    async with get_tenant_session(tenant_id) as s:
        cleared = await clear_kill_switch(
            s,
            tenant_id=tenant_id,
            team_id=team,
            project_id=proj,
            agent_id="bursty",
            now=datetime.now(timezone.utc),
        )
        await s.commit()
    assert cleared is True

    await drainer.drain_tenant(tenant_id, settings, datetime.now(timezone.utc))
    states = await read_state(tenant_id)
    assert states[0]["state"] == "clear"
    outbox = await read_outbox(tenant_id)
    assert [o["transition"] for o in outbox] == ["kill", "clear"]
