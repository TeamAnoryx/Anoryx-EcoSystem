"""Non-stubbed cross-module automation-rules engine e2e (O-011, ADR-0011).

Reuses the O-004 distribution-engine fixtures/shim (a REAL signed policy, a REAL
distribution, a REAL loopback Sentinel-shim intake) and the O-003 ingest HMAC receiver, so
NOTHING on the path under test is stubbed: a real signed HMAC envelope is POSTed to
`/v1/ingest/events`, accepted, and (via a FastAPI BackgroundTask — httpx's ASGITransport
runs it synchronously, so it has already completed by the time the POST returns) the
automation engine evaluates this tenant's rules and re-drives the matched rule's O-004
distribution through the real engine, over a real socket, to the real shim.

Proves:
  * `automation_executions` gets exactly one `executed` row referencing the right
    rule_id/triggering_event_id after a genuine ingest -> match -> execute path.
  * A second, duplicate SCHEDULING of the same (rule_id, triggering_event_id) — the exact
    race the UNIQUE dedup constraint exists for — does NOT produce a second row.
  * With `ORCH_AUTOMATION_ENABLED` unset/false, no row is EVER written even though the
    rule genuinely matches — the master switch genuinely gates everything.
  * A rule with a non-matching condition never produces a row.

Gated by automation_ready, which FAILS (not skips) under ORCH_REQUIRE_AUTOMATION_E2E=1 so
this gate provably EXECUTES on CI.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration

_INGEST_SECRET = "o011-ingest-secret"  # noqa: S105 - test-only fake
_TARGET = "sentinel-automation-test"
_VIOLATION_TYPE = "budget_cost_exceeded"


def _sign_and_headers(body: bytes, *, secret: bytes) -> dict[str, str]:
    ts = int(time.time())
    signed = f"{ts}.".encode("utf-8") + body
    digest = hmac.new(secret, signed, hashlib.sha256).hexdigest()
    return {
        "X-Sentinel-Signature": f"sha256={digest}",
        "X-Sentinel-Timestamp": str(ts),
        "Content-Type": "application/json",
    }


def _make_envelope(*, tenant_id: str, violation_type: str = _VIOLATION_TYPE) -> dict:
    event_id = str(uuid.uuid4())
    request_id = "req-" + uuid.uuid4().hex[:24]
    return {
        "schema_version": 1,
        "envelope_id": str(uuid.uuid4()),
        "event_type": "policy_decision_deny",
        "source_product": "sentinel",
        "occurred_at": "2026-07-08T12:00:01Z",
        "idempotency_key": event_id,
        "sequence": 1,
        "correlation_id": request_id,
        "payload": {
            "event_type": "policy_decision_deny",
            "tenant_id": tenant_id,
            "team_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "agent_id": "gateway-core",
            "event_id": event_id,
            "event_timestamp": "2026-07-08T12:00:00Z",
            "request_id": request_id,
            "action_taken": "blocked",
            "policy_id": str(uuid.uuid4()),
            "requested_model": "gpt-4o",
            "violation_type": violation_type,
        },
    }


async def _post_ingest(app, envelope: dict) -> httpx.Response:
    body = json.dumps(envelope).encode("utf-8")
    headers = _sign_and_headers(body, secret=_INGEST_SECRET.encode("utf-8"))
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post("/v1/ingest/events", content=body, headers=headers)


def _app(monkeypatch, *, shim_base_url: str, enabled: bool = True):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", _INGEST_SECRET)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "o011-sentinel-admin-token")
    monkeypatch.setenv("ORCH_DISTRIBUTION_TARGETS", json.dumps({_TARGET: shim_base_url}))
    monkeypatch.setenv("ORCH_SENTINEL_INTAKE_PATH", "/admin/policies/intake")
    monkeypatch.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "1")
    if enabled:
        monkeypatch.setenv("ORCH_AUTOMATION_ENABLED", "1")
    else:
        monkeypatch.delenv("ORCH_AUTOMATION_ENABLED", raising=False)
    from orchestrator.app import create_app

    return create_app()


async def _create_rule(app, *, token: str, distribution_id: str, violation_type: str) -> dict:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.post(
            "/v1/automation/rules",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "redistribute-on-budget-deny-" + uuid.uuid4().hex[:8],
                "trigger_event_type": "policy_decision_deny",
                "trigger_conditions": {"violation_type": violation_type},
                "action_type": "redistribute_policy",
                "action_config": {"distribution_id": distribution_id},
            },
        )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _executions_for_rule(rule_id: str) -> list[dict]:
    from orchestrator.persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        from sqlalchemy import select

        from orchestrator.persistence.models.automation_execution import AutomationExecution

        result = await session.execute(
            select(AutomationExecution).where(AutomationExecution.rule_id == rule_id)
        )
        return [
            {c.name: getattr(row, c.name) for c in AutomationExecution.__table__.columns}
            for row in result.scalars()
        ]


async def test_matching_event_executes_exactly_once_and_dedupes(
    automation_ready,
    sentinel_shim_server,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    seed_query_token,
    monkeypatch,
):
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy("model_allowlist", tenant_id=tenant, allowed_model_ids=["gpt-4o"])
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    app = _app(monkeypatch, shim_base_url=sentinel_shim_server, enabled=True)
    token = await seed_query_token(tenant)
    rule = await _create_rule(
        app, token=token, distribution_id=distribution_id, violation_type=_VIOLATION_TYPE
    )

    envelope = _make_envelope(tenant_id=tenant, violation_type=_VIOLATION_TYPE)
    resp = await _post_ingest(app, envelope)
    assert resp.status_code == 202, resp.text

    # --- REAL execution proof: exactly one `executed` row for this rule/event --------- #
    rows = await _executions_for_rule(rule["id"])
    matching = [r for r in rows if r["triggering_event_id"] == envelope["idempotency_key"]]
    assert len(matching) == 1, matching
    assert matching[0]["disposition"] == "executed", matching[0]
    assert matching[0]["tenant_id"] == tenant
    assert matching[0]["action_type"] == "redistribute_policy"

    # The redistributed O-004 distribution genuinely settled (real engine, real shim).
    from orchestrator.persistence.database import get_privileged_session

    async with get_privileged_session() as psession:
        from sqlalchemy import text

        state = (
            await psession.execute(
                text("SELECT state FROM policy_distributions WHERE distribution_id = :d"),
                {"d": distribution_id},
            )
        ).scalar_one()
    assert state == "distributed", state

    # --- REAL dedup proof: a duplicate SCHEDULING of the same event never double-executes #
    from orchestrator.automation.engine import evaluate_and_execute
    from orchestrator.config import get_automation_settings, get_distribution_settings

    await evaluate_and_execute(
        tenant_id=tenant,
        event_id=envelope["idempotency_key"],
        event_type="policy_decision_deny",
        source_product="sentinel",
        payload=envelope["payload"],
        automation_settings=get_automation_settings(),
        distribution_settings=get_distribution_settings(),
    )
    rows_after = await _executions_for_rule(rule["id"])
    matching_after = [
        r for r in rows_after if r["triggering_event_id"] == envelope["idempotency_key"]
    ]
    assert len(matching_after) == 1, matching_after  # still exactly one — no duplicate row

    # --- REAL duplicate-ingest proof: a re-delivered identical envelope dedupes at the
    #     ingest layer too, so automation is never even re-scheduled for it. -------------- #
    resp2 = await _post_ingest(app, envelope)
    assert resp2.status_code == 202
    rows_after_redelivery = await _executions_for_rule(rule["id"])
    matching_after_redelivery = [
        r for r in rows_after_redelivery if r["triggering_event_id"] == envelope["idempotency_key"]
    ]
    assert len(matching_after_redelivery) == 1, matching_after_redelivery


async def test_master_switch_off_never_writes_a_row_even_when_matching(
    automation_ready,
    sentinel_shim_server,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    seed_query_token,
    monkeypatch,
):
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy("model_allowlist", tenant_id=tenant, allowed_model_ids=["gpt-4o"])
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    # ORCH_AUTOMATION_ENABLED is set on ONE app (to create the rule via the real API) and
    # unset on a SECOND app (to prove the master switch, not merely absent config, gates
    # evaluation) — both point at the same DB, so the rule created via the first app is
    # visible to the second.
    creating_app = _app(monkeypatch, shim_base_url=sentinel_shim_server, enabled=True)
    token = await seed_query_token(tenant)
    rule = await _create_rule(
        creating_app, token=token, distribution_id=distribution_id, violation_type=_VIOLATION_TYPE
    )

    disabled_app = _app(monkeypatch, shim_base_url=sentinel_shim_server, enabled=False)
    envelope = _make_envelope(tenant_id=tenant, violation_type=_VIOLATION_TYPE)
    resp = await _post_ingest(disabled_app, envelope)
    assert resp.status_code == 202, resp.text

    rows = await _executions_for_rule(rule["id"])
    matching = [r for r in rows if r["triggering_event_id"] == envelope["idempotency_key"]]
    assert matching == []  # the rule genuinely matches, but the master switch is off


async def test_non_matching_condition_never_produces_a_row(
    automation_ready,
    sentinel_shim_server,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    seed_query_token,
    monkeypatch,
):
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy("model_allowlist", tenant_id=tenant, allowed_model_ids=["gpt-4o"])
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    app = _app(monkeypatch, shim_base_url=sentinel_shim_server, enabled=True)
    token = await seed_query_token(tenant)
    # The rule requires violation_type == "prompt_injection"; the ingested event carries
    # "budget_cost_exceeded" — a genuine non-match.
    rule = await _create_rule(
        app, token=token, distribution_id=distribution_id, violation_type="prompt_injection"
    )

    envelope = _make_envelope(tenant_id=tenant, violation_type=_VIOLATION_TYPE)
    resp = await _post_ingest(app, envelope)
    assert resp.status_code == 202, resp.text

    rows = await _executions_for_rule(rule["id"])
    assert rows == []  # never fired — no row for a rule that never matched
