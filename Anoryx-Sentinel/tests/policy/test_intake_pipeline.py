"""Intake pipeline paths beyond signatures: schema, replay/rollback, parsing,
and the own-session wrapper (ADR-0009 §3). Each rejection asserts its audit event.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from persistence.models.events_audit_log import EventsAuditLog
from policy import crypto
from policy import intake as intake_mod
from policy.constants import SYSTEM_TENANT_ID
from policy.intake import intake_policy
from policy.results import Accepted, RejectedReplay, RejectedSchema


async def _last_event(session) -> EventsAuditLog | None:
    result = await session.execute(
        select(EventsAuditLog).order_by(EventsAuditLog.sequence_number.desc()).limit(1)
    )
    return result.scalar_one_or_none()


@pytest.mark.asyncio
async def test_missing_required_field_rejected(priv_session, make_budget_record) -> None:
    """Schema gate runs before signature; a missing required field is RejectedSchema."""
    record = make_budget_record()
    del record["period"]  # required by BudgetLimitPolicy
    result = await intake_policy(record, session=priv_session)

    assert isinstance(result, RejectedSchema)
    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_rejected_schema"
    assert event.action_taken == "blocked"
    assert event.tenant_id == SYSTEM_TENANT_ID  # no signature parsed -> system tenant


@pytest.mark.asyncio
async def test_additional_property_poisoning_rejected(priv_session, make_budget_record) -> None:
    record = make_budget_record(admin_override=True)  # additionalProperties:false
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)


@pytest.mark.asyncio
async def test_non_object_record_rejected(priv_session) -> None:
    result = await intake_policy("[]", session=priv_session)
    assert isinstance(result, RejectedSchema)


@pytest.mark.asyncio
async def test_replay_same_version_rejected(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
) -> None:
    first = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_version=2), signing_keypair
    )
    accepted = await intake_policy(first, session=priv_session)
    assert isinstance(accepted, Accepted)

    replay = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_id=first["policy_id"], policy_version=2),
        signing_keypair,
    )
    result = await intake_policy(replay, session=priv_session)

    assert isinstance(result, RejectedReplay)
    assert result.current_max_version == 2
    assert result.attempted_version == 2
    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_rejected_replay"
    assert event.policy_id == first["policy_id"]


@pytest.mark.asyncio
async def test_rollback_older_version_rejected(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
) -> None:
    pid = make_budget_record()["policy_id"]
    v5 = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_id=pid, policy_version=5),
        signing_keypair,
    )
    assert isinstance(await intake_policy(v5, session=priv_session), Accepted)

    v3 = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_id=pid, policy_version=3),
        signing_keypair,
    )
    result = await intake_policy(v3, session=priv_session)
    assert isinstance(result, RejectedReplay)
    assert result.current_max_version == 5
    assert result.attempted_version == 3


@pytest.mark.asyncio
async def test_bytes_input_accepted(
    priv_session, signing_keypair, make_allowlist_record, seeded_tenant
) -> None:
    record = crypto.sign_policy_record(
        make_allowlist_record(tenant_id=seeded_tenant), signing_keypair
    )
    raw = json.dumps(record).encode("utf-8")
    result = await intake_policy(raw, session=priv_session)
    assert isinstance(result, Accepted)
    assert result.policy_type == "model_allowlist"


@pytest.mark.asyncio
async def test_intake_opens_own_session_when_not_injected(monkeypatch) -> None:
    """The public no-session path opens a privileged session + transaction itself."""
    seen: dict[str, object] = {}

    @asynccontextmanager
    async def fake_get_privileged_session():
        session = MagicMock(name="own_session")

        @asynccontextmanager
        async def _begin():
            seen["began"] = True
            yield

        session.begin = _begin
        seen["session"] = session
        yield session

    async def fake_run_intake(record_json, session):
        seen["ran_with"] = session
        return RejectedSchema("stub")

    monkeypatch.setattr(intake_mod, "get_privileged_session", fake_get_privileged_session)
    monkeypatch.setattr(intake_mod, "_run_intake", fake_run_intake)

    result = await intake_policy({"any": "thing"})

    assert isinstance(result, RejectedSchema)
    assert seen.get("began") is True
    assert seen["ran_with"] is seen["session"]
