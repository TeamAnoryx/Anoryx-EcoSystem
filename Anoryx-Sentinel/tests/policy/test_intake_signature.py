"""Intake signature + scope vectors (ADR-0009 §3; threat vectors 1-4, 16).

Each test asserts the typed result AND (for representative paths) the audit row's
event_type, action_taken, and Decision-B tenant attribution. The priv_session
SAVEPOINT rolls everything back, so sentinel_dev is never polluted.
"""

from __future__ import annotations

import base64
import json

import pytest
from sqlalchemy import select

from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.policy_repository import PolicyRepository
from policy import crypto
from policy.constants import SYSTEM_TENANT_ID, WILDCARD_UUID
from policy.intake import intake_policy
from policy.results import Accepted, RejectedScopeMismatch, RejectedSignature


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _token(alg: str, claims: dict, sig: bytes = b"\x01" * 8) -> str:
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.{_b64(sig)}"


async def _last_event(session) -> EventsAuditLog | None:
    result = await session.execute(
        select(EventsAuditLog).order_by(EventsAuditLog.sequence_number.desc()).limit(1)
    )
    return result.scalar_one_or_none()


@pytest.mark.asyncio
async def test_valid_budget_accepted(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
) -> None:
    record = crypto.sign_policy_record(make_budget_record(tenant_id=seeded_tenant), signing_keypair)
    result = await intake_policy(record, session=priv_session)

    assert isinstance(result, Accepted)
    assert result.policy_id == record["policy_id"]
    assert result.policy_version == 1
    assert result.policy_type == "budget_limit"

    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_accepted"
    assert event.action_taken == "logged"
    assert event.tenant_id == record["tenant_id"]  # signature-resolved tenant
    assert event.policy_id == record["policy_id"]


@pytest.mark.asyncio
async def test_forged_signature_rejected(priv_session, signing_keypair, make_budget_record) -> None:
    signed = crypto.sign_policy_record(make_budget_record(), signing_keypair)
    parts = signed["signature"].split(".")
    parts[2] = _b64(b"\x02" * 64)  # valid length, wrong signature
    signed["signature"] = ".".join(parts)

    result = await intake_policy(signed, session=priv_session)

    assert isinstance(result, RejectedSignature)
    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_rejected_signature"
    assert event.action_taken == "blocked"
    # No resolvable tenant -> system-tenant attribution (Decision B case 2).
    assert event.tenant_id == SYSTEM_TENANT_ID


@pytest.mark.asyncio
async def test_wrong_signing_key_rejected(
    priv_session, signing_keypair, make_budget_record
) -> None:
    other_priv, _ = crypto.generate_keypair()  # not the key behind POLICY_SIGNING_PUBKEY_PATH
    record = crypto.sign_policy_record(make_budget_record(), other_priv)
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSignature)


@pytest.mark.asyncio
async def test_alg_none_rejected(priv_session, signing_keypair, make_budget_record) -> None:
    record = make_budget_record()
    claims = {k: record[k] for k in crypto.SIGNED_CLAIM_FIELDS}
    record["signature"] = _token("none", claims)
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSignature)


@pytest.mark.asyncio
async def test_alg_hs256_rejected(priv_session, signing_keypair, make_budget_record) -> None:
    record = make_budget_record()
    claims = {k: record[k] for k in crypto.SIGNED_CLAIM_FIELDS}
    record["signature"] = _token("HS256", claims)
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSignature)


@pytest.mark.asyncio
async def test_no_verifying_key_fail_closed(priv_session, make_budget_record, monkeypatch) -> None:
    """Env unset => no key => every intake fails closed with RejectedSignature."""
    priv, _ = crypto.generate_keypair()
    record = crypto.sign_policy_record(make_budget_record(), priv)
    monkeypatch.delenv("POLICY_SIGNING_PUBKEY_PATH", raising=False)
    crypto.reset_key_cache_for_testing()
    try:
        result = await intake_policy(record, session=priv_session)
    finally:
        crypto.reset_key_cache_for_testing()
    assert isinstance(result, RejectedSignature)


@pytest.mark.asyncio
async def test_cross_tenant_scope_widening_rejected(
    priv_session, signing_keypair, make_budget_record
) -> None:
    """Sign for tenant A, then swap the body tenant_id to B -> scope mismatch."""
    import uuid

    record = make_budget_record()
    signed_tenant = record["tenant_id"]
    signed = crypto.sign_policy_record(record, signing_keypair)
    signed["tenant_id"] = str(uuid.uuid4())  # body now disagrees with signed claims

    result = await intake_policy(signed, session=priv_session)

    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "tenant_id"
    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_rejected_scope_mismatch"
    assert event.violation_type == "scope_mismatch.tenant_id"
    # Attributed to the signature-resolved tenant (Decision B case 3), NOT the body.
    assert event.tenant_id == signed_tenant


@pytest.mark.asyncio
async def test_wildcard_tenant_id_rejected(
    priv_session, signing_keypair, make_budget_record
) -> None:
    """Threat #16: a signature whose tenant_id is the wildcard is hard-rejected."""
    record = make_budget_record(tenant_id=WILDCARD_UUID)
    signed = crypto.sign_policy_record(record, signing_keypair)

    result = await intake_policy(signed, session=priv_session)

    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "wildcard_tenant"
    event = await _last_event(priv_session)
    assert event is not None
    assert event.event_type == "policy_intake_rejected_scope_mismatch"
    assert event.violation_type == "scope_mismatch.wildcard_tenant"
    assert event.tenant_id == SYSTEM_TENANT_ID


@pytest.mark.asyncio
async def test_audit_append_failure_on_accept_rolls_back_policy(
    priv_session, signing_keypair, make_budget_record, seeded_tenant, monkeypatch
) -> None:
    """Accept-path atomicity: if the audit append fails, the policy INSERT rolls
    back with it — an unauditable accept must NOT persist (ADR-0009 §7; F-004 parity).

    The accept path does save_new_version + append_policy_event in ONE caller-owned
    transaction (intake.py step 7). We force the audit append to raise and prove the
    exception propagates (not swallowed) AND that no policy row survives the rollback.
    """

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated audit-log append failure")

    monkeypatch.setattr("policy.intake.append_policy_event", _boom)

    record = crypto.sign_policy_record(make_budget_record(tenant_id=seeded_tenant), signing_keypair)

    # Wrap in our own SAVEPOINT so the failed accept (INSERT + raising append) can be
    # rolled back atomically before we assert non-persistence within this transaction.
    savepoint = await priv_session.begin_nested()
    with pytest.raises(RuntimeError, match="simulated audit-log append failure"):
        await intake_policy(record, session=priv_session)
    await savepoint.rollback()

    # The policy INSERT was undone with the failed audit write — never persisted.
    max_version = await PolicyRepository(priv_session).get_max_version(record["policy_id"])
    assert max_version is None
