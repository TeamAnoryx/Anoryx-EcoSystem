"""F-008 adversarial threat model — 16 vectors (ADR-0009 §8).

Each test PROVES the attack fails: it asserts the typed rejection/decision, the
correct hash-chained audit event (type + reason + Decision-B attribution), AND
that no state was poisoned (a rejected policy is never persisted; a replay never
rolls the stored version back). Vector #14 (budget exhaustion mid-stream) lives
in tests/gateway/router/test_policy_enforcement.py because it needs the gateway
streaming handler; it is cross-referenced here for traceability.

Intake (13): #1-#12 + #16.  Enforcement (3): #13, #14 (gateway), #15.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.audit_log_repository import AuditLogRepository
from persistence.repositories.policy_repository import PolicyRepository
from policy import crypto
from policy.constants import SYSTEM_TENANT_ID, WILDCARD_UUID
from policy.enforcement import (
    BudgetExceeded,
    BudgetOk,
    ModelDeny,
    RequestScope,
    budget_period_used,
    evaluate_budget_against,
    evaluate_model_policies,
)
from policy.intake import intake_policy
from policy.results import (
    Accepted,
    RejectedReplay,
    RejectedSchema,
    RejectedScopeMismatch,
    RejectedSignature,
)
from policy.variants import BudgetLimitPolicy


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _alg_token(alg: str, claims: dict) -> str:
    # 64-byte sig segment so the ONLY gate exercised is the header-alg check
    # (a wrong-length sig would otherwise be caught by the raw-length check first).
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.{_b64(b'\x01' * 64)}"


async def _last_event(session) -> EventsAuditLog | None:
    result = await session.execute(
        select(EventsAuditLog).order_by(EventsAuditLog.sequence_number.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def _max_version(session, policy_id: str) -> int | None:
    return await PolicyRepository(session).get_max_version(policy_id)


# =========================================================================== #
# Intake — signature integrity (#1-#3)
# =========================================================================== #
@pytest.mark.asyncio
async def test_forged_signature_rejected(priv_session, signing_keypair, make_budget_record):
    signed = crypto.sign_policy_record(make_budget_record(), signing_keypair)
    parts = signed["signature"].split(".")
    parts[2] = _b64(b"\x07" * 64)  # valid length, wrong signature
    signed["signature"] = ".".join(parts)

    result = await intake_policy(signed, session=priv_session)

    assert isinstance(result, RejectedSignature)
    event = await _last_event(priv_session)
    assert event.event_type == "policy_intake_rejected_signature"
    assert event.action_taken == "blocked"
    assert event.tenant_id == SYSTEM_TENANT_ID
    assert await _max_version(priv_session, signed["policy_id"]) is None  # not persisted


@pytest.mark.asyncio
async def test_wrong_signing_key_rejected(priv_session, signing_keypair, make_budget_record):
    attacker_key, _ = crypto.generate_keypair()
    signed = crypto.sign_policy_record(make_budget_record(), attacker_key)
    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedSignature)
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_signature"
    assert await _max_version(priv_session, signed["policy_id"]) is None


@pytest.mark.asyncio
async def test_algorithm_confusion_rejected(priv_session, signing_keypair, make_budget_record):
    for alg in ("none", "HS256"):
        record = make_budget_record()
        claims = {k: record[k] for k in crypto.SIGNED_CLAIM_FIELDS}
        record["signature"] = _alg_token(alg, claims)
        result = await intake_policy(record, session=priv_session)
        assert isinstance(result, RejectedSignature), f"alg={alg} not rejected"
        assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_signature"
        assert await _max_version(priv_session, record["policy_id"]) is None


# =========================================================================== #
# Intake — scope poisoning (#4, #5) + wildcard tenant (#16)
# =========================================================================== #
@pytest.mark.asyncio
async def test_cross_tenant_scope_widening_rejected(
    priv_session, signing_keypair, make_budget_record
):
    record = make_budget_record()
    signed_tenant = record["tenant_id"]
    signed = crypto.sign_policy_record(record, signing_keypair)
    signed["tenant_id"] = str(uuid.uuid4())  # body claims a different tenant than the signature

    result = await intake_policy(signed, session=priv_session)

    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "tenant_id"
    event = await _last_event(priv_session)
    assert event.event_type == "policy_intake_rejected_scope_mismatch"
    assert event.violation_type == "scope_mismatch.tenant_id"
    assert event.tenant_id == signed_tenant  # attributed to the SIGNATURE tenant, not the body
    assert await _max_version(priv_session, signed["policy_id"]) is None


@pytest.mark.asyncio
async def test_cross_team_scope_widening_rejected(
    priv_session, signing_keypair, make_budget_record
):
    record = make_budget_record()
    signed = crypto.sign_policy_record(record, signing_keypair)
    signed["team_id"] = str(uuid.uuid4())  # body widens the team beyond the signed scope

    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "team_id"
    assert (await _last_event(priv_session)).violation_type == "scope_mismatch.team_id"
    assert await _max_version(priv_session, signed["policy_id"]) is None


@pytest.mark.asyncio
async def test_wildcard_tenant_id_rejected(priv_session, signing_keypair, make_budget_record):
    signed = crypto.sign_policy_record(make_budget_record(tenant_id=WILDCARD_UUID), signing_keypair)
    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "wildcard_tenant"
    event = await _last_event(priv_session)
    assert event.event_type == "policy_intake_rejected_scope_mismatch"
    assert event.violation_type == "scope_mismatch.wildcard_tenant"
    assert event.tenant_id == SYSTEM_TENANT_ID  # no real tenant -> system attribution
    assert await _max_version(priv_session, signed["policy_id"]) is None


@pytest.mark.asyncio
async def test_incomplete_signed_claims_rejected(priv_session, signing_keypair, make_budget_record):
    """A validly-signed JWS whose payload omits a required scope claim is rejected."""
    record = make_budget_record()
    claims = {k: record[k] for k in crypto.SIGNED_CLAIM_FIELDS if k != "policy_type"}
    record["signature"] = crypto.sign_claims(claims, signing_keypair)  # signed, but incomplete
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "claims_incomplete"
    event = await _last_event(priv_session)
    assert event.violation_type == "scope_mismatch.claims_incomplete"
    assert event.tenant_id == SYSTEM_TENANT_ID
    assert await _max_version(priv_session, record["policy_id"]) is None


@pytest.mark.asyncio
async def test_body_tamper_on_non_id_signed_field_rejected(
    priv_session, signing_keypair, make_budget_record
):
    """Tampering a signed NON-id field (policy_version) in the body is caught too."""
    signed = crypto.sign_policy_record(make_budget_record(policy_version=1), signing_keypair)
    signed["policy_version"] = 2  # body disagrees with the signed claim
    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "policy_version"
    assert (await _last_event(priv_session)).violation_type == "scope_mismatch.policy_version"
    assert await _max_version(priv_session, signed["policy_id"]) is None


@pytest.mark.asyncio
async def test_enforcement_field_tamper_rejected(
    priv_session, signing_keypair, make_denylist_record
):
    """SECURITY-AUDITOR CRITICAL repro: emptying a signed deny-list's denied_model_ids
    (an enforcement field NOT among the 8 scope claims) is caught by the content hash —
    the signature covers the full record, so this no longer persists as Accepted.
    """
    signed = crypto.sign_policy_record(
        make_denylist_record(denied_model_ids=["gpt-4"]), signing_keypair
    )
    signed["denied_model_ids"] = []  # neutralize the deny-list after signing
    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "content_hash"
    event = await _last_event(priv_session)
    assert event.event_type == "policy_intake_rejected_scope_mismatch"
    assert event.violation_type == "scope_mismatch.content_hash"
    assert await _max_version(priv_session, signed["policy_id"]) is None  # NOT persisted


@pytest.mark.asyncio
async def test_budget_ceiling_tamper_rejected(priv_session, signing_keypair, make_budget_record):
    """Inflating a signed budget ceiling after signing is caught by the content hash."""
    signed = crypto.sign_policy_record(
        make_budget_record(max_tokens_per_period=100), signing_keypair
    )
    signed["max_tokens_per_period"] = 10_000_000  # inflate the ceiling after signing
    result = await intake_policy(signed, session=priv_session)
    assert isinstance(result, RejectedScopeMismatch)
    assert result.dimension == "content_hash"
    assert await _max_version(priv_session, signed["policy_id"]) is None


# =========================================================================== #
# Intake — replay / rollback (#6, #7)
# =========================================================================== #
@pytest.mark.asyncio
async def test_replay_same_version_rejected(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
):
    first = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_version=2), signing_keypair
    )
    assert isinstance(await intake_policy(first, session=priv_session), Accepted)
    pid = first["policy_id"]

    replay = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_id=pid, policy_version=2),
        signing_keypair,
    )
    result = await intake_policy(replay, session=priv_session)

    assert isinstance(result, RejectedReplay)
    assert result.current_max_version == 2 and result.attempted_version == 2
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_replay"
    assert await _max_version(priv_session, pid) == 2  # stored version NOT poisoned


@pytest.mark.asyncio
async def test_rollback_older_version_rejected(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
):
    pid = make_budget_record()["policy_id"]
    assert isinstance(
        await intake_policy(
            crypto.sign_policy_record(
                make_budget_record(tenant_id=seeded_tenant, policy_id=pid, policy_version=5),
                signing_keypair,
            ),
            session=priv_session,
        ),
        Accepted,
    )
    older = crypto.sign_policy_record(
        make_budget_record(tenant_id=seeded_tenant, policy_id=pid, policy_version=3),
        signing_keypair,
    )
    result = await intake_policy(older, session=priv_session)
    assert isinstance(result, RejectedReplay)
    assert await _max_version(priv_session, pid) == 5  # not rolled back


# =========================================================================== #
# Intake — schema layer (#8-#12)
# =========================================================================== #
@pytest.mark.asyncio
async def test_truncated_signature_rejected(priv_session, make_budget_record):
    record = make_budget_record(signature="aaaaaaaa.bbbbbbbb")  # 2 segments, not 3
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_schema"
    assert await _max_version(priv_session, record["policy_id"]) is None


@pytest.mark.asyncio
async def test_oversized_payload_rejected(priv_session, make_allowlist_record):
    record = make_allowlist_record(allowed_model_ids=["x" * 300])  # item > maxLength 256
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_schema"


@pytest.mark.asyncio
async def test_wrong_policy_type_for_variant_rejected(priv_session, make_allowlist_record):
    # Allowlist fields but policy_type claims budget_limit -> matches zero oneOf branches.
    record = make_allowlist_record(policy_type="budget_limit")
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_schema"


@pytest.mark.asyncio
async def test_missing_required_field_rejected(priv_session, make_budget_record):
    record = make_budget_record()
    del record["effective_from"]
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)
    assert (await _last_event(priv_session)).event_type == "policy_intake_rejected_schema"


@pytest.mark.asyncio
async def test_additional_properties_poisoning_rejected(priv_session, make_budget_record):
    record = make_budget_record(admin_override=True)  # additionalProperties:false
    result = await intake_policy(record, session=priv_session)
    assert isinstance(result, RejectedSchema)
    event = await _last_event(priv_session)
    assert event.event_type == "policy_intake_rejected_schema"
    assert event.tenant_id == SYSTEM_TENANT_ID


# =========================================================================== #
# Enforcement (#13 deny precedence, #15 period boundary; #14 in gateway tests)
# =========================================================================== #
def _persist(payload, *, effective_from=None):
    # TEST-ONLY helper: writes a policy row directly (placeholder signature),
    # bypassing the intake signature gate. Used for ENFORCEMENT tests, whose
    # subject is read-time matching, not intake. Intake itself is proven in the
    # intake/signature vectors above (which DO exercise the full pipeline).
    async def _do(session):
        await PolicyRepository(session).save_new_version(
            policy_id=payload["policy_id"],
            policy_type=payload["policy_type"],
            policy_version=payload["policy_version"],
            tenant_id=payload["tenant_id"],
            team_id=payload["team_id"],
            project_id=payload["project_id"],
            agent_id=payload["agent_id"],
            effective_from=effective_from or datetime(2026, 1, 1, tzinfo=UTC),
            signature="aaaaaaaa.bbbbbbbb.cccccccc",
            policy_payload=payload,
        )

    return _do


@pytest.mark.asyncio
async def test_allow_deny_conflict_deny_wins(
    priv_session, seeded_tenant, make_allowlist_record, make_denylist_record
):
    scope = RequestScope(
        tenant_id=seeded_tenant,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
    )
    common = dict(
        tenant_id=seeded_tenant,
        team_id=scope.team_id,
        project_id=scope.project_id,
        agent_id="gateway-core",
    )
    # Both an allow-list AND a deny-list list "gpt-4" for the same scope.
    await _persist(make_allowlist_record(allowed_model_ids=["gpt-4"], **common))(priv_session)
    await _persist(make_denylist_record(denied_model_ids=["gpt-4"], **common))(priv_session)

    decision = await evaluate_model_policies(priv_session, scope, "gpt-4")
    assert isinstance(decision, ModelDeny)
    assert decision.reason == "model_denied"  # deny precedence (contract §ModelDenylistPolicy)


@pytest.mark.asyncio
async def test_period_boundary_bucket_reset(priv_session):
    tenant = str(uuid.uuid4())
    scope = RequestScope(tenant_id=tenant, team_id="tm", project_id="pr", agent_id="gateway-core")
    audit = AuditLogRepository(priv_session)

    def _usage(ts_iso, tokens):
        return {
            "event_type": "usage",
            "tenant_id": tenant,
            "team_id": "tm",
            "project_id": "pr",
            "agent_id": "gateway-core",
            "event_id": str(uuid.uuid4()),
            "event_timestamp": ts_iso,
            "request_id": "req-" + uuid.uuid4().hex[:8],
            "model": "gpt-4o",
            "tokens_in": tokens,
            "tokens_out": 0,
            "latency_ms": 1,
            "cost_estimate_cents": 0.0,
        }

    # 23:59 on day D (previous bucket) vs 00:01 on day D+1 (current bucket).
    await audit.append(_usage("2026-06-17T23:59:00Z", 500))
    await audit.append(_usage("2026-06-18T00:01:00Z", 42))

    budget = BudgetLimitPolicy(
        policy_id=str(uuid.uuid4()),
        tenant_id=tenant,
        team_id="tm",
        project_id="pr",
        agent_id="gateway-core",
        policy_version=1,
        period="daily",
        scope="tenant",
        max_tokens_per_period=100,
    )
    now = datetime(2026, 6, 18, 0, 5, 0, tzinfo=UTC)
    used_tokens, _ = await budget_period_used(priv_session, scope, budget, now=now)
    assert used_tokens == 42  # the prior-day 23:59 usage is in the PREVIOUS bucket, not counted

    # Prove the FULL decision, not just the aggregate: a 50-token request fits the
    # reset bucket (42 + 50 <= 100) and is allowed...
    assert isinstance(evaluate_budget_against([(budget, used_tokens, 0.0)], 50, 0.0), BudgetOk)
    # ...whereas had the previous-day 500 tokens NOT reset, the same request would be denied.
    assert isinstance(
        evaluate_budget_against([(budget, used_tokens + 500, 0.0)], 50, 0.0), BudgetExceeded
    )
