"""POST /admin/policies/intake — X-003 wire loop closure (F-008, ADR-0042).

DB-backed (admin package conftest provisions schema + sentinel_app; skips with
no DATABASE_URL/APP_DATABASE_URL, mirroring every other tests/admin/* module).

Drives the REAL mounted route on the real ASGI app (admin_app), reusing the
EXACT signing machinery tests/policy/conftest.py uses for F-008
(policy.crypto.generate_keypair / sign_policy_record) — no new signer invented.

Vectors:
  1  test_valid_signed_policy_accepted_and_persisted — 200 AdminPolicyIntakeAccepted,
     policy actually persisted (asserted via the repo/DB, not just the response).
  2  test_forged_signature_rejected                  — 403 policy_intake_signature_rejected.
  3  test_schema_invalid_body_rejected                — 422 policy_intake_schema_rejected.
  4  test_wildcard_tenant_rejected_as_scope_mismatch  — 409 policy_intake_scope_mismatch.
  5  test_replay_rejected                             — 409 policy_intake_replay_rejected.
  6  test_no_admin_auth_401                           — missing/invalid bearer -> 401.
  7  test_data_plane_key_cannot_reach                 — a tenant virtual key -> 401.
  8  test_sso_operator_forbidden                      — an SSO-operator-session -> 403
     (reject_sso_global; see admin/policies.py "SCOPE / AUTH DECISION").
  9  test_rejection_bodies_carry_no_record_content    — rejection bodies are exactly
     {error_code, message, request_id} — no policy_id / signature / disputed IDs.
  10 nothing persisted on ANY rejection path (asserted per-vector).
"""

from __future__ import annotations

import json
import os
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from persistence.models.policy import Policy
from policy import crypto

pytestmark = pytest.mark.asyncio

PLACEHOLDER_SIG = "aaaaaaaa.bbbbbbbb.cccccccc"
_WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


async def _seed_tenant() -> str:
    """Commit a bare tenant row (policies.tenant_id FK target only)."""
    engine = _priv_engine()
    tid = str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"x003-{tid[:8]}"},
            )
    finally:
        await engine.dispose()
    return tid


def _ids(tenant_id: str) -> dict[str, str]:
    return {
        "tenant_id": tenant_id,
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
    }


def _budget_record(tenant_id: str, **overrides) -> dict:
    rec = {
        "policy_type": "budget_limit",
        **_ids(tenant_id),
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": "2026-07-11T00:00:00Z",
        "signature": PLACEHOLDER_SIG,
        "period": "daily",
        "scope": "tenant",
        "max_tokens_per_period": 100000,
    }
    rec.update(overrides)
    return rec


@pytest.fixture()
def signing_keypair(tmp_path, monkeypatch):
    """A fresh ES256 keypair; POLICY_SIGNING_PUBKEY_PATH -> its public PEM.

    Reuses policy.crypto directly (the exact F-008 intake test machinery, see
    tests/policy/conftest.py::signing_keypair) — no new signer is invented here.
    Yields the PRIVATE key; intake_policy() verifies against the matching public
    key loaded from the env-pointed PEM.
    """
    private_key, public_key = crypto.generate_keypair()
    pub_path = tmp_path / "policy_pub.pem"
    pub_path.write_bytes(crypto.public_key_to_pem(public_key))
    monkeypatch.setenv("POLICY_SIGNING_PUBKEY_PATH", str(pub_path))
    crypto.reset_key_cache_for_testing()
    yield private_key
    crypto.reset_key_cache_for_testing()


async def _policy_row(tenant_id: str, policy_id: str) -> Policy | None:
    engine = _priv_engine()
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                select(
                    Policy.policy_id, Policy.tenant_id, Policy.current_version, Policy.policy_type
                ).where(Policy.policy_id == policy_id)
            )
            row = result.first()
            return row
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# 1. Accept path — real end-to-end intake over the mounted route.
# ---------------------------------------------------------------------------


async def test_valid_signed_policy_accepted_and_persisted(
    admin_app, admin_auth_headers, signing_keypair, truncate_audit_log_after
):
    tenant_id = await _seed_tenant()
    record = crypto.sign_policy_record(_budget_record(tenant_id), signing_keypair)
    raw = json.dumps(record).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "status": "accepted",
        "policy_id": record["policy_id"],
        "policy_version": 1,
        "policy_type": "budget_limit",
    }
    assert "X-Request-Id" in r.headers

    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is not None, "accepted policy was not persisted"
    assert row.tenant_id == tenant_id
    assert row.current_version == 1
    assert row.policy_type == "budget_limit"


# ---------------------------------------------------------------------------
# 2. Forged / unverifiable signature -> 403.
# ---------------------------------------------------------------------------


async def test_forged_signature_rejected(admin_app, admin_auth_headers, signing_keypair):
    """A record signed by a DIFFERENT keypair than the configured verifying key —
    a well-formed compact-JWS whose signature does not verify (forged/untrusted
    signer), the realistic "someone signed this, but not Delta/Orchestrator" case.

    NOTE: does NOT use the malformed PLACEHOLDER_SIG here — its base64url segments
    decode to non-UTF-8 bytes, which crypto.verify_compact_jws's json.loads() does
    not catch as CompactJWSError (a pre-existing, out-of-scope latent defect in
    policy/crypto.py this route/tests must not mask or touch). A real-but-untrusted
    signature exercises the SAME RejectedSignature outcome this route maps to 403,
    without depending on that separate defect.
    """
    tenant_id = str(uuid.uuid4())  # no need to seed — rejected before persist
    untrusted_private_key, _ = crypto.generate_keypair()
    record = crypto.sign_policy_record(_budget_record(tenant_id), untrusted_private_key)
    raw = json.dumps(record).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 403, r.text
    assert r.json()["error_code"] == "policy_intake_signature_rejected"
    assert r.json()["message"] == "The signed policy record signature could not be verified."

    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is None, "a forged-signature record must never be persisted"


# ---------------------------------------------------------------------------
# 2b. Signature segment that decodes to invalid UTF-8 -> clean, audited 403
#     (not an uncaught 500). Regression for the X-003 security-audit Low finding:
#     crypto.verify_compact_jws decodes the JWS header BEFORE verifying, and a
#     base64url segment decoding to non-UTF-8 raised UnicodeDecodeError, which the
#     intake pipeline did not classify — so the new wire ingress returned 500 with
#     no rejection audit event. intake_policy() now maps UnicodeDecodeError to
#     RejectedSignature, so this route returns the contract's 403 + audits it.
# ---------------------------------------------------------------------------


async def test_non_utf8_signature_segment_rejected_as_signature(
    admin_app, admin_auth_headers, signing_keypair
):
    """A record whose signature segments decode to non-UTF-8 bytes (the malformed
    PLACEHOLDER_SIG, e.g. "aaaaaaaa" -> 0x69a69a...) is a malformed signature, not
    an internal fault: the route must return 403 policy_intake_signature_rejected
    (never 500) and persist nothing."""
    tenant_id = str(uuid.uuid4())  # rejected before persist — no seed needed
    record = _budget_record(tenant_id)  # default signature is the non-UTF-8 PLACEHOLDER_SIG
    raw = json.dumps(record).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 403, r.text
    assert r.json()["error_code"] == "policy_intake_signature_rejected"
    assert r.json()["message"] == "The signed policy record signature could not be verified."
    assert set(r.json().keys()) == {"error_code", "message", "request_id"}

    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is None, "a malformed-signature record must never be persisted"


# ---------------------------------------------------------------------------
# 3. Schema-invalid body -> 422.
# ---------------------------------------------------------------------------


async def test_schema_invalid_body_rejected(admin_app, admin_auth_headers, signing_keypair):
    tenant_id = str(uuid.uuid4())
    record = _budget_record(tenant_id)
    del record["period"]  # required by BudgetLimitPolicy (sentinel:policy:v1)
    signed = crypto.sign_policy_record(record, signing_keypair)
    raw = json.dumps(signed).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 422, r.text
    assert r.json()["error_code"] == "policy_intake_schema_rejected"
    assert r.json()["message"] == "The signed policy record failed schema validation."

    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is None


# ---------------------------------------------------------------------------
# 4. Wildcard tenant (a scope-mismatch variant, IntakeResult.RejectedScopeMismatch)
#    -> 409 policy_intake_scope_mismatch.
# ---------------------------------------------------------------------------


async def test_wildcard_tenant_rejected_as_scope_mismatch(
    admin_app, admin_auth_headers, signing_keypair
):
    record = _budget_record(_WILDCARD_UUID)
    signed = crypto.sign_policy_record(record, signing_keypair)
    raw = json.dumps(signed).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 409, r.text
    assert r.json()["error_code"] == "policy_intake_scope_mismatch"
    assert r.json()["message"] == "The signed policy scope does not match the record body."

    row = await _policy_row(_WILDCARD_UUID, record["policy_id"])
    assert row is None, "a wildcard-tenant record must never be persisted"


# ---------------------------------------------------------------------------
# 5. Replay/rollback -> 409 policy_intake_replay_rejected.
# ---------------------------------------------------------------------------


async def test_replay_rejected(
    admin_app, admin_auth_headers, signing_keypair, truncate_audit_log_after
):
    tenant_id = await _seed_tenant()
    policy_id = str(uuid.uuid4())

    v2 = crypto.sign_policy_record(
        _budget_record(tenant_id, policy_id=policy_id, policy_version=2), signing_keypair
    )
    async with _client(admin_app) as client:
        first = await client.post(
            "/admin/policies/intake",
            content=json.dumps(v2).encode("utf-8"),
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )
        assert first.status_code == 200, first.text

        # Replay the SAME version — not strictly greater than the stored max.
        replay = crypto.sign_policy_record(
            _budget_record(tenant_id, policy_id=policy_id, policy_version=2), signing_keypair
        )
        r = await client.post(
            "/admin/policies/intake",
            content=json.dumps(replay).encode("utf-8"),
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 409, r.text
    assert r.json()["error_code"] == "policy_intake_replay_rejected"
    assert (
        r.json()["message"]
        == "The policy version is not newer than the stored version (replay/rollback)."
    )

    row = await _policy_row(tenant_id, policy_id)
    assert row is not None
    assert row.current_version == 2  # unchanged by the rejected replay


# ---------------------------------------------------------------------------
# 6/7/8. Auth: no admin auth -> 401; data-plane virtual key -> 401;
#    SSO-operator-session -> 403 (reject_sso_global, admin/policies.py).
# ---------------------------------------------------------------------------


async def test_no_admin_auth_401(admin_app, signing_keypair):
    record = crypto.sign_policy_record(_budget_record(str(uuid.uuid4())), signing_keypair)
    raw = json.dumps(record).encode("utf-8")

    async with _client(admin_app) as client:
        no_header = await client.post(
            "/admin/policies/intake", content=raw, headers={"Content-Type": "application/json"}
        )
        bad_token = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={"Authorization": "Bearer not-the-token", "Content-Type": "application/json"},
        )

    assert no_header.status_code == 401, no_header.text
    assert bad_token.status_code == 401, bad_token.text

    row = await _policy_row(record["tenant_id"], record["policy_id"])
    assert row is None


async def test_data_plane_key_cannot_reach(admin_app, admin_auth_headers, signing_keypair):
    """A tenant virtual API key (the data-plane credential) gets 401 here too —
    require_admin never accepts a tenant key, regardless of route."""
    tenant_id = await _seed_tenant()
    async with _client(admin_app) as client:
        # Seed team/project so a virtual key can be minted for this tenant.
        team_id, project_id = str(uuid.uuid4()), str(uuid.uuid4())
        engine = _priv_engine()
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                        "VALUES (:tm, :t, :n, true)"
                    ),
                    {"tm": team_id, "t": tenant_id, "n": f"team-{team_id[:8]}"},
                )
                await conn.execute(
                    text(
                        "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                        "VALUES (:p, :tm, :t, :n, true)"
                    ),
                    {"p": project_id, "tm": team_id, "t": tenant_id, "n": f"proj-{project_id[:8]}"},
                )
        finally:
            await engine.dispose()

        secret = (
            await client.post(
                f"/admin/tenants/{tenant_id}/keys",
                json={"team_id": team_id, "project_id": project_id, "agent_id": "gateway-core"},
                headers=admin_auth_headers,
            )
        ).json()["secret"]

        record = crypto.sign_policy_record(_budget_record(tenant_id), signing_keypair)
        r = await client.post(
            "/admin/policies/intake",
            content=json.dumps(record).encode("utf-8"),
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
        )

    assert r.status_code == 401, r.text
    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is None


async def test_sso_operator_forbidden(
    admin_app, operator_session_headers, signing_keypair, truncate_audit_log_after
):
    """An SSO-operator-session is authenticated (require_admin) but not authorized
    here (reject_sso_global) — this route is inherently cross-tenant (the
    authoritative tenant is resolved from the signature, not a path param), so it
    follows the SAME break-glass-only invariant as the global tenant-registry
    routes (admin/scope.py::reject_sso_global, ADR-0017 §3 D2.5)."""
    tenant_id = await _seed_tenant()
    headers = operator_session_headers(tenant_id=tenant_id, role="tenant_admin")
    record = crypto.sign_policy_record(_budget_record(tenant_id), signing_keypair)

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=json.dumps(record).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 403, r.text
    row = await _policy_row(tenant_id, record["policy_id"])
    assert row is None


# ---------------------------------------------------------------------------
# 9. Rejection bodies never carry record content / signature bytes / disputed IDs.
# ---------------------------------------------------------------------------


async def test_rejection_bodies_carry_no_record_content(
    admin_app, admin_auth_headers, signing_keypair
):
    tenant_id = str(uuid.uuid4())
    untrusted_private_key, _ = crypto.generate_keypair()
    # Signed by an untrusted key (see test_forged_signature_rejected) -> signature rejection.
    record = crypto.sign_policy_record(_budget_record(tenant_id), untrusted_private_key)
    raw = json.dumps(record).encode("utf-8")

    async with _client(admin_app) as client:
        r = await client.post(
            "/admin/policies/intake",
            content=raw,
            headers={**admin_auth_headers, "Content-Type": "application/json"},
        )

    assert r.status_code == 403, r.text
    body = r.json()
    # EXACTLY the standard Error envelope — no extra keys leaking record content.
    assert set(body.keys()) == {"error_code", "message", "request_id"}
    serialized = json.dumps(body)
    assert tenant_id not in serialized
    assert record["policy_id"] not in serialized
    assert record["signature"] not in serialized
