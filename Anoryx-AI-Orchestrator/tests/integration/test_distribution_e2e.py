"""Non-stubbed allow + deny distribution e2e (O-004, ADR-0004) — the acceptance gate.

Proves the WHOLE policy-distribution path with NOTHING stubbed on the distribution call:
a real signed policy is distributed by the Orchestrator's REAL engine over real httpx → a
real loopback socket → a uvicorn app serving Sentinel's REAL admin policy-intake route
(X-003, ADR-0042: POST /admin/policies/intake on the real admin_router, gated by the real
require_admin / reject_sso_global auth), which hands the byte-identical body to Sentinel's
REAL intake_policy(), verifies the ES256 signature UNCHANGED, and persists the policy; then
Sentinel's REAL enforcement (evaluate_model_policies) returns ALLOW for an allow policy and
DENY for a deny policy.

  * ALLOW: distribute a model_allowlist → orchestrator target+parent == "distributed";
           GET status reflects it; the persisted signature is byte-identical (verify
           unchanged); Sentinel enforcement ALLOWs the listed model and DENYs an unlisted one.
  * DENY:  distribute a model_denylist → "distributed"; Sentinel enforcement DENYs the
           denied model.
  * SUBMIT path: POST /v1/policies/distributions → 202; the FastAPI BackgroundTask drives the
           REAL distribution (httpx ASGITransport runs background tasks synchronously), so on
           return the distribution is settled "distributed" and Sentinel enforces it — the
           full HTTP submit → distribute → intake → enforce path, nothing stubbed.
  * FORGED (threat T1): a tampered signature → Sentinel rejects (permanent 4xx) → target +
           parent == "failed" (no retry storm); the forged policy is NOT persisted.

REAL-ROUTE proofs (X-003, ADR-0042) — assertions that could ONLY pass against Sentinel's
actual production route + real auth, distinguishing it from the old hand-rolled shim (which
did its own bearer check and returned {"result": ...}, not the `Error` envelope):

  * BAD BEARER: O-004 configured with a WRONG SENTINEL_ADMIN_TOKEN gets a real 401 from
           require_admin → the target/parent are `failed` and the policy is NOT persisted.
  * ENVELOPE: a forged-signature record makes the real route return 403 with the standard
           `Error` envelope error_code == "policy_intake_signature_rejected" (asserted by
           calling the real route directly over the same loopback socket — the old shim never
           produced that error_code / body shape).

The intake path IS Sentinel's real route (mounted, never re-implemented). The only faking
anywhere in O-004's test suite is the pure _aggregate_state UNIT test — never here.

THREE-HOP SCOPE (X-003 Deliverable 3 — documented gap, honest by design):
  The killer loop is Delta cap-breach → Orchestrator O-004 distribution → real Sentinel
  intake → enforcement. Its two seams are each proven non-stubbed, but by SEPARATE e2es:
    * O-004 → real Sentinel route → enforcement: proven HERE (real engine → real httpx →
      real loopback socket → the REAL POST /admin/policies/intake route + real auth →
      intake_policy() persist → evaluate_model_policies enforcement).
    * Delta D-005 cap-breach → real O-004 seam: proven by Delta's OWN non-stubbed e2e,
      Delta/tests/budget_engine/test_o004_e2e.py (the real budget engine signs a
      budget_limit and POSTs it over a real socket to the real O-004 receiver).
  Driving ALL THREE hops from a single real Delta cap-breach in ONE test is intentionally
  NOT done here: it would require standing up Delta's ledger/outbox DB + drainer + budget
  decision seeding AND Sentinel's DB + route AND the Orchestrator receiver simultaneously,
  with all three products sharing one signing/verifying keypair — disproportionate
  scaffolding across three separate products' databases for no additional seam coverage
  beyond what the two e2es above already establish. Left as a documented gap (honesty over a
  forced pseudo-e2e), per X-003 Deliverable 3.
"""

from __future__ import annotations

import dataclasses
import uuid

import httpx
import pytest

from orchestrator.distribution.engine import drive_distribution

# NOTE: Sentinel's `policy.*` is imported LAZILY inside the tests (not at module top) so the
# no-DB contract CI lane — which collects this file but skips its integration tests, and does
# not install Sentinel's deps — can import the module without ImportError.

pytestmark = pytest.mark.integration

ORCH_SERVICE_TOKEN = "o004-orch-service-token"  # noqa: S105 - test-only fake
# The break-glass admin bearer the shim's real require_admin authenticates (set into the
# SENTINEL_ADMIN_TOKEN env by the sentinel_signing fixture; O-004 sends the same value).
_ADMIN_TOKEN = "o004-sentinel-admin-token"  # noqa: S105 - test-only fake
_TARGET = "sentinel-test"
_ALLOWED_MODEL = "gpt-4o-mini"
_UNLISTED_MODEL = "claude-3-opus"
_DENIED_MODEL = "gpt-3.5-turbo"


@pytest.fixture
def dist_app(sentinel_db_ready, sentinel_shim_server, monkeypatch):
    """Construct the orchestrator app wired to the real shim as the single distribution target.

    Env is set BEFORE create_app() so get_distribution_settings() resolves the inbound/outbound
    tokens, the shim base URL target, the intake path, and a low backoff at construction.
    """
    import json

    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "o004-ingest-secret")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", ORCH_SERVICE_TOKEN)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "o004-sentinel-admin-token")
    monkeypatch.setenv("ORCH_DISTRIBUTION_TARGETS", json.dumps({_TARGET: sentinel_shim_server}))
    monkeypatch.setenv("ORCH_SENTINEL_INTAKE_PATH", "/admin/policies/intake")
    monkeypatch.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "2")

    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = ORCH_SERVICE_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get_status(app, distribution_id: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(f"/v1/policies/distributions/{distribution_id}", headers=_bearer())


async def test_allow_policy_distributes_then_enforces_allow_and_deny(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    sentinel_enforce,
    read_sentinel_policy_signature,
):
    """ALLOW gate: distribute a model_allowlist, then Sentinel REALLY enforces it.

    Distributed-state, byte-identical signature, ALLOW on the listed model, DENY on an
    unlisted one — all via the real engine + real intake + real enforcement.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy(
        "model_allowlist", tenant_id=tenant, allowed_model_ids=[_ALLOWED_MODEL]
    )
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    # Real non-stubbed distribution: real httpx → real socket → shim → Sentinel real intake.
    await drive_distribution(distribution_id, tenant, settings=dist_app.state.distribution_settings)

    # Orchestrator state settled to distributed (privileged BYPASSRLS read on the ORCH DB).
    target_state = await db_conn.fetchval(
        "SELECT state FROM policy_distribution_targets WHERE distribution_id = $1",
        distribution_id,
    )
    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert target_state == "distributed", target_state
    assert parent_state == "distributed", parent_state

    # GET status reflects it (re-read under the tenant session, RLS-confirmed).
    status = await _get_status(dist_app, distribution_id)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["state"] == "distributed"
    assert body["targets"][0]["sentinel_id"] == _TARGET
    assert body["targets"][0]["state"] == "distributed"
    assert "last_attempt_at" in body["targets"][0]

    # Signature verified UNCHANGED: the bytes Sentinel persisted == what Delta/test signed.
    persisted_sig = await read_sentinel_policy_signature(signed["policy_id"])
    assert persisted_sig == signed["signature"]

    # Sentinel's REAL enforcement: the distributed allow-list actually enforces.
    from policy.enforcement import ModelAllow, ModelDeny

    allow = await sentinel_enforce(tenant, _ALLOWED_MODEL)
    deny = await sentinel_enforce(tenant, _UNLISTED_MODEL)
    assert isinstance(allow, ModelAllow), allow
    assert isinstance(deny, ModelDeny), deny
    assert deny.reason == "model_not_in_allowlist"


async def test_deny_policy_distributes_then_enforces_deny(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    sentinel_enforce,
):
    """DENY gate: distribute a model_denylist, then Sentinel REALLY denies the denied model."""
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy(
        "model_denylist",
        tenant_id=tenant,
        denied_model_ids=[_DENIED_MODEL],
        reason="blocked model for O-004 deny gate",
    )
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    await drive_distribution(distribution_id, tenant, settings=dist_app.state.distribution_settings)

    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert parent_state == "distributed", parent_state

    from policy.enforcement import ModelDeny

    deny = await sentinel_enforce(tenant, _DENIED_MODEL)
    assert isinstance(deny, ModelDeny), deny
    assert deny.reason == "model_denied"


async def test_submit_endpoint_drives_real_distribution_and_enforces(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    sentinel_enforce,
):
    """Full HTTP submit path: POST → 202 → BackgroundTask drives the REAL distribution.

    httpx ASGITransport runs the FastAPI BackgroundTask synchronously, so on POST return the
    distribution is already settled. Proves the orchestrator's OWN submit→distribute path
    end-to-end with nothing stubbed, then Sentinel really enforces the distributed allow-list.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy("model_allowlist", tenant_id=tenant, allowed_model_ids=["gpt-4o"])

    transport = httpx.ASGITransport(app=dist_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.post(
            "/v1/policies/distributions", json={"policy": signed}, headers=_bearer()
        )
    assert resp.status_code == 202, resp.text
    distribution_id = resp.json()["distribution_id"]
    assert resp.json()["state"] == "pending"

    # The background task has run the real distribution by now; orchestrator state settled.
    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert parent_state == "distributed", parent_state

    status = await _get_status(dist_app, distribution_id)
    assert status.status_code == 200, status.text
    assert status.json()["state"] == "distributed"
    assert status.json()["targets"][0]["state"] == "distributed"

    from policy.enforcement import ModelAllow

    assert isinstance(await sentinel_enforce(tenant, "gpt-4o"), ModelAllow)


async def test_forged_signature_rejected_target_and_parent_failed(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    read_sentinel_policy_signature,
):
    """Threat T1: a tampered signature → Sentinel rejects (permanent 4xx) → state == failed.

    The engine sees a permanent 4xx and records `failed` WITHOUT a retry storm; the parent
    aggregates to `failed`; the forged policy is never persisted in Sentinel.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    forged = make_signed_policy(
        "model_allowlist",
        tenant_id=tenant,
        allowed_model_ids=[_ALLOWED_MODEL],
        tamper_signature=True,
    )
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=forged,
        sentinel_ids=[_TARGET],
    )

    await drive_distribution(distribution_id, tenant, settings=dist_app.state.distribution_settings)

    target_row = await db_conn.fetchrow(
        "SELECT state, attempt_count FROM policy_distribution_targets WHERE distribution_id = $1",
        distribution_id,
    )
    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert target_row["state"] == "failed", dict(target_row)
    assert parent_state == "failed", parent_state
    # Permanent reject: a single attempt, no retry amplification on a rejected signature.
    assert target_row["attempt_count"] == 1, dict(target_row)

    # The forged policy was rejected before persist — nothing landed in Sentinel.
    assert await read_sentinel_policy_signature(forged["policy_id"]) is None


# --------------------------------------------------------------------------------------- #
# X-003 (ADR-0042) REAL-ROUTE proofs: assertions that could ONLY pass against Sentinel's
# actual production /admin/policies/intake route + real require_admin / reject_sso_global
# auth — NOT against the old hand-rolled shim (which did its own bearer compare and returned
# {"result": ...} rather than the standard `Error` envelope).
# --------------------------------------------------------------------------------------- #


async def test_wrong_admin_bearer_is_rejected_by_real_require_admin(
    dist_app,
    db_conn,
    seed_sentinel_tenant,
    make_signed_policy,
    seed_distribution,
    read_sentinel_policy_signature,
):
    """A WRONG admin bearer → the real require_admin returns 401 → target/parent `failed`.

    O-004 is driven with a DistributionSettings whose sentinel_admin_token does NOT match the
    SENTINEL_ADMIN_TOKEN the shim's real require_admin authenticates. The real route's
    router-level require_admin rejects it with a genuine 401 (a wrong bearer is neither the
    break-glass env token nor a valid operator-session) BEFORE intake_policy() ever runs. The
    engine treats 401 as a permanent 4xx (single attempt, no retry storm) and the policy is
    never persisted. This could NOT pass against a shim that skipped or hand-rolled auth.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy(
        "model_allowlist", tenant_id=tenant, allowed_model_ids=[_ALLOWED_MODEL]
    )
    distribution_id = uuid.uuid4().hex
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant,
        signed_record=signed,
        sentinel_ids=[_TARGET],
    )

    # A validly-signed record, but the outbound bearer is WRONG — only auth should fail.
    bad_auth_settings = dataclasses.replace(
        dist_app.state.distribution_settings,
        sentinel_admin_token="not-the-admin-token",  # noqa: S106 - test-only fake
    )
    await drive_distribution(distribution_id, tenant, settings=bad_auth_settings)

    target_row = await db_conn.fetchrow(
        "SELECT state, attempt_count, last_error FROM policy_distribution_targets "
        "WHERE distribution_id = $1",
        distribution_id,
    )
    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert target_row["state"] == "failed", dict(target_row)
    assert parent_state == "failed", parent_state
    # 401 is a permanent 4xx → a single attempt, no retry amplification.
    assert target_row["attempt_count"] == 1, dict(target_row)
    assert target_row["last_error"] == "http_401", dict(target_row)

    # A validly-signed record that never authenticated must NOT have been persisted.
    assert await read_sentinel_policy_signature(signed["policy_id"]) is None


async def test_forged_signature_returns_real_error_envelope_over_the_wire(
    sentinel_db_ready,
    sentinel_shim_server,
    seed_sentinel_tenant,
    make_signed_policy,
):
    """The real route returns 403 + the standard `Error` envelope on a forged signature.

    POSTs a forged-signature record straight at the REAL /admin/policies/intake route over the
    same real loopback socket, carrying the correct admin bearer (so require_admin passes and
    intake_policy() runs and rejects the signature). Asserts the response is 403 with the
    standard `Error` envelope whose error_code is the contract-pinned
    `policy_intake_signature_rejected` (contracts/openapi.yaml). The OLD hand-rolled shim
    returned {"result": "RejectedSignature"} with no error_code, so this body shape could only
    come from the real route's response mapping.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    forged = make_signed_policy(
        "model_allowlist",
        tenant_id=tenant,
        allowed_model_ids=[_ALLOWED_MODEL],
        tamper_signature=True,
    )

    url = sentinel_shim_server.rstrip("/") + "/admin/policies/intake"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            url, json=forged, headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"}
        )

    assert resp.status_code == 403, resp.text
    body = resp.json()
    # The standard `Error` envelope (error_code/message/request_id) — NOT the old shim's
    # {"result": ...}. The stable, contract-pinned error_code proves it is the real route.
    assert body["error_code"] == "policy_intake_signature_rejected", body
    assert set(body) == {"error_code", "message", "request_id"}, body
    assert "result" not in body


async def test_absent_admin_bearer_is_rejected_by_real_require_admin(
    sentinel_db_ready,
    sentinel_shim_server,
    seed_sentinel_tenant,
    make_signed_policy,
):
    """No Authorization header at all → the real require_admin returns 401 with its detail.

    Confirms the real router-level require_admin (not a hand-rolled check) is the gate: a
    validly-signed record with NO bearer is 401'd before intake_policy() runs.
    """
    tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)
    signed = make_signed_policy(
        "model_allowlist", tenant_id=tenant, allowed_model_ids=[_ALLOWED_MODEL]
    )

    url = sentinel_shim_server.rstrip("/") + "/admin/policies/intake"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, json=signed)  # no Authorization header

    assert resp.status_code == 401, resp.text
    # require_admin raises HTTPException(detail="admin_unauthorized") → FastAPI {"detail": ...}.
    assert resp.json()["detail"] == "admin_unauthorized"
