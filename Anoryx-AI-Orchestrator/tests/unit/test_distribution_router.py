"""Unit tests for the POST /v1/policies/distributions boundary (O-004, ADR-0004). No DB.

Every case here returns at or before structural / schema / NUL validation — strictly BEFORE
the tenant-session persist — so no Postgres is needed: fail-closed bearer auth (401/403), JSON
+ structural request validation (422), locked policy-schema validation (422), the NUL guard
(422), and the sign_on_behalf=false constraint (422).
"""

from __future__ import annotations

import contextlib
import uuid

import httpx
import pytest

_SERVICE_TOKEN = "unit-orch-service-token"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    """Construct the orchestrator app with a service token and no DB access on these paths."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", _SERVICE_TOKEN)
    monkeypatch.delenv("ORCH_DISTRIBUTION_TARGETS", raising=False)

    from orchestrator.app import create_app

    return create_app()


def _valid_policy() -> dict:
    """A schema-valid model_denylist policy with a well-formed (unverified) signature.

    The router only STRUCTURALLY validates the policy (it never verifies the JWS — Sentinel
    intake is the verifying authority), so a syntactically valid signature is sufficient here.
    """
    return {
        "policy_type": "model_denylist",
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": "2026-01-01T00:00:00Z",
        "signature": "aaaaaa.bbbbbb.cccccc",
        "denied_model_ids": ["gpt-3.5-turbo"],
        "reason": "unit test policy",
    }


async def _post(app, *, headers=None, json=None, content=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            "/v1/policies/distributions", headers=headers or {}, json=json, content=content
        )


async def test_missing_authorization_is_401(app):
    resp = await _post(app, json={"policy": _valid_policy()})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_non_bearer_authorization_is_401(app):
    resp = await _post(
        app, headers={"Authorization": "Basic abc"}, json={"policy": _valid_policy()}
    )
    assert resp.status_code == 401


async def test_empty_bearer_is_401(app):
    resp = await _post(app, headers={"Authorization": "Bearer "}, json={"policy": _valid_policy()})
    assert resp.status_code == 401


async def test_wrong_bearer_is_403(app):
    resp = await _post(
        app, headers={"Authorization": "Bearer not-the-token"}, json={"policy": _valid_policy()}
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {_SERVICE_TOKEN}"}


async def test_non_json_body_is_422(app):
    resp = await _post(app, headers=_auth(), content=b"not json at all")
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_object_body_is_422(app):
    resp = await _post(app, headers=_auth(), json=[1, 2, 3])
    assert resp.status_code == 422


async def test_unknown_request_field_is_422(app):
    resp = await _post(app, headers=_auth(), json={"policy": _valid_policy(), "bogus": 1})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_sign_on_behalf_true_is_422(app):
    resp = await _post(
        app, headers=_auth(), json={"policy": _valid_policy(), "sign_on_behalf": True}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "sign_on_behalf_disabled"


async def test_policy_schema_invalid_is_422(app):
    # Missing required fields (only policy_type present) → locked policy.schema.json fails.
    resp = await _post(app, headers=_auth(), json={"policy": {"policy_type": "model_allowlist"}})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "policy_schema_invalid"


async def test_nul_in_policy_is_422(app):
    # Schema-valid policy carrying a NUL in a string field → the NUL guard rejects (422),
    # since \x00 cannot be stored in Postgres text/JSONB (deterministic terminal disposition).
    policy = _valid_policy()
    policy["reason"] = "blocked\x00now"
    resp = await _post(app, headers=_auth(), json={"policy": policy})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"
    assert "NUL" in resp.json()["error"]["message"]


# --------------------------------------------------------------------------- #
# GET /v1/policies/distributions/{distribution_id} — auth + not-found (no DB).
# 401/403 decide at the auth boundary before any read; the 404 case mocks the
# repository boundary (and a fake privileged session) so no Postgres is touched.
# --------------------------------------------------------------------------- #


async def _get(app, distribution_id: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(
            f"/v1/policies/distributions/{distribution_id}", headers=headers or {}
        )


async def test_get_missing_authorization_is_401(app):
    resp = await _get(app, str(uuid.uuid4()))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_get_wrong_bearer_is_403(app):
    resp = await _get(app, str(uuid.uuid4()), headers={"Authorization": "Bearer not-the-token"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


async def test_get_unknown_distribution_is_404(app, monkeypatch):
    # Mock at the repository boundary so this stays a no-DB unit test: a fake privileged
    # session context manager (never opens a real connection) + a get_distribution that
    # resolves nothing → the handler returns 404 before any tenant read.
    from orchestrator.distribution import router as dist_router

    @contextlib.asynccontextmanager
    async def _fake_privileged_session():
        yield object()

    async def _no_distribution(_session, _distribution_id):
        return None

    monkeypatch.setattr(dist_router, "get_privileged_session", _fake_privileged_session)
    monkeypatch.setattr(dist_router, "get_distribution", _no_distribution)

    resp = await _get(app, str(uuid.uuid4()), headers=_auth())
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
