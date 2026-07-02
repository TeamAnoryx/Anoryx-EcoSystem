"""Unit tests for the POST + GET /v1/policies/distributions boundary (O-004 + O-006). No DB.

Every case returns at or before the tenant-session persist — strictly BEFORE any Postgres — so
no DB is needed. AUTH IS SPLIT (O-006): the POST WRITE keeps the COARSE service-token peer gate
(`_require_bearer`, ORCH_SERVICE_TOKEN — 401 on missing/empty/non-Bearer/unconfigured, 403 on a
present-but-wrong token); its inbound `tenant_id` is server-resolved from the signed body, NOT
validated against a principal (O-004 LOW-2 carried forward — the live Delta budget-engine
consumer is a trusted multi-tenant relay). The GET status READ is per-tenant
(require_tenant_principal): a missing/malformed Bearer → 401 (before any DB), and an id not
visible under the principal's RLS session → 404 (closes O-004 LOW-1).
"""

from __future__ import annotations

import contextlib
import uuid

import httpx
import pytest

from orchestrator.security import require_tenant_principal

_SERVICE_TOKEN = "unit-orch-service-token"  # noqa: S105 - test-only fake
_PRINCIPAL = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.fixture
def app(monkeypatch):
    """The app with the coarse POST service token set; GET uses the real per-tenant gate."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", _SERVICE_TOKEN)
    monkeypatch.delenv("ORCH_DISTRIBUTION_TARGETS", raising=False)
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def authed_app(app):
    """The app with the GET principal dep overridden to a fixed tenant (no DB in the gate)."""
    app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    return app


def _valid_policy(tenant_id: str | None = None) -> dict:
    """A schema-valid model_denylist policy with a well-formed (unverified) signature.

    The router only STRUCTURALLY validates the policy (Sentinel intake is the verifying
    authority), so a syntactically valid signature is sufficient here.
    """
    return {
        "policy_type": "model_denylist",
        "tenant_id": tenant_id or str(uuid.uuid4()),
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


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {_SERVICE_TOKEN}"}


async def _post(app, *, headers=None, json=None, content=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            "/v1/policies/distributions", headers=headers or {}, json=json, content=content
        )


async def _get(app, distribution_id: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(
            f"/v1/policies/distributions/{distribution_id}", headers=headers or {}
        )


# --------------------------------------------------------------------------- #
# POST auth gate (coarse service token): 401 missing/empty/non-Bearer, 403 wrong token.
# --------------------------------------------------------------------------- #


async def test_post_missing_authorization_is_401(app):
    resp = await _post(app, json={"policy": _valid_policy()})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_post_non_bearer_authorization_is_401(app):
    resp = await _post(
        app, headers={"Authorization": "Basic abc"}, json={"policy": _valid_policy()}
    )
    assert resp.status_code == 401


async def test_post_empty_bearer_is_401(app):
    resp = await _post(app, headers={"Authorization": "Bearer "}, json={"policy": _valid_policy()})
    assert resp.status_code == 401


async def test_post_wrong_bearer_is_403(app):
    resp = await _post(
        app, headers={"Authorization": "Bearer not-the-token"}, json={"policy": _valid_policy()}
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


# --------------------------------------------------------------------------- #
# Structural / schema / NUL 422s (coarse-authed; all fire before tenant extraction).
# --------------------------------------------------------------------------- #


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
    resp = await _post(app, headers=_auth(), json={"policy": {"policy_type": "model_allowlist"}})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "policy_schema_invalid"


async def test_nul_in_policy_is_422(app):
    policy = _valid_policy()
    policy["reason"] = "blocked\x00now"
    resp = await _post(app, headers=_auth(), json={"policy": policy})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"
    assert "NUL" in resp.json()["error"]["message"]


# --------------------------------------------------------------------------- #
# GET /v1/policies/distributions/{id} — per-tenant auth (401) + not-visible (404), no DB.
# --------------------------------------------------------------------------- #


async def test_get_missing_authorization_is_401(app):
    resp = await _get(app, str(uuid.uuid4()))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_get_non_bearer_authorization_is_401(app):
    resp = await _get(app, str(uuid.uuid4()), headers={"Authorization": "Basic abc"})
    assert resp.status_code == 401


async def test_get_not_visible_under_principal_is_404(authed_app, monkeypatch):
    # The GET reads DIRECTLY under the principal's tenant session (no privileged pre-resolve).
    # A fake tenant-session CM + a get_distribution that resolves nothing → 404 before any DB.
    from orchestrator.distribution import router as dist_router

    @contextlib.asynccontextmanager
    async def _fake_tenant_session(_tenant_id):
        yield object()

    async def _no_distribution(_session, _distribution_id):
        return None

    monkeypatch.setattr(dist_router, "get_tenant_session", _fake_tenant_session)
    monkeypatch.setattr(dist_router, "get_distribution", _no_distribution)

    resp = await _get(authed_app, str(uuid.uuid4()))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
