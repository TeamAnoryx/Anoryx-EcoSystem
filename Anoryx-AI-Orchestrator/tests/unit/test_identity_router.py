"""Auth + structural-validation boundary for the O-010 identity seam (ADR-0010). No DB.

Two layers, mirroring test_relay_router.py (POST) and test_query_router.py (GET):
  * POST /v1/identity/events — every case returns at or before the auth/structural boundary
    — strictly BEFORE any DB call (insert_identity_event / append_identity_audit_link) — so
    no Postgres is needed.
  * GET /v1/identity/events — the tenant principal dependency is overridden and the repo
    layer is monkeypatched (no DB), mirroring test_query_router.py's pattern exactly.
"""

from __future__ import annotations

import json

import httpx
import pytest

from orchestrator.identity import router as identity_router
from orchestrator.security import require_tenant_principal

_SENTINEL_TOKEN = "unit-identity-sentinel-token"  # noqa: S105 - test-only fake
_DELTA_TOKEN = "unit-identity-delta-token"  # noqa: S105 - test-only fake
_PRINCIPAL = "11111111-1111-4111-8111-111111111111"

_VALID_BODY = {
    "tenant_id": "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
    "principal_type": "operator",
    "principal_id": "idp-subject-a1b2c3",
    "action": "sso_login",
    "target": "admin-console",
    "idempotency_key": "sentinel-sso-a1b2c3-1",
    "occurred_at": "2026-07-08T12:00:00Z",
}


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv(
        "ORCH_IDENTITY_SOURCE_TOKENS",
        json.dumps({"sentinel": _SENTINEL_TOKEN, "delta": _DELTA_TOKEN}),
    )
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_no_tokens(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.delenv("ORCH_IDENTITY_SOURCE_TOKENS", raising=False)
    from orchestrator.app import create_app

    return create_app()


async def _post(app, *, headers=None, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post("/v1/identity/events", headers=headers or {}, json=json_body)


def _bearer(token: str = _SENTINEL_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# POST /v1/identity/events — auth + schema boundary (no DB).
# --------------------------------------------------------------------------- #


async def test_missing_auth_is_401(app):
    resp = await _post(app, json_body=_VALID_BODY)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_wrong_source_token_is_401(app):
    resp = await _post(app, headers=_bearer("not-a-token"), json_body=_VALID_BODY)
    assert resp.status_code == 401


async def test_unconfigured_source_tokens_is_401(app_no_tokens):
    resp = await _post(app_no_tokens, headers=_bearer(), json_body=_VALID_BODY)
    assert resp.status_code == 401


async def test_delta_token_also_authenticates(app):
    # Only proves auth passed (no DB here, so the actual insert would 503) — a distinct
    # code from 401 proves the Delta token matched and resolved source_product.
    resp = await _post(app, headers=_bearer(_DELTA_TOKEN), json_body=_VALID_BODY)
    assert resp.status_code != 401


async def test_non_object_body_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body=["not", "an", "object"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_unknown_field_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "extra": 1})
    assert resp.status_code == 422


async def test_missing_tenant_id_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "tenant_id"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_bad_principal_type_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "principal_type": "god"})
    assert resp.status_code == 422


async def test_missing_principal_id_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "principal_id"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_missing_action_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "action"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_target_too_long_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "target": "x" * 300})
    assert resp.status_code == 422


async def test_missing_idempotency_key_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "idempotency_key"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_missing_occurred_at_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "occurred_at"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_malformed_occurred_at_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "occurred_at": "nope"})
    assert resp.status_code == 422


async def test_occurred_at_without_timezone_is_422(app):
    resp = await _post(
        app, headers=_bearer(), json_body={**_VALID_BODY, "occurred_at": "2026-07-08T12:00:00"}
    )
    assert resp.status_code == 422


async def test_oversized_body_is_413(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "target": "x" * 20000})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "request_too_large"


async def test_nul_byte_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "principal_id": "a\x00b"})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# GET /v1/identity/events — principal overridden, repo mocked (no DB).
# --------------------------------------------------------------------------- #


@pytest.fixture
def read_app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    application = create_app()
    application.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    return application


def _patch_tenant_session(monkeypatch):
    import contextlib

    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield object()

    monkeypatch.setattr(identity_router, "get_tenant_session", _fake)


async def _get(read_app, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=read_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path)


async def test_read_projects_expected_fields_and_omits_absent_target(read_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_identity_events(_session, *, filters, limit, cursor):
        row = {
            "tenant_id": _PRINCIPAL,
            "source_product": "sentinel",
            "principal_type": "operator",
            "principal_id": "idp-subject-a1",
            "action": "sso_login",
            "target": None,
            "idempotency_key": "k1",
            "occurred_at": "2026-07-08T12:00:00+00:00",
            "received_at": "2026-07-08T12:00:01+00:00",
        }
        return [row], None

    monkeypatch.setattr(identity_router, "list_identity_events", _list_identity_events)
    resp = await _get(read_app, "/v1/identity/events")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 1
    assert "target" not in body["data"][0]
    assert body["next_cursor"] is None


async def test_read_limit_is_clamped_before_repo(read_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    seen: dict[str, int] = {}

    async def _list_identity_events(_session, *, filters, limit, cursor):
        seen["limit"] = limit
        return [], None

    monkeypatch.setattr(identity_router, "list_identity_events", _list_identity_events)
    await _get(read_app, "/v1/identity/events?limit=9999")
    assert seen["limit"] == 200


async def test_read_malformed_cursor_is_422(read_app):
    resp = await _get(read_app, "/v1/identity/events?cursor=not-base64!!!")
    assert resp.status_code == 422
