"""Auth + structural-validation boundary for the X-004 safety seam. No DB.

Two layers, mirroring test_identity_router.py:
  * POST /v1/safety/events — every case returns at or before the auth/structural boundary
    — strictly BEFORE any DB call (insert_safety_event / append_safety_audit_link) — so no
    Postgres is needed.
  * GET /v1/safety/events — the tenant principal dependency is overridden and the repo
    layer is monkeypatched (no DB), mirroring test_identity_router.py's pattern exactly.

NOTE on mTLS: mTLS peer termination is deferred to O-008 (the same honesty boundary
identity/router.py documents) — this app layer authenticates purely via the safety-source
bearer. There is no separate "wrong mTLS peer -> 403" code path to exercise here (a
present-but-non-matching bearer is indistinguishable from an absent one and is a uniform
401, mirroring test_wrong_source_token_is_401 below) — mirrors the identity precedent
exactly; no genuine 403 case exists at this layer to test.
"""

from __future__ import annotations

import json

import httpx
import pytest

from orchestrator.safety import router as safety_router
from orchestrator.security import require_tenant_principal

_SENTINEL_TOKEN = "unit-safety-sentinel-token"  # noqa: S105 - test-only fake
_DELTA_TOKEN = "unit-safety-delta-token"  # noqa: S105 - test-only fake
_PRINCIPAL = "22222222-2222-4222-8222-222222222222"

_VALID_BODY = {
    "tenant_id": "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
    "category": "pii",
    "outcome": "block",
    "target": "room-7f3a",
    "idempotency_key": "rendly-safety-7f3a-1",
    "occurred_at": "2026-07-08T12:00:00Z",
}


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv(
        "ORCH_SAFETY_SOURCE_TOKENS",
        json.dumps({"sentinel": _SENTINEL_TOKEN, "delta": _DELTA_TOKEN}),
    )
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_no_tokens(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.delenv("ORCH_SAFETY_SOURCE_TOKENS", raising=False)
    from orchestrator.app import create_app

    return create_app()


async def _post(app, *, headers=None, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post("/v1/safety/events", headers=headers or {}, json=json_body)


def _bearer(token: str = _SENTINEL_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# POST /v1/safety/events — auth + schema boundary (no DB).
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


async def test_identity_token_does_not_authenticate_safety(app, monkeypatch):
    """Least privilege: a token configured only for ORCH_IDENTITY_SOURCE_TOKENS must NOT
    authenticate the distinct safety seam."""
    monkeypatch.setenv(
        "ORCH_IDENTITY_SOURCE_TOKENS", json.dumps({"sentinel": "identity-only-token"})
    )
    from orchestrator.app import create_app

    identity_scoped_app = create_app()
    resp = await _post(
        identity_scoped_app, headers=_bearer("identity-only-token"), json_body=_VALID_BODY
    )
    assert resp.status_code == 401


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


async def test_bad_category_is_422(app):
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "category": "malware"})
    assert resp.status_code == 422


async def test_missing_category_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "category"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_bad_outcome_is_422(app):
    # v1 accepts ONLY "block" — routine passes are deliberately out of scope.
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "outcome": "pass"})
    assert resp.status_code == 422


async def test_missing_outcome_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "outcome"}
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
    resp = await _post(app, headers=_bearer(), json_body={**_VALID_BODY, "target": "a\x00b"})
    assert resp.status_code == 422


async def test_target_is_optional(app, monkeypatch):
    """target is nullable/opt-in — a body omitting it entirely clears the auth+schema
    boundary (no DB here, so the actual insert would 503, never a 422)."""
    body = {k: v for k, v in _VALID_BODY.items() if k != "target"}
    resp = await _post(app, headers=_bearer(), json_body=body)
    assert resp.status_code != 422


# --------------------------------------------------------------------------- #
# GET /v1/safety/events — principal overridden, repo mocked (no DB).
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

    monkeypatch.setattr(safety_router, "get_tenant_session", _fake)


async def _get(read_app, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=read_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path)


async def test_read_projects_expected_fields_and_omits_absent_target(read_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_safety_events(_session, *, filters, limit, cursor):
        row = {
            "tenant_id": _PRINCIPAL,
            "source_product": "rendly",
            "category": "pii",
            "outcome": "block",
            "target": None,
            "idempotency_key": "k1",
            "occurred_at": "2026-07-08T12:00:00+00:00",
            "received_at": "2026-07-08T12:00:01+00:00",
        }
        return [row], None

    monkeypatch.setattr(safety_router, "list_safety_events", _list_safety_events)
    resp = await _get(read_app, "/v1/safety/events")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 1
    assert "target" not in body["data"][0]
    assert body["next_cursor"] is None


async def test_read_limit_is_clamped_before_repo(read_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    seen: dict[str, int] = {}

    async def _list_safety_events(_session, *, filters, limit, cursor):
        seen["limit"] = limit
        return [], None

    monkeypatch.setattr(safety_router, "list_safety_events", _list_safety_events)
    await _get(read_app, "/v1/safety/events?limit=9999")
    assert seen["limit"] == 200


async def test_read_filters_pass_through_to_repo(read_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    seen: dict[str, dict] = {}

    async def _list_safety_events(_session, *, filters, limit, cursor):
        seen["filters"] = filters
        return [], None

    monkeypatch.setattr(safety_router, "list_safety_events", _list_safety_events)
    await _get(read_app, "/v1/safety/events?source_product=rendly&category=injection")
    assert seen["filters"] == {"source_product": "rendly", "category": "injection"}


async def test_read_malformed_cursor_is_422(read_app):
    resp = await _get(read_app, "/v1/safety/events?cursor=not-base64!!!")
    assert resp.status_code == 422
