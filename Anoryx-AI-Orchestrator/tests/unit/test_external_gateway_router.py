"""Unit tests for the O-013 third-party external gateway (ADR-0013). No DB.

Mirrors test_admin_router.py (operator-token boundary) and test_messaging_router.py
(repository-layer monkeypatching, no Postgres anywhere in this file). Genuine RLS
isolation, real rate-limit races, and real chain persistence live in
tests/integration/test_external_gateway_e2e.py — this file proves the ROUTER's own logic.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone

import httpx
import pytest

from orchestrator.external_gateway import router as gateway_router
from orchestrator.external_gateway.auth import ExternalGatewayPrincipal, require_third_party_api_key

_ADMIN_TOKEN = "unit-orch-admin-token"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    monkeypatch.setenv("ORCH_EXTERNAL_GATEWAY_ENABLED", "1")
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_disabled(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    monkeypatch.setenv("ORCH_EXTERNAL_GATEWAY_ENABLED", "0")
    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = _ADMIN_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get(app, path: str, *, headers=None, params=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=headers or {}, params=params or {})


async def _post(app, path: str, *, headers=None, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(path, headers=headers or {}, json=json_body)


class _FakePrivilegedSession:
    async def execute(self, *args, **kwargs):
        raise AssertionError("unexpected raw execute on the fake privileged session")

    @contextlib.asynccontextmanager
    async def begin(self):
        yield None


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield _FakePrivilegedSession()

    monkeypatch.setattr(gateway_router, "get_privileged_session", _fake)


def _patch_tenant_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield object()

    monkeypatch.setattr(gateway_router, "get_tenant_session", _fake)


def _patch_audit(monkeypatch) -> list:
    calls: list[dict] = []

    async def _append(_session, **kwargs):
        calls.append(kwargs)
        return "fake-row-hash"

    monkeypatch.setattr(gateway_router, "append_external_gateway_audit_link", _append)
    return calls


# --------------------------------------------------------------------------- #
# Admin operator-auth boundary (byte-identical policy to admin/router.py).
# --------------------------------------------------------------------------- #

_ADMIN_ROUTES = [
    ("POST", "/v1/admin/external-keys"),
    ("GET", "/v1/admin/external-keys"),
    ("POST", "/v1/admin/external-keys/extkey-does-not-matter/revoke"),
]


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
async def test_admin_routes_require_auth(app, method, path):
    call = _get if method == "GET" else _post
    resp = await call(app, path)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
async def test_admin_routes_wrong_token_is_403(app, method, path):
    call = _get if method == "GET" else _post
    resp = await call(app, path, headers=_bearer("wrong-token"))
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# POST /v1/admin/external-keys — issuance validation + happy path.
# --------------------------------------------------------------------------- #


def _valid_issue_body(**overrides) -> dict:
    body = {"tenant_id": "tenant-a", "label": "integration-partner", "scopes": ["events:read"]}
    body.update(overrides)
    return body


async def test_issue_unknown_field_is_422(app):
    resp = await _post(
        app,
        "/v1/admin/external-keys",
        headers=_bearer(),
        json_body=_valid_issue_body(surprise="field"),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_issue_missing_field_is_422(app):
    body = _valid_issue_body()
    del body["label"]
    resp = await _post(app, "/v1/admin/external-keys", headers=_bearer(), json_body=body)
    assert resp.status_code == 422


async def test_issue_unknown_scope_is_422(app):
    resp = await _post(
        app,
        "/v1/admin/external-keys",
        headers=_bearer(),
        json_body=_valid_issue_body(scopes=["not:a:real:scope"]),
    )
    assert resp.status_code == 422


async def test_issue_out_of_range_rate_limit_is_422(app):
    resp = await _post(
        app,
        "/v1/admin/external-keys",
        headers=_bearer(),
        json_body=_valid_issue_body(rate_limit_per_minute=0),
    )
    assert resp.status_code == 422


async def test_issue_happy_path_returns_plaintext_key_once(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _fake_lock(_session, _tenant_id):
        return None

    async def _fake_count(_session, _tenant_id):
        return 0

    inserted_rows = []

    async def _fake_insert(_session, row):
        inserted_rows.append(row)
        return {
            **row,
            "created_at": datetime(2026, 7, 8, tzinfo=timezone.utc),
            "revoked_at": None,
        }

    monkeypatch.setattr(gateway_router, "lock_external_gateway_key_cap", _fake_lock)
    monkeypatch.setattr(gateway_router, "count_third_party_api_keys", _fake_count)
    monkeypatch.setattr(gateway_router, "insert_third_party_api_key", _fake_insert)

    resp = await _post(
        app, "/v1/admin/external-keys", headers=_bearer(), json_body=_valid_issue_body()
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["api_key"].startswith("eak_")
    assert body["tenant_id"] == "tenant-a"
    assert body["scopes"] == ["events:read"]
    assert "key_hash" not in body
    assert inserted_rows[0]["tenant_id"] == "tenant-a"
    assert inserted_rows[0]["key_hash"] != body["api_key"]


async def test_issue_over_cap_is_422(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _fake_lock(_session, _tenant_id):
        return None

    async def _fake_count(_session, _tenant_id):
        return 999999

    monkeypatch.setattr(gateway_router, "lock_external_gateway_key_cap", _fake_lock)
    monkeypatch.setattr(gateway_router, "count_third_party_api_keys", _fake_count)

    resp = await _post(
        app, "/v1/admin/external-keys", headers=_bearer(), json_body=_valid_issue_body()
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "key_limit_exceeded"


# --------------------------------------------------------------------------- #
# GET /v1/admin/external-keys + revoke.
# --------------------------------------------------------------------------- #


async def test_list_keys_never_projects_key_hash(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _fake_list(_session, *, tenant_id):
        return [
            {
                "key_id": "extkey-1",
                "tenant_id": "tenant-a",
                "key_hash": "should-never-appear",
                "label": "x",
                "scopes": ["events:read"],
                "status": "active",
                "rate_limit_per_minute": 60,
                "created_at": datetime(2026, 7, 8, tzinfo=timezone.utc),
                "revoked_at": None,
            }
        ]

    monkeypatch.setattr(gateway_router, "list_third_party_api_keys", _fake_list)
    resp = await _get(app, "/v1/admin/external-keys", headers=_bearer())
    assert resp.status_code == 200
    assert "key_hash" not in resp.text
    assert "should-never-appear" not in resp.text


async def test_revoke_unknown_key_is_404(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _fake_revoke(_session, _key_id):
        return None

    monkeypatch.setattr(gateway_router, "revoke_third_party_api_key", _fake_revoke)
    resp = await _post(app, "/v1/admin/external-keys/extkey-nope/revoke", headers=_bearer())
    assert resp.status_code == 404


async def test_revoke_happy_path(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _fake_revoke(_session, key_id):
        return {
            "key_id": key_id,
            "tenant_id": "tenant-a",
            "label": "x",
            "scopes": ["events:read"],
            "status": "revoked",
            "rate_limit_per_minute": 60,
            "created_at": datetime(2026, 7, 8, tzinfo=timezone.utc),
            "revoked_at": datetime(2026, 7, 8, tzinfo=timezone.utc),
        }

    monkeypatch.setattr(gateway_router, "revoke_third_party_api_key", _fake_revoke)
    resp = await _post(app, "/v1/admin/external-keys/extkey-1/revoke", headers=_bearer())
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


# --------------------------------------------------------------------------- #
# GET /v1/external/events — the gated read.
# --------------------------------------------------------------------------- #

_PRINCIPAL_ACTIVE = ExternalGatewayPrincipal(
    key_id="extkey-1",
    tenant_id="tenant-a",
    scopes=("events:read",),
    status="active",
    rate_limit_per_minute=60,
)
_PRINCIPAL_REVOKED = ExternalGatewayPrincipal(
    key_id="extkey-2",
    tenant_id="tenant-a",
    scopes=("events:read",),
    status="revoked",
    rate_limit_per_minute=60,
)
_PRINCIPAL_SCOPELESS = ExternalGatewayPrincipal(
    key_id="extkey-3",
    tenant_id="tenant-a",
    scopes=(),
    status="active",
    rate_limit_per_minute=60,
)


def _override(app, principal):
    app.dependency_overrides[require_third_party_api_key] = lambda: principal
    return app


async def test_disabled_gateway_is_404_even_for_a_valid_key(app_disabled, monkeypatch):
    _override(app_disabled, _PRINCIPAL_ACTIVE)
    resp = await _get(app_disabled, "/v1/external/events", headers={"X-Api-Key": "irrelevant"})
    assert resp.status_code == 404


async def test_revoked_key_is_403_and_audited(app, monkeypatch):
    _override(app, _PRINCIPAL_REVOKED)
    _patch_privileged_session(monkeypatch)
    audited = _patch_audit(monkeypatch)
    resp = await _get(app, "/v1/external/events", headers={"X-Api-Key": "irrelevant"})
    assert resp.status_code == 403
    assert audited == [
        {
            "tenant_id": "tenant-a",
            "key_id": "extkey-2",
            "route": "GET /v1/external/events",
            "outcome": "revoked",
        }
    ]


async def test_scopeless_key_is_403_and_audited(app, monkeypatch):
    _override(app, _PRINCIPAL_SCOPELESS)
    _patch_privileged_session(monkeypatch)
    audited = _patch_audit(monkeypatch)
    resp = await _get(app, "/v1/external/events", headers={"X-Api-Key": "irrelevant"})
    assert resp.status_code == 403
    assert audited[0]["outcome"] == "scope_denied"


async def test_rate_limited_key_is_429_and_audited(app, monkeypatch):
    _override(app, _PRINCIPAL_ACTIVE)
    _patch_privileged_session(monkeypatch)
    audited = _patch_audit(monkeypatch)

    async def _fake_increment(_session, *, key_id, window_start):
        return 61  # over the 60/min limit

    monkeypatch.setattr(gateway_router, "increment_external_gateway_rate_limit", _fake_increment)
    resp = await _get(app, "/v1/external/events", headers={"X-Api-Key": "irrelevant"})
    assert resp.status_code == 429
    assert audited[0]["outcome"] == "rate_limited"


async def test_malformed_cursor_is_422_before_rate_limit_consumed(app, monkeypatch):
    _override(app, _PRINCIPAL_ACTIVE)

    async def _fail_increment(*_args, **_kwargs):
        raise AssertionError("rate limit must not be consumed for a malformed cursor")

    monkeypatch.setattr(gateway_router, "increment_external_gateway_rate_limit", _fail_increment)
    resp = await _get(
        app, "/v1/external/events", headers={"X-Api-Key": "irrelevant"}, params={"cursor": "!!!"}
    )
    assert resp.status_code == 422


async def test_allowed_read_returns_events_and_is_audited(app, monkeypatch):
    _override(app, _PRINCIPAL_ACTIVE)
    _patch_privileged_session(monkeypatch)
    _patch_tenant_session(monkeypatch)
    audited = _patch_audit(monkeypatch)

    async def _fake_increment(_session, *, key_id, window_start):
        return 1

    async def _fake_list_events(session, *, filters, limit, cursor):
        return [], None

    monkeypatch.setattr(gateway_router, "increment_external_gateway_rate_limit", _fake_increment)
    monkeypatch.setattr(gateway_router, "list_events", _fake_list_events)

    resp = await _get(app, "/v1/external/events", headers={"X-Api-Key": "irrelevant"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"data": [], "next_cursor": None}
    assert audited[0]["outcome"] == "allowed"
