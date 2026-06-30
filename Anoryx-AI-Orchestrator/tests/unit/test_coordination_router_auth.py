"""Operator-auth boundary for the O-005 registry + coordinate seams (ADR-0005). No DB.

Every case returns at or before the auth / structural-validation boundary — strictly BEFORE any
privileged or tenant persist — so no Postgres is needed: fail-closed operator-token auth
(401/403), the unconfigured-token fail-closed posture (401), and the pre-DB request-shape 422s
(unknown fields, malformed sentinel_id, malformed policy).
"""

from __future__ import annotations

import httpx
import pytest

_ADMIN_TOKEN = "unit-orch-admin-token"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    """Construct the orchestrator app with an operator admin token configured."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_no_token(monkeypatch):
    """Construct the app with NO operator admin token (fail-closed: every request is 401)."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.delenv("ORCH_ADMIN_TOKEN", raising=False)
    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = _ADMIN_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _request(app, method: str, path: str, *, headers=None, json=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.request(method, path, headers=headers or {}, json=json)


# Every operator-gated route (method, path, body).
_ROUTES = [
    (
        "POST",
        "/v1/registry/sentinels",
        {"sentinel_id": "s", "endpoint": "https://8.8.8.8", "capabilities": ["model_allowlist"]},
    ),
    ("GET", "/v1/registry/sentinels", None),
    ("GET", "/v1/registry/sentinels/s-a", None),
    ("PATCH", "/v1/registry/sentinels/s-a", {"enabled": False}),
    ("DELETE", "/v1/registry/sentinels/s-a", None),
    ("POST", "/v1/registry/health-check", {}),
    ("POST", "/v1/policies/coordinate", {"policy": {}}),
]


@pytest.mark.parametrize(("method", "path", "body"), _ROUTES)
async def test_missing_auth_is_401(app, method, path, body):
    resp = await _request(app, method, path, json=body)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(("method", "path", "body"), _ROUTES)
async def test_wrong_token_is_403(app, method, path, body):
    resp = await _request(app, method, path, headers=_bearer("not-the-token"), json=body)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize(("method", "path", "body"), _ROUTES)
async def test_unconfigured_admin_token_is_401(app_no_token, method, path, body):
    # Fail-closed: with no admin token configured, even a presented bearer can never match.
    resp = await _request(app_no_token, method, path, headers=_bearer(), json=body)
    assert resp.status_code == 401


async def test_register_unknown_field_is_422(app):
    resp = await _request(
        app,
        "POST",
        "/v1/registry/sentinels",
        headers=_bearer(),
        json={"sentinel_id": "s", "endpoint": "https://8.8.8.8", "capabilities": ["x"], "nope": 1},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_register_bad_sentinel_id_is_422(app):
    # A malformed sentinel_id is rejected before any DB write.
    resp = await _request(
        app,
        "POST",
        "/v1/registry/sentinels",
        headers=_bearer(),
        json={
            "sentinel_id": "bad id!",
            "endpoint": "https://8.8.8.8",
            "capabilities": ["model_allowlist"],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_sentinel_id"


async def test_register_bad_capabilities_is_422(app):
    resp = await _request(
        app,
        "POST",
        "/v1/registry/sentinels",
        headers=_bearer(),
        json={"sentinel_id": "s-a", "endpoint": "https://8.8.8.8", "capabilities": ["not_a_type"]},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_capabilities"


async def test_oversized_body_is_413(app):
    big = {
        "sentinel_id": "s",
        "endpoint": "https://8.8.8.8",
        "capabilities": ["model_allowlist"],
        "pad": "x" * 70000,  # > 64 KiB cap
    }
    resp = await _request(app, "POST", "/v1/registry/sentinels", headers=_bearer(), json=big)
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "request_too_large"


async def test_coordinate_non_object_policy_is_422(app):
    resp = await _request(
        app, "POST", "/v1/policies/coordinate", headers=_bearer(), json={"policy": "nope"}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_coordinate_schema_invalid_policy_is_422(app):
    resp = await _request(
        app,
        "POST",
        "/v1/policies/coordinate",
        headers=_bearer(),
        json={"policy": {"policy_type": "model_allowlist"}},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "policy_schema_invalid"
