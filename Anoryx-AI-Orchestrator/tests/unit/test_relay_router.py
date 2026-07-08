"""Auth + structural-validation boundary for the O-009 relay seam (ADR-0009). No DB.

Every case returns at or before the auth / structural-validation boundary — strictly BEFORE
`relay.client.relay_request` (which is the only place that touches the DB) — so no Postgres is
needed: fail-closed source-bearer auth (401), the missing-tenant-key posture (401), the pre-DB
request-shape 422s (unknown fields, non-object payload, disallowed target_path, streaming
request), and the oversized-body 413.
"""

from __future__ import annotations

import json

import httpx
import pytest

_DELTA_TOKEN = "unit-relay-delta-token"  # noqa: S105 - test-only fake
_RENDLY_TOKEN = "unit-relay-rendly-token"  # noqa: S105 - test-only fake
_SENTINEL_AUTH_HEADER = "X-Sentinel-Authorization"


@pytest.fixture
def app(monkeypatch):
    """Construct the orchestrator app with two configured relay source tokens."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv(
        "ORCH_RELAY_SOURCE_TOKENS",
        json.dumps({"delta": _DELTA_TOKEN, "rendly": _RENDLY_TOKEN}),
    )
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_no_tokens(monkeypatch):
    """Construct the app with NO relay source tokens (fail-closed: every request is 401)."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.delenv("ORCH_RELAY_SOURCE_TOKENS", raising=False)
    from orchestrator.app import create_app

    return create_app()


def _headers(
    *, source_token: str | None = _DELTA_TOKEN, sentinel_auth: str | None = "s-key"
) -> dict:
    headers = {}
    if source_token is not None:
        headers["Authorization"] = f"Bearer {source_token}"
    if sentinel_auth is not None:
        headers[_SENTINEL_AUTH_HEADER] = sentinel_auth
    return headers


_VALID_BODY = {
    "tenant_id": "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
    "sentinel_id": "sentinel-a",
    "target_path": "/v1/chat/completions",
    "payload": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
}


async def _post(app, *, headers=None, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post("/v1/relay/dispatch", headers=headers or {}, json=json_body)


async def test_missing_auth_is_401(app):
    resp = await _post(app, headers=_headers(source_token=None), json_body=_VALID_BODY)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_wrong_source_token_is_401(app):
    resp = await _post(app, headers=_headers(source_token="not-a-token"), json_body=_VALID_BODY)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_unconfigured_source_tokens_is_401(app_no_tokens):
    # Fail-closed: with no relay source tokens configured, even a presented bearer never matches.
    resp = await _post(app_no_tokens, headers=_headers(), json_body=_VALID_BODY)
    assert resp.status_code == 401


async def test_rendly_token_also_authenticates(app):
    # Only asserts source auth passes (we never reach relay_request without a DB); the
    # unconfigured sentinel target then fails structural validation with a distinct code
    # only if we got past auth, so we instead prove auth passed by checking it's NOT a 401.
    resp = await _post(app, headers=_headers(source_token=_RENDLY_TOKEN), json_body=_VALID_BODY)
    assert resp.status_code != 401


async def test_missing_sentinel_auth_header_is_401(app):
    resp = await _post(app, headers=_headers(sentinel_auth=None), json_body=_VALID_BODY)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_non_object_body_is_422(app):
    resp = await _post(app, headers=_headers(), json_body=["not", "an", "object"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_unknown_field_is_422(app):
    resp = await _post(app, headers=_headers(), json_body={**_VALID_BODY, "extra": 1})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_missing_tenant_id_is_422(app):
    body = {k: v for k, v in _VALID_BODY.items() if k != "tenant_id"}
    resp = await _post(app, headers=_headers(), json_body=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_disallowed_target_path_is_422(app):
    resp = await _post(
        app, headers=_headers(), json_body={**_VALID_BODY, "target_path": "/v1/admin/secret"}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "path_not_allowed"


async def test_non_object_payload_is_422(app):
    resp = await _post(app, headers=_headers(), json_body={**_VALID_BODY, "payload": "nope"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_streaming_payload_is_422(app):
    body = {**_VALID_BODY, "payload": {**_VALID_BODY["payload"], "stream": True}}
    resp = await _post(app, headers=_headers(), json_body=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "streaming_not_supported"


async def test_oversized_body_is_413(app):
    big_payload = {**_VALID_BODY["payload"], "pad": "x" * 2_000_000}
    resp = await _post(app, headers=_headers(), json_body={**_VALID_BODY, "payload": big_payload})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "request_too_large"


async def test_nul_byte_is_422(app):
    body = {**_VALID_BODY, "sentinel_id": "sentinel-a\x00evil"}
    resp = await _post(app, headers=_headers(), json_body=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"
