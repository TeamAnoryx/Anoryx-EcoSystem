"""Router error-response tests for the ingest seam (O-003) — no DB required.

401 (missing/malformed HMAC), 403 (stale timestamp / signature mismatch), and 422
(malformed JSON / structurally-invalid envelope) are all decided at the boundary BEFORE
the pipeline touches Postgres, so these run in the contract lane without a live DB. They
pin the contract's error envelope shape (error.code / error.message / error.request_id).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx
import pytest

_SECRET = "router-error-secret"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", _SECRET)
    from orchestrator.app import create_app

    return create_app()


def _sign(body: bytes, ts: int) -> str:
    digest = hmac.new(_SECRET.encode("utf-8"), f"{ts}.".encode("utf-8") + body, hashlib.sha256)
    return f"sha256={digest.hexdigest()}"


async def _post(app, body: bytes, headers: dict[str, str]):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/v1/ingest/events", content=body, headers={**headers})


async def test_missing_signature_returns_401(app, make_valid_envelope):
    body = json.dumps(make_valid_envelope()).encode("utf-8")
    resp = await _post(app, body, {"X-Sentinel-Timestamp": str(int(time.time()))})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"
    assert resp.json()["error"]["request_id"]


async def test_stale_timestamp_returns_403(app, make_valid_envelope):
    ts = int(time.time()) - 700  # outside the ±300s window
    body = json.dumps(make_valid_envelope()).encode("utf-8")
    resp = await _post(
        app, body, {"X-Sentinel-Signature": _sign(body, ts), "X-Sentinel-Timestamp": str(ts)}
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "signature_invalid"


async def test_signature_mismatch_returns_403(app, make_valid_envelope):
    ts = int(time.time())
    body = json.dumps(make_valid_envelope()).encode("utf-8")
    # Sign the right ts but a DIFFERENT body, then send the original body.
    bad_sig = _sign(body + b"x", ts)
    resp = await _post(
        app, body, {"X-Sentinel-Signature": bad_sig, "X-Sentinel-Timestamp": str(ts)}
    )
    assert resp.status_code == 403


async def test_malformed_json_returns_422(app):
    ts = int(time.time())
    body = b"not-json"
    resp = await _post(
        app, body, {"X-Sentinel-Signature": _sign(body, ts), "X-Sentinel-Timestamp": str(ts)}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_hex_signature_returns_401(app, make_valid_envelope):
    ts = int(time.time())
    body = json.dumps(make_valid_envelope()).encode("utf-8")
    resp = await _post(
        app,
        body,
        {"X-Sentinel-Signature": "sha256=" + "z" * 64, "X-Sentinel-Timestamp": str(ts)},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_structurally_invalid_envelope_returns_422(app, make_valid_envelope):
    ts = int(time.time())
    env = make_valid_envelope()
    del env["sequence"]  # required envelope field → structural validation fails
    body = json.dumps(env).encode("utf-8")
    resp = await _post(
        app, body, {"X-Sentinel-Signature": _sign(body, ts), "X-Sentinel-Timestamp": str(ts)}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_nul_char_in_payload_returns_422(app, make_valid_envelope):
    # audit M-2: a NUL char cannot be stored in Postgres text/JSONB (neither persisted nor
    # dead-lettered), so a NUL-bearing body is rejected at the boundary as malformed (422),
    # never a 503 retry-storm. json.dumps serialises \x00 as the ASCII escape , so the
    # body is transmittable; the receiver decodes it back to a NUL and rejects it.
    ts = int(time.time())
    env = make_valid_envelope()
    env["payload"]["tenant_id"] = "ab\x00cd"
    body = json.dumps(env).encode("utf-8")
    resp = await _post(
        app, body, {"X-Sentinel-Signature": _sign(body, ts), "X-Sentinel-Timestamp": str(ts)}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"
