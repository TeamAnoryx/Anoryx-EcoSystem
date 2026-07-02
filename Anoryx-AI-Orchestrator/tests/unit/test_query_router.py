"""Unit tests for the O-006 query/bus read seams (ADR-0006). No DB.

Two layers:
  * PURE helpers — Limit clamp, opaque cursor round-trips, and the metadata-only projections
    (asserting `payload` / `original_envelope` NEVER leak, and DLQ `source_sequence` → the
    contract's `sequence`).
  * ENDPOINT behavior with the principal dependency overridden and the repo layer mocked (no
    Postgres): the FilterTenantId=B → 403 reject, the clamp is actually applied to the repo
    call, a malformed cursor → 422, schema-versions is the global allow-list, and the response
    bodies carry ONLY the contract metadata fields.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import httpx
import pytest

from orchestrator.query import router as query_router
from orchestrator.query.router import (
    _BIGINT_MAX,
    _MAX_CURSOR_LENGTH,
    _clamp_limit,
    _dead_letter_metadata_body,
    _decode_dlq_cursor,
    _decode_seq_cursor,
    _encode_dlq_cursor,
    _encode_seq_cursor,
    _event_metadata_body,
)
from orchestrator.security import require_tenant_principal


def _b64(raw: bytes) -> str:
    """base64url-encode raw bytes into an opaque cursor string (matches the router encoders)."""
    return base64.urlsafe_b64encode(raw).decode("ascii")


_PRINCIPAL = "11111111-1111-4111-8111-111111111111"
_OTHER = "22222222-2222-4222-8222-222222222222"


# --------------------------------------------------------------------------- #
# Pure helpers.
# --------------------------------------------------------------------------- #


def test_clamp_limit_default_when_absent():
    assert _clamp_limit(None) == 50


def test_clamp_limit_floor_and_ceiling():
    assert _clamp_limit(0) == 1
    assert _clamp_limit(-100) == 1
    assert _clamp_limit(9999) == 200
    assert _clamp_limit(200) == 200
    assert _clamp_limit(1) == 1
    assert _clamp_limit(75) == 75


def test_seq_cursor_round_trip():
    assert _decode_seq_cursor(_encode_seq_cursor(1024)) == 1024


def test_dlq_cursor_round_trip():
    created = datetime(2026, 6, 26, 12, 0, 10, tzinfo=timezone.utc)
    cursor = _encode_dlq_cursor(created, "dlq-abc")
    c_created, c_dlq = _decode_dlq_cursor(cursor)
    assert c_created == created.isoformat()
    assert c_dlq == "dlq-abc"


def test_seq_cursor_rejects_garbage():
    with pytest.raises(ValueError):
        _decode_seq_cursor("!!!not-base64!!!")


def test_event_metadata_body_is_allowlist_no_payload():
    row = {
        "event_id": "e1",
        "event_type": "policy_decision_deny",
        "event_timestamp": "2026-06-26T12:00:00Z",
        "tenant_id": _PRINCIPAL,
        "team_id": "t1",
        "project_id": "p1",
        "agent_id": "gateway-core",
        "request_id": "req-1",
        # These MUST never appear in the projection.
        "payload": {"secret": "leak"},
        "content_hash": "deadbeef",
        "sequence_number": 5,
    }
    body = _event_metadata_body(row)
    assert "payload" not in body
    assert "content_hash" not in body
    assert "sequence_number" not in body
    assert body["event_id"] == "e1"
    assert body["request_id"] == "req-1"


def test_dead_letter_metadata_body_no_envelope_and_maps_sequence():
    row = {
        "dlq_id": "dlq-1",
        "reason": "unknown_schema_version",
        "attempt_count": 3,
        "first_failed_at": "2026-06-26T12:00:10Z",
        "event_type": "policy_decision_deny",
        "source_product": "sentinel",
        "source_sequence": 1024,
        # Must never appear.
        "original_envelope": {"payload": {"secret": "leak"}},
    }
    body = _dead_letter_metadata_body(row)
    assert "original_envelope" not in body
    assert body["sequence"] == 1024
    assert "source_sequence" not in body


def test_dead_letter_metadata_body_null_sequence_coerced_to_zero():
    row = {
        "dlq_id": "dlq-2",
        "reason": "payload_schema_invalid",
        "attempt_count": 1,
        "first_failed_at": "2026-06-26T12:00:10Z",
        "event_type": "policy_decision_deny",
        "source_product": "sentinel",
        "source_sequence": None,
    }
    assert _dead_letter_metadata_body(row)["sequence"] == 0


# --------------------------------------------------------------------------- #
# Endpoint behavior (principal dependency overridden; repo layer mocked → no DB).
# --------------------------------------------------------------------------- #


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    application = create_app()
    application.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    return application


async def _get(app, path: str, params: dict | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, params=params)


def _patch_tenant_session(monkeypatch):
    """Replace get_tenant_session in the query router with a fake CM (no DB)."""
    import contextlib

    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield object()

    monkeypatch.setattr(query_router, "get_tenant_session", _fake)


async def test_events_filter_tenant_mismatch_is_403(app):
    resp = await _get(app, f"/v1/events?tenant_id={_OTHER}")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


async def test_events_malformed_cursor_is_422(app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    resp = await _get(app, "/v1/events?cursor=%21%21%21bad")
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_events_cursor_out_of_bigint_range_is_422(app, monkeypatch):
    # A cursor that base64-decodes to a valid int OUTSIDE signed BIGINT range must be caught in
    # the decoder (would otherwise be a DB DataError → 503). Validated pre-query → 422.
    _patch_tenant_session(monkeypatch)
    cursor = _b64(str(_BIGINT_MAX + 1).encode("ascii"))
    resp = await _get(app, "/v1/events", params={"cursor": cursor})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


@pytest.mark.parametrize("raw", [b"[1,2]", b"5"])
async def test_dlq_non_dict_cursor_is_422(app, monkeypatch, raw):
    # A DLQ cursor that base64-decodes to valid JSON that is NOT an object (`[1,2]` → TypeError
    # on obj["c"]; `5` → int not subscriptable) previously reached the 503 catch-all. Now 422.
    _patch_tenant_session(monkeypatch)
    resp = await _get(app, "/v1/bus/dlq", params={"cursor": _b64(raw)})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_dlq_unparseable_timestamp_cursor_is_422(app, monkeypatch):
    # A DLQ cursor whose `c` is not a parseable ISO timestamp previously raised a DB DataError at
    # CAST(... AS timestamptz) time → 503. Now pre-parsed in the decoder → 422.
    _patch_tenant_session(monkeypatch)
    cursor = _b64(json.dumps({"c": "not-a-timestamp", "d": "dlq-x"}).encode("utf-8"))
    resp = await _get(app, "/v1/bus/dlq", params={"cursor": cursor})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


@pytest.mark.parametrize("path", ["/v1/events", "/v1/bus/dlq"])
async def test_cursor_over_max_length_is_422(app, monkeypatch, path):
    # An over-512-char cursor is rejected by FastAPI's own Query(max_length) validation → 422
    # (its RequestValidationError body, not our error envelope), never the 503 catch-all.
    _patch_tenant_session(monkeypatch)
    resp = await _get(app, path, params={"cursor": "A" * (_MAX_CURSOR_LENGTH + 1)})
    assert resp.status_code == 422


def test_decode_seq_cursor_rejects_out_of_bigint_range():
    with pytest.raises(ValueError):
        _decode_seq_cursor(_b64(str(_BIGINT_MAX + 1).encode("ascii")))


def test_decode_dlq_cursor_rejects_non_dict_and_bad_timestamp():
    # Non-object JSON and an unparseable `c` are both decoder-level rejects (mapped to 422).
    with pytest.raises((ValueError, TypeError)):
        _decode_dlq_cursor(_b64(b"[1,2]"))
    with pytest.raises((ValueError, TypeError)):
        _decode_dlq_cursor(_b64(b"5"))
    with pytest.raises(ValueError):
        _decode_dlq_cursor(_b64(json.dumps({"c": "nope", "d": "x"}).encode("utf-8")))


async def test_events_response_is_metadata_only(app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_events(_session, *, filters, limit, cursor):
        row = {
            "event_id": "e1",
            "event_type": "policy_decision_deny",
            "event_timestamp": "2026-06-26T12:00:00Z",
            "tenant_id": _PRINCIPAL,
            "team_id": "t1",
            "project_id": "p1",
            "agent_id": "gateway-core",
            "request_id": "req-1",
            "payload": {"secret": "leak"},  # a leak-canary the projection must drop
        }
        return [row], None

    monkeypatch.setattr(query_router, "list_events", _list_events)
    resp = await _get(app, "/v1/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["next_cursor"] is None
    assert len(body["data"]) == 1
    assert "payload" not in body["data"][0]
    assert "secret" not in resp.text


async def test_events_limit_is_clamped_before_repo(app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    seen: dict[str, int] = {}

    async def _list_events(_session, *, filters, limit, cursor):
        seen["limit"] = limit
        return [], None

    monkeypatch.setattr(query_router, "list_events", _list_events)
    await _get(app, "/v1/events?limit=9999")
    assert seen["limit"] == 200
    await _get(app, "/v1/events?limit=0")
    assert seen["limit"] == 1
    await _get(app, "/v1/events")
    assert seen["limit"] == 50


async def test_events_next_cursor_is_encoded(app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_events(_session, *, filters, limit, cursor):
        return [], 4096

    monkeypatch.setattr(query_router, "list_events", _list_events)
    resp = await _get(app, "/v1/events")
    body = resp.json()
    assert body["next_cursor"] is not None
    assert _decode_seq_cursor(body["next_cursor"]) == 4096


async def test_dlq_response_is_metadata_only(app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_dead_letters(_session, *, filters, limit, cursor):
        row = {
            "dlq_id": "dlq-1",
            "reason": "unknown_schema_version",
            "attempt_count": 3,
            "first_failed_at": "2026-06-26T12:00:10Z",
            "event_type": "policy_decision_deny",
            "source_product": "sentinel",
            "source_sequence": 1024,
            "original_envelope": {"payload": {"secret": "leak"}},  # canary
        }
        return [row], None

    monkeypatch.setattr(query_router, "list_dead_letters", _list_dead_letters)
    resp = await _get(app, "/v1/bus/dlq")
    assert resp.status_code == 200
    body = resp.json()
    assert "original_envelope" not in body["data"][0]
    assert body["data"][0]["sequence"] == 1024
    assert "secret" not in resp.text


async def test_dlq_next_cursor_is_encoded(app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    created = datetime(2026, 6, 26, 12, 0, 10, tzinfo=timezone.utc)

    async def _list_dead_letters(_session, *, filters, limit, cursor):
        return [], (created, "dlq-9")

    monkeypatch.setattr(query_router, "list_dead_letters", _list_dead_letters)
    resp = await _get(app, "/v1/bus/dlq")
    body = resp.json()
    c_created, c_dlq = _decode_dlq_cursor(body["next_cursor"])
    assert c_dlq == "dlq-9"
    assert c_created == created.isoformat()


async def test_schema_versions_is_global_allowlist(app):
    resp = await _get(app, "/v1/bus/schema-versions")
    assert resp.status_code == 200
    body = resp.json()
    assert body["supported"] == [1]
    assert body["envelope_schema_id"] == "anoryx:event-envelope:v1"


async def test_events_requires_principal_when_not_overridden(monkeypatch):
    # Without the dependency override, a missing token → the real gate → uniform 401.
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    application = create_app()
    resp = await _get(application, "/v1/events")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_pure_garbage_cursor_is_rejected():
    # A cursor of only non-base64 chars decodes to empty under lenient urlsafe_b64decode; the
    # downstream int()/json.loads then raises ValueError, so no garbage cursor yields a valid
    # key (the endpoint maps that to 422). Proves both decoders reject it deterministically.
    with pytest.raises(ValueError):
        _decode_seq_cursor("!!!")
    with pytest.raises(ValueError):
        _decode_dlq_cursor("!!!")
