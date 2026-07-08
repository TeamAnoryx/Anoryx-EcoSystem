"""Auth/validation/dedup/pagination boundary for the O-012 agent mailbox relay (ADR-0012).

No DB. Mirrors test_automation_router.py's pattern: the tenant principal dependency is
overridden and the repository layer is monkeypatched at the `messaging.router` module
boundary (get_tenant_session, get_privileged_session, and the repo functions imported by
name into that module), so no Postgres is needed anywhere in this file. Genuine two-real-
HTTP-request dedup + real-RLS cross-tenant-invisibility proofs live in
tests/integration/test_messaging_e2e.py — this file proves the ROUTER's own logic (which
repo function it calls, with what arguments, and how it maps outcomes to status codes).
"""

from __future__ import annotations

import contextlib

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from orchestrator.messaging import router as messaging_router
from orchestrator.security import require_tenant_principal

_PRINCIPAL = "11111111-1111-4111-8111-111111111111"


def _valid_send_body(**overrides) -> dict:
    body = {
        "sender_team_id": "team-a",
        "sender_project_id": "proj-a",
        "sender_agent_id": "agent-a",
        "recipient_team_id": "team-a",
        "recipient_project_id": "proj-a",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "body": {"hello": "world"},
        "idempotency_key": "msg-1",
    }
    body.update(overrides)
    return body


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def test_app(app):
    """The app with the tenant principal dependency overridden (no auth boundary)."""
    app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    yield app
    app.dependency_overrides.clear()


class _FakeSession:
    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _patch_tenant_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield _FakeSession()

    monkeypatch.setattr(messaging_router, "get_tenant_session", _fake)


def _capture_tenant_session_ids(monkeypatch) -> list:
    """Patch get_tenant_session to RECORD every tenant_id it is opened with (proves the
    router always scopes via the caller's OWN resolved principal — genuine RLS isolation
    itself is proven end-to-end against a real Postgres in test_messaging_e2e.py)."""
    seen: list[str] = []

    @contextlib.asynccontextmanager
    async def _fake(tenant_id):
        seen.append(tenant_id)
        yield _FakeSession()

    monkeypatch.setattr(messaging_router, "get_tenant_session", _fake)
    return seen


class _FakePrivilegedSession:
    @contextlib.asynccontextmanager
    async def begin(self):
        yield None


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield _FakePrivilegedSession()

    monkeypatch.setattr(messaging_router, "get_privileged_session", _fake)


def _patch_messaging_audit_append(monkeypatch) -> list:
    appended: list[dict] = []

    async def _append(_session, **kwargs):
        appended.append(kwargs)
        return "fake-row-hash"

    monkeypatch.setattr(messaging_router, "append_messaging_audit_link", _append)
    return appended


async def _post(app, path: str, *, json_body=None, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(path, headers=headers or {}, json=json_body)


async def _post_raw(app, path: str, *, content: bytes) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            path, content=content, headers={"Content-Type": "application/json"}
        )


async def _get(app, path: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=headers or {})


# --------------------------------------------------------------------------- #
# Auth boundary — missing tenant principal -> 401 (real dependency, no override).
# --------------------------------------------------------------------------- #


async def test_send_missing_principal_is_401(app):
    resp = await _post(app, "/v1/messaging/messages", json_body=_valid_send_body())
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_inbox_missing_principal_is_401(app):
    resp = await _get(app, "/v1/messaging/inbox/team-a/proj-a/agent-b")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# POST /v1/messaging/messages — structural validation (no DB reached).
# --------------------------------------------------------------------------- #


async def test_unknown_field_is_422(test_app):
    resp = await _post(
        test_app, "/v1/messaging/messages", json_body={**_valid_send_body(), "extra": 1}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_missing_field_is_422(test_app):
    body = {k: v for k, v in _valid_send_body().items() if k != "recipient_agent_id"}
    resp = await _post(test_app, "/v1/messaging/messages", json_body=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_wrong_typed_field_is_422(test_app):
    resp = await _post(
        test_app, "/v1/messaging/messages", json_body=_valid_send_body(sender_agent_id=123)
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_object_body_field_is_422(test_app):
    resp = await _post(
        test_app, "/v1/messaging/messages", json_body=_valid_send_body(body="not-an-object")
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_object_request_is_422(test_app):
    resp = await _post(test_app, "/v1/messaging/messages", json_body=["not", "an", "object"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_oversized_body_is_422(test_app, monkeypatch):
    monkeypatch.setenv("ORCH_MESSAGING_MAX_BODY_BYTES", "16")
    from orchestrator.app import create_app

    small_cap_app = create_app()
    small_cap_app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    resp = await _post(
        small_cap_app,
        "/v1/messaging/messages",
        json_body=_valid_send_body(body={"padding": "x" * 100}),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "body_too_large"


async def test_nul_byte_is_422(test_app):
    resp = await _post(
        test_app, "/v1/messaging/messages", json_body=_valid_send_body(message_type="bad\x00type")
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


def _deeply_nested_json_object(depth: int) -> bytes:
    return (b'{"n":' * depth) + b"{}" + (b"}" * depth)


async def test_deeply_nested_body_is_422_not_500(test_app):
    resp = await _post_raw(
        test_app, "/v1/messaging/messages", content=_deeply_nested_json_object(650)
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


# --------------------------------------------------------------------------- #
# POST /v1/messaging/messages — dedup behavior (repo layer mocked).
# --------------------------------------------------------------------------- #


def _patch_message_cap_not_hit(monkeypatch, *, existing_idempotency_row=None):
    """Patch the dedup pre-check + cap lock/count so a fresh send proceeds normally.

    `existing_idempotency_row` lets a caller simulate the pre-check finding (or not
    finding) an existing row for the idempotency_key; defaults to "nothing exists yet".
    """

    async def _get_agent_message_by_idempotency_key(_session, _idempotency_key):
        return existing_idempotency_row

    async def _lock_messaging_message_cap(_session, _tenant_id):
        return None

    async def _count_agent_messages(_session):
        return 0

    monkeypatch.setattr(
        messaging_router,
        "get_agent_message_by_idempotency_key",
        _get_agent_message_by_idempotency_key,
    )
    monkeypatch.setattr(messaging_router, "lock_messaging_message_cap", _lock_messaging_message_cap)
    monkeypatch.setattr(messaging_router, "count_agent_messages", _count_agent_messages)


async def test_fresh_send_is_sent_disposition(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    _patch_message_cap_not_hit(monkeypatch)
    appended = _patch_messaging_audit_append(monkeypatch)

    async def _insert_agent_message(_session, row):
        return {**row, "sequence_number": 7, "created_at": "2026-07-08T12:00:00+00:00"}

    monkeypatch.setattr(messaging_router, "insert_agent_message", _insert_agent_message)

    resp = await _post(test_app, "/v1/messaging/messages", json_body=_valid_send_body())
    assert resp.status_code == 202
    body = resp.json()
    assert body["disposition"] == "sent"
    assert body["sequence_number"] == 7
    assert appended[0]["disposition"] == "sent"


async def test_duplicate_send_is_deduped_disposition_same_sequence(test_app, monkeypatch):
    """The dedup pre-check races a concurrent sender: it finds NOTHING (the concurrent
    send hasn't committed yet), the cap check passes, and the INSERT itself hits the
    UNIQUE(tenant_id, idempotency_key) conflict — the genuine IntegrityError race path.
    (The pre-check-finds-it-immediately path is covered by
    test_dedup_resend_via_precheck_skips_cap_check_entirely below.)"""
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    appended = _patch_messaging_audit_append(monkeypatch)

    existing_row = {
        "sequence_number": 7,
        "tenant_id": _PRINCIPAL,
        "sender_team_id": "team-a",
        "sender_project_id": "proj-a",
        "sender_agent_id": "agent-a",
        "recipient_team_id": "team-a",
        "recipient_project_id": "proj-a",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "body": {"hello": "world"},
        "idempotency_key": "msg-1",
        "created_at": "2026-07-08T12:00:00+00:00",
    }
    precheck_calls = {"n": 0}

    async def _insert_agent_message(_session, row):
        raise IntegrityError("insert", {}, Exception("duplicate"))

    async def _get_agent_message_by_idempotency_key(_session, idempotency_key):
        precheck_calls["n"] += 1
        if precheck_calls["n"] == 1:
            return None  # pre-check: nothing exists yet, so the cap IS checked
        return existing_row  # post-conflict re-fetch: the concurrent sender's row

    async def _lock_messaging_message_cap(_session, _tenant_id):
        return None

    async def _count_agent_messages(_session):
        return 0

    monkeypatch.setattr(messaging_router, "insert_agent_message", _insert_agent_message)
    monkeypatch.setattr(
        messaging_router,
        "get_agent_message_by_idempotency_key",
        _get_agent_message_by_idempotency_key,
    )
    monkeypatch.setattr(messaging_router, "lock_messaging_message_cap", _lock_messaging_message_cap)
    monkeypatch.setattr(messaging_router, "count_agent_messages", _count_agent_messages)

    resp = await _post(test_app, "/v1/messaging/messages", json_body=_valid_send_body())
    assert resp.status_code == 202
    body = resp.json()
    assert body["disposition"] == "deduped"
    assert body["sequence_number"] == 7
    assert body["created_at"] == "2026-07-08T12:00:00+00:00"
    assert appended[0]["disposition"] == "deduped"


# --------------------------------------------------------------------------- #
# POST /v1/messaging/messages — per-tenant message cap (security-auditor follow-up).
# --------------------------------------------------------------------------- #


async def test_dedup_resend_via_precheck_skips_cap_check_entirely(test_app, monkeypatch):
    """A resend whose idempotency_key ALREADY exists is found by the pre-check and must
    never touch the cap lock/count/insert at all — not just "never be blocked" by them."""
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    appended = _patch_messaging_audit_append(monkeypatch)

    existing_row = {
        "sequence_number": 3,
        "tenant_id": _PRINCIPAL,
        "sender_team_id": "team-a",
        "sender_project_id": "proj-a",
        "sender_agent_id": "agent-a",
        "recipient_team_id": "team-a",
        "recipient_project_id": "proj-a",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "body": {"hello": "world"},
        "idempotency_key": "msg-1",
        "created_at": "2026-07-08T12:00:00+00:00",
    }

    async def _get_agent_message_by_idempotency_key(_session, _idempotency_key):
        return existing_row

    async def _never_called(*_args, **_kwargs):
        raise AssertionError("must not be called for a pre-checked dedup resend")

    monkeypatch.setattr(
        messaging_router,
        "get_agent_message_by_idempotency_key",
        _get_agent_message_by_idempotency_key,
    )
    monkeypatch.setattr(messaging_router, "lock_messaging_message_cap", _never_called)
    monkeypatch.setattr(messaging_router, "count_agent_messages", _never_called)
    monkeypatch.setattr(messaging_router, "insert_agent_message", _never_called)

    resp = await _post(test_app, "/v1/messaging/messages", json_body=_valid_send_body())
    assert resp.status_code == 202
    body = resp.json()
    assert body["disposition"] == "deduped"
    assert body["sequence_number"] == 3
    assert appended[0]["disposition"] == "deduped"


async def test_message_cap_at_limit_returns_422_and_does_not_insert(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_agent_message_by_idempotency_key(_session, _idempotency_key):
        return None

    async def _lock_messaging_message_cap(_session, _tenant_id):
        return None

    async def _count_agent_messages(_session):
        return 3  # at the configured cap below

    async def _insert_should_not_be_called(_session, _row):
        raise AssertionError("insert_agent_message must not be called over the cap")

    monkeypatch.setattr(
        messaging_router,
        "get_agent_message_by_idempotency_key",
        _get_agent_message_by_idempotency_key,
    )
    monkeypatch.setattr(messaging_router, "lock_messaging_message_cap", _lock_messaging_message_cap)
    monkeypatch.setattr(messaging_router, "count_agent_messages", _count_agent_messages)
    monkeypatch.setattr(messaging_router, "insert_agent_message", _insert_should_not_be_called)

    monkeypatch.setenv("ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT", "3")
    from orchestrator.app import create_app

    capped_app = create_app()
    capped_app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL

    resp = await _post(capped_app, "/v1/messaging/messages", json_body=_valid_send_body())
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "message_limit_exceeded"


# --------------------------------------------------------------------------- #
# GET /v1/messaging/inbox/{team_id}/{project_id}/{agent_id} — pagination (repo mocked).
# --------------------------------------------------------------------------- #


def _sample_message_row(**overrides) -> dict:
    row = {
        "sequence_number": 1,
        "tenant_id": _PRINCIPAL,
        "sender_team_id": "team-a",
        "sender_project_id": "proj-a",
        "sender_agent_id": "agent-a",
        "recipient_team_id": "team-a",
        "recipient_project_id": "proj-a",
        "recipient_agent_id": "agent-b",
        "message_type": "ping",
        "body": {"hello": "world"},
        "idempotency_key": "msg-1",
        "created_at": "2026-07-08T12:00:00+00:00",
    }
    row.update(overrides)
    return row


async def test_inbox_projects_expected_fields(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_inbox_messages(
        _session, *, team_id, project_id, agent_id, since_sequence, limit
    ):
        return [_sample_message_row()], None

    monkeypatch.setattr(messaging_router, "list_inbox_messages", _list_inbox_messages)
    resp = await _get(test_app, "/v1/messaging/inbox/team-a/proj-a/agent-b")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["sequence_number"] == 1
    assert body["next_since_sequence"] is None


async def test_inbox_since_sequence_is_forwarded_as_exclusive_lower_bound(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    seen: dict = {}

    async def _list_inbox_messages(
        _session, *, team_id, project_id, agent_id, since_sequence, limit
    ):
        seen["since_sequence"] = since_sequence
        seen["team_id"] = team_id
        seen["project_id"] = project_id
        seen["agent_id"] = agent_id
        return [], None

    monkeypatch.setattr(messaging_router, "list_inbox_messages", _list_inbox_messages)
    await _get(test_app, "/v1/messaging/inbox/team-a/proj-a/agent-b?since_sequence=41")
    assert seen["since_sequence"] == 41
    assert seen["team_id"] == "team-a"
    assert seen["project_id"] == "proj-a"
    assert seen["agent_id"] == "agent-b"


async def test_inbox_limit_is_clamped_to_configured_ceiling(test_app, monkeypatch):
    monkeypatch.setenv("ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE", "10")
    from orchestrator.app import create_app

    clamped_app = create_app()
    clamped_app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    _patch_tenant_session(monkeypatch)
    seen: dict = {}

    async def _list_inbox_messages(
        _session, *, team_id, project_id, agent_id, since_sequence, limit
    ):
        seen["limit"] = limit
        return [], None

    monkeypatch.setattr(messaging_router, "list_inbox_messages", _list_inbox_messages)
    await _get(clamped_app, "/v1/messaging/inbox/team-a/proj-a/agent-b?limit=9999")
    assert seen["limit"] == 10


async def test_inbox_next_since_sequence_echoes_repo_cursor(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_inbox_messages(
        _session, *, team_id, project_id, agent_id, since_sequence, limit
    ):
        return [_sample_message_row()], 5

    monkeypatch.setattr(messaging_router, "list_inbox_messages", _list_inbox_messages)
    resp = await _get(test_app, "/v1/messaging/inbox/team-a/proj-a/agent-b")
    assert resp.json()["next_since_sequence"] == 5


# --------------------------------------------------------------------------- #
# Tenant-scoping contract — the router always opens get_tenant_session with the
# CALLER'S OWN resolved principal (genuine cross-tenant RLS invisibility is proven
# end-to-end against a real Postgres in test_messaging_e2e.py).
# --------------------------------------------------------------------------- #


async def test_inbox_uses_the_callers_own_principal_for_the_session(app, monkeypatch):
    tenant_x = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    app.dependency_overrides[require_tenant_principal] = lambda: tenant_x
    seen = _capture_tenant_session_ids(monkeypatch)

    async def _list_inbox_messages(_session, **_kwargs):
        return [], None

    monkeypatch.setattr(messaging_router, "list_inbox_messages", _list_inbox_messages)
    await _get(app, "/v1/messaging/inbox/team-a/proj-a/agent-b")
    assert seen == [tenant_x]
