"""Auth/validation/CAS boundary for the O-012 shared state store (ADR-0012). No DB.

Mirrors test_messaging_router.py's pattern: the tenant principal dependency is overridden
and the repository layer is monkeypatched at the `messaging.router` module boundary, so no
Postgres is needed anywhere in this file. The genuine two-concurrent-writers race proof
(the single most important correctness property of the CAS design) lives in
tests/integration/test_messaging_e2e.py, driven over a real Postgres.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest

from orchestrator.messaging import router as messaging_router
from orchestrator.security import require_tenant_principal

_PRINCIPAL = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def test_app(app):
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


class _FakePrivilegedSession:
    @contextlib.asynccontextmanager
    async def begin(self):
        yield None


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield _FakePrivilegedSession()

    monkeypatch.setattr(messaging_router, "get_privileged_session", _fake)


def _patch_state_audit_append(monkeypatch) -> list:
    appended: list[dict] = []

    async def _append(_session, **kwargs):
        appended.append(kwargs)
        return "fake-row-hash"

    monkeypatch.setattr(messaging_router, "append_state_audit_link", _append)
    return appended


async def _put(app, path: str, *, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.put(path, json=json_body)


async def _put_raw(app, path: str, *, content: bytes) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.put(path, content=content, headers={"Content-Type": "application/json"})


async def _get(app, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path)


# --------------------------------------------------------------------------- #
# Auth boundary.
# --------------------------------------------------------------------------- #


async def test_put_missing_principal_is_401(app):
    resp = await _put(
        app, "/v1/state/my-key", json_body={"expected_version": None, "value": {"x": 1}}
    )
    assert resp.status_code == 401


async def test_get_missing_principal_is_401(app):
    resp = await _get(app, "/v1/state/my-key")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# PUT /v1/state/{state_key} — structural validation (no DB reached).
# --------------------------------------------------------------------------- #


async def test_unknown_field_is_422(test_app):
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": None, "value": {"x": 1}, "extra": 1},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_missing_expected_version_key_is_422(test_app):
    resp = await _put(test_app, "/v1/state/my-key", json_body={"value": {"x": 1}})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_missing_value_key_is_422(test_app):
    resp = await _put(test_app, "/v1/state/my-key", json_body={"expected_version": None})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_object_value_is_422(test_app):
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": None, "value": "not-an-object"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_bool_expected_version_is_422(test_app):
    """isinstance(True, int) is True in Python — a bool must be explicitly rejected."""
    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": True, "value": {"x": 1}}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_integer_expected_version_is_422(test_app):
    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": "1", "value": {"x": 1}}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_zero_expected_version_is_422(test_app):
    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": 0, "value": {"x": 1}}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_non_object_request_is_422(test_app):
    resp = await _put(test_app, "/v1/state/my-key", json_body=["not", "an", "object"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_oversized_value_is_422(test_app, monkeypatch):
    monkeypatch.setenv("ORCH_MESSAGING_MAX_STATE_VALUE_BYTES", "16")
    from orchestrator.app import create_app

    small_cap_app = create_app()
    small_cap_app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    resp = await _put(
        small_cap_app,
        "/v1/state/my-key",
        json_body={"expected_version": None, "value": {"padding": "x" * 100}},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "state_value_too_large"


async def test_nul_byte_is_422(test_app):
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": None, "value": {"x": "bad\x00value"}},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_invalid_updated_by_agent_id_is_422(test_app):
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": None, "value": {"x": 1}, "updated_by_agent_id": ""},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


def _deeply_nested_json_object(depth: int) -> bytes:
    return (b'{"n":' * depth) + b"{}" + (b"}" * depth)


async def test_deeply_nested_body_is_422_not_500(test_app):
    resp = await _put_raw(test_app, "/v1/state/my-key", content=_deeply_nested_json_object(650))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


# --------------------------------------------------------------------------- #
# PUT /v1/state/{state_key} — create-only-if-absent semantics (repo layer mocked).
# --------------------------------------------------------------------------- #


def _patch_state_cap_not_hit(monkeypatch, *, existing_state_row=None):
    """Patch the existence pre-check + cap lock/count so a state CREATE proceeds normally.

    `existing_state_row` lets a caller simulate the pre-check finding (or not finding) an
    existing row for the state_key; defaults to "the key does not exist yet".
    """

    async def _get_agent_state(_session, _state_key):
        return existing_state_row

    async def _lock_messaging_state_key_cap(_session, _tenant_id):
        return None

    async def _count_agent_state_keys(_session):
        return 0

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    monkeypatch.setattr(
        messaging_router, "lock_messaging_state_key_cap", _lock_messaging_state_key_cap
    )
    monkeypatch.setattr(messaging_router, "count_agent_state_keys", _count_agent_state_keys)


async def test_create_on_absent_key_is_200_created(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    _patch_state_cap_not_hit(monkeypatch)
    appended = _patch_state_audit_append(monkeypatch)

    async def _create_agent_state_if_absent(_session, **kwargs):
        return {
            "state_key": kwargs["state_key"],
            "state_value": kwargs["state_value"],
            "version": 1,
            "updated_at": "2026-07-08T12:00:00+00:00",
            "updated_by_agent_id": kwargs["updated_by_agent_id"],
        }

    monkeypatch.setattr(
        messaging_router, "create_agent_state_if_absent", _create_agent_state_if_absent
    )
    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": None, "value": {"x": 1}}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert body["state_key"] == "my-key"
    assert appended[0]["disposition"] == "created"
    assert appended[0]["version"] == 1


async def test_create_on_existing_key_is_409_already_exists_with_current_version(
    test_app, monkeypatch
):
    _patch_tenant_session(monkeypatch)

    async def _create_agent_state_if_absent(_session, **_kwargs):
        return None  # ON CONFLICT DO NOTHING -> the row already existed

    async def _get_agent_state(_session, state_key):
        return {
            "state_key": state_key,
            "state_value": {"x": 99},
            "version": 3,
            "updated_at": "2026-07-08T12:00:00+00:00",
            "updated_by_agent_id": None,
        }

    monkeypatch.setattr(
        messaging_router, "create_agent_state_if_absent", _create_agent_state_if_absent
    )
    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": None, "value": {"x": 1}}
    )
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"]["code"] == "already_exists"
    assert body["current_version"] == 3


# --------------------------------------------------------------------------- #
# PUT /v1/state/{state_key} — per-tenant state-key cap (security-auditor follow-up).
# --------------------------------------------------------------------------- #


async def test_create_on_existing_key_skips_cap_check_entirely(test_app, monkeypatch):
    """An existing-key create attempt (-> 409 already_exists) never adds a new key, so it
    must never touch the cap lock/count at all — not just "never be blocked" by them."""
    _patch_tenant_session(monkeypatch)

    existing_row = {
        "state_key": "my-key",
        "state_value": {"x": 99},
        "version": 3,
        "updated_at": "2026-07-08T12:00:00+00:00",
        "updated_by_agent_id": None,
    }

    async def _get_agent_state(_session, _state_key):
        return existing_row

    async def _never_called(*_args, **_kwargs):
        raise AssertionError("must not be called when the state_key already exists")

    async def _create_agent_state_if_absent(_session, **_kwargs):
        return None  # ON CONFLICT DO NOTHING -> the row already existed

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    monkeypatch.setattr(messaging_router, "lock_messaging_state_key_cap", _never_called)
    monkeypatch.setattr(messaging_router, "count_agent_state_keys", _never_called)
    monkeypatch.setattr(
        messaging_router, "create_agent_state_if_absent", _create_agent_state_if_absent
    )

    resp = await _put(
        test_app, "/v1/state/my-key", json_body={"expected_version": None, "value": {"x": 1}}
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "already_exists"


async def test_state_key_cap_at_limit_returns_422_and_does_not_insert(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_agent_state(_session, _state_key):
        return None  # brand-new key

    async def _lock_messaging_state_key_cap(_session, _tenant_id):
        return None

    async def _count_agent_state_keys(_session):
        return 2  # at the configured cap below

    async def _create_should_not_be_called(_session, **_kwargs):
        raise AssertionError("create_agent_state_if_absent must not be called over the cap")

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    monkeypatch.setattr(
        messaging_router, "lock_messaging_state_key_cap", _lock_messaging_state_key_cap
    )
    monkeypatch.setattr(messaging_router, "count_agent_state_keys", _count_agent_state_keys)
    monkeypatch.setattr(
        messaging_router, "create_agent_state_if_absent", _create_should_not_be_called
    )

    monkeypatch.setenv("ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT", "2")
    from orchestrator.app import create_app

    capped_app = create_app()
    capped_app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL

    resp = await _put(
        capped_app,
        "/v1/state/brand-new-key",
        json_body={"expected_version": None, "value": {"x": 1}},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "state_key_limit_exceeded"


async def test_version_matched_update_never_checks_state_key_cap(test_app, monkeypatch):
    """A version-matched UPDATE of an EXISTING key never adds a new key, so the cap check
    must never even be invoked on this path — regardless of how close to the cap the
    tenant is."""
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    appended = _patch_state_audit_append(monkeypatch)

    async def _never_called(*_args, **_kwargs):
        raise AssertionError("must not be called on a version-matched UPDATE")

    async def _update_agent_state_cas(_session, **kwargs):
        return {
            "state_key": "my-key",
            "state_value": kwargs["state_value"],
            "version": 3,
            "updated_at": "2026-07-08T12:00:01+00:00",
            "updated_by_agent_id": kwargs["updated_by_agent_id"],
        }

    monkeypatch.setattr(messaging_router, "lock_messaging_state_key_cap", _never_called)
    monkeypatch.setattr(messaging_router, "count_agent_state_keys", _never_called)
    monkeypatch.setattr(messaging_router, "update_agent_state_cas", _update_agent_state_cas)

    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": 2, "value": {"x": 2}},
    )
    assert resp.status_code == 200
    assert appended[0]["disposition"] == "updated"


# --------------------------------------------------------------------------- #
# PUT /v1/state/{state_key} — version-match update / version-mismatch (repo mocked).
# --------------------------------------------------------------------------- #


async def test_matching_version_update_succeeds_and_increments(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)
    appended = _patch_state_audit_append(monkeypatch)

    async def _update_agent_state_cas(_session, **kwargs):
        assert kwargs["expected_version"] == 2
        return {
            "state_key": "my-key",
            "state_value": kwargs["state_value"],
            "version": 3,
            "updated_at": "2026-07-08T12:00:01+00:00",
            "updated_by_agent_id": kwargs["updated_by_agent_id"],
        }

    monkeypatch.setattr(messaging_router, "update_agent_state_cas", _update_agent_state_cas)
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": 2, "value": {"x": 2}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 3
    assert appended[0]["disposition"] == "updated"
    assert appended[0]["version"] == 3


async def test_version_mismatch_is_409_version_conflict_with_current_version(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _update_agent_state_cas(_session, **_kwargs):
        return None  # the WHERE version = :expected matched zero rows

    async def _get_agent_state(_session, state_key):
        return {
            "state_key": state_key,
            "state_value": {"x": 5},
            "version": 5,
            "updated_at": "2026-07-08T12:00:00+00:00",
            "updated_by_agent_id": None,
        }

    monkeypatch.setattr(messaging_router, "update_agent_state_cas", _update_agent_state_cas)
    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    resp = await _put(
        test_app,
        "/v1/state/my-key",
        json_body={"expected_version": 1, "value": {"x": 2}},
    )
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"]["code"] == "version_conflict"
    assert body["current_version"] == 5


async def test_version_mismatch_on_absent_key_echoes_null_current_version(test_app, monkeypatch):
    """A non-null expected_version on a key that was NEVER created: there is no "current
    version" to echo, so current_version is null (a documented, deliberate design choice —
    see ADR-0012 — rather than a separate 404 branch for this specific combination)."""
    _patch_tenant_session(monkeypatch)

    async def _update_agent_state_cas(_session, **_kwargs):
        return None

    async def _get_agent_state(_session, state_key):
        return None

    monkeypatch.setattr(messaging_router, "update_agent_state_cas", _update_agent_state_cas)
    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    resp = await _put(
        test_app,
        "/v1/state/never-created",
        json_body={"expected_version": 1, "value": {"x": 2}},
    )
    assert resp.status_code == 409
    assert resp.json()["current_version"] is None


# --------------------------------------------------------------------------- #
# GET /v1/state/{state_key} — 404 for unknown key (repo mocked).
# --------------------------------------------------------------------------- #


async def test_get_unknown_key_is_404(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_agent_state(_session, _state_key):
        return None

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    resp = await _get(test_app, "/v1/state/missing-key")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


async def test_get_oversized_state_key_is_422_not_a_silent_no_match(test_app):
    """GET must reject an oversized state_key the same way PUT already does (code-reviewer
    follow-up) — never fall through to a DB lookup that silently returns a 404 no-match."""
    resp = await _get(test_app, "/v1/state/" + ("k" * 257))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_get_known_key_is_200(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_agent_state(_session, state_key):
        return {
            "state_key": state_key,
            "state_value": {"x": 1},
            "version": 4,
            "updated_at": "2026-07-08T12:00:00+00:00",
            "updated_by_agent_id": "agent-a",
        }

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    resp = await _get(test_app, "/v1/state/my-key")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state_key"] == "my-key"
    assert body["value"] == {"x": 1}
    assert body["version"] == 4


# --------------------------------------------------------------------------- #
# Cross-tenant invisibility — the router always opens get_tenant_session with the
# CALLER'S OWN resolved principal (genuine RLS invisibility is proven end-to-end against
# a real Postgres in test_messaging_e2e.py).
# --------------------------------------------------------------------------- #


async def test_get_state_uses_the_callers_own_principal_for_the_session(app, monkeypatch):
    tenant_x = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    app.dependency_overrides[require_tenant_principal] = lambda: tenant_x
    seen: list[str] = []

    @contextlib.asynccontextmanager
    async def _fake(tenant_id):
        seen.append(tenant_id)
        yield _FakeSession()

    monkeypatch.setattr(messaging_router, "get_tenant_session", _fake)

    async def _get_agent_state(_session, _state_key):
        return None

    monkeypatch.setattr(messaging_router, "get_agent_state", _get_agent_state)
    await _get(app, "/v1/state/my-key")
    assert seen == [tenant_x]
