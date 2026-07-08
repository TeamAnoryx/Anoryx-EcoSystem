"""Unit tests for the O-014 command center + guarded rollback (ADR-0014). No DB.

Mirrors test_admin_router.py (operator-token boundary) and
test_external_gateway_router.py (repository-layer monkeypatching, no Postgres anywhere
in this file). Genuine end-to-end rollback correctness (byte-identical signed_record,
real chain persistence) lives in tests/integration/test_command_center_e2e.py — this
file proves the ROUTER's own logic.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest

from orchestrator.command_center import router as cc_router

_ADMIN_TOKEN = "unit-orch-admin-token"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = _ADMIN_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get(app, path: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=headers or {})


async def _post(app, path: str, *, headers=None, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(path, headers=headers or {}, json=json_body)


class _FakeSession:
    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class _FakePrivilegedSession:
    @contextlib.asynccontextmanager
    async def begin(self):
        yield None


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield _FakePrivilegedSession()

    monkeypatch.setattr(cc_router, "get_privileged_session", _fake)


def _patch_tenant_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield _FakeSession()

    monkeypatch.setattr(cc_router, "get_tenant_session", _fake)


_ADMIN_ROUTES = [
    ("GET", "/v1/admin/command-center/summary"),
    ("POST", "/v1/admin/policy-distributions/rollback"),
]


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
async def test_missing_auth_is_401(app, method, path):
    call = _get if method == "GET" else _post
    resp = await call(app, path)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
async def test_wrong_token_is_403(app, method, path):
    call = _get if method == "GET" else _post
    resp = await call(app, path, headers=_bearer("wrong-token"))
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# GET /v1/admin/command-center/summary
# --------------------------------------------------------------------------- #


async def test_summary_zero_fills_and_shapes_response(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _registry(_session):
        return {"healthy": 3}

    async def _distributions(_session, _since):
        return {"distributed": 5, "failed": 1}

    async def _automation(_session, _since):
        return {}

    async def _external_gateway(_session, _since):
        return {"allowed": 10, "rate_limited": 2}

    async def _ingest_count(_session, _since):
        return 42

    async def _rollback_count(_session, _since):
        return 0

    monkeypatch.setattr(cc_router, "count_registry_by_status", _registry)
    monkeypatch.setattr(cc_router, "count_distributions_by_state_since", _distributions)
    monkeypatch.setattr(cc_router, "count_automation_executions_by_disposition_since", _automation)
    monkeypatch.setattr(cc_router, "count_external_gateway_by_outcome_since", _external_gateway)
    monkeypatch.setattr(cc_router, "count_ingest_events_since", _ingest_count)
    monkeypatch.setattr(cc_router, "count_rollbacks_since", _rollback_count)

    resp = await _get(app, "/v1/admin/command-center/summary", headers=_bearer())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registry"] == {
        "unknown": 0,
        "healthy": 3,
        "degraded": 0,
        "unreachable": 0,
    }
    assert body["distributions"] == {
        "pending": 0,
        "distributed": 5,
        "partial": 0,
        "failed": 1,
    }
    assert body["automation_executions"] == {"executed": 0, "failed": 0}
    assert body["external_gateway"] == {
        "allowed": 10,
        "scope_denied": 0,
        "rate_limited": 2,
        "revoked": 0,
    }
    assert body["ingest_events_count"] == 42
    assert body["rollbacks_count"] == 0
    assert body["lookback_hours"] == 24


# --------------------------------------------------------------------------- #
# POST /v1/admin/policy-distributions/rollback
# --------------------------------------------------------------------------- #


def _valid_rollback_body(**overrides) -> dict:
    body = {"tenant_id": "tenant-a", "policy_id": "policy-1"}
    body.update(overrides)
    return body


async def test_rollback_unknown_field_is_422(app):
    resp = await _post(
        app,
        "/v1/admin/policy-distributions/rollback",
        headers=_bearer(),
        json_body=_valid_rollback_body(surprise="field"),
    )
    assert resp.status_code == 422


async def test_rollback_missing_field_is_422(app):
    body = _valid_rollback_body()
    del body["policy_id"]
    resp = await _post(
        app, "/v1/admin/policy-distributions/rollback", headers=_bearer(), json_body=body
    )
    assert resp.status_code == 422


async def test_rollback_oversized_tenant_id_is_422(app):
    resp = await _post(
        app,
        "/v1/admin/policy-distributions/rollback",
        headers=_bearer(),
        json_body=_valid_rollback_body(tenant_id="t" * 65),
    )
    assert resp.status_code == 422


async def test_rollback_with_fewer_than_two_distributions_is_409(app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _fake_recent(_session, *, policy_id, limit):
        return [{"distribution_id": "only-one"}]

    monkeypatch.setattr(cc_router, "list_recent_distributions_for_policy", _fake_recent)

    resp = await _post(
        app,
        "/v1/admin/policy-distributions/rollback",
        headers=_bearer(),
        json_body=_valid_rollback_body(),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "nothing_to_roll_back_to"


async def test_rollback_happy_path_copies_signed_record_and_audits(app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_privileged_session(monkeypatch)

    current = {
        "distribution_id": "dist-current",
        "policy_version": 3,
        "policy_type": "budget_limit",
        "signed_record": {"policy_id": "policy-1", "policy_version": 3},
        "content_hash": "c" * 64,
    }
    previous = {
        "distribution_id": "dist-previous",
        "policy_version": 2,
        "policy_type": "budget_limit",
        "signed_record": {"policy_id": "policy-1", "policy_version": 2},
        "content_hash": "b" * 64,
    }

    async def _fake_recent(_session, *, policy_id, limit):
        return [current, previous]

    async def _fake_targets(_session, distribution_id):
        assert distribution_id == "dist-previous"
        return [{"sentinel_id": "sentinel-a", "max_attempts": 5}]

    inserted_distributions = []
    inserted_targets = []

    async def _fake_insert_distribution(_session, row):
        inserted_distributions.append(row)

    async def _fake_insert_target(_session, row):
        inserted_targets.append(row)

    audit_calls = []
    rollback_calls = []

    async def _fake_append_distribution_audit(_session, fields, *, disposition, **kwargs):
        audit_calls.append((fields, disposition))
        return "fake-hash"

    async def _fake_append_rollback_audit(_session, **kwargs):
        rollback_calls.append(kwargs)
        return "fake-hash"

    drive_calls = []

    async def _fake_drive(distribution_id, tenant_id, *, settings):
        drive_calls.append((distribution_id, tenant_id))

    monkeypatch.setattr(cc_router, "list_recent_distributions_for_policy", _fake_recent)
    monkeypatch.setattr(cc_router, "list_distribution_targets", _fake_targets)
    monkeypatch.setattr(cc_router, "insert_policy_distribution", _fake_insert_distribution)
    monkeypatch.setattr(cc_router, "insert_distribution_target", _fake_insert_target)
    monkeypatch.setattr(
        cc_router, "append_distribution_audit_link", _fake_append_distribution_audit
    )
    monkeypatch.setattr(cc_router, "append_rollback_audit_link", _fake_append_rollback_audit)
    monkeypatch.setattr(cc_router, "drive_distribution", _fake_drive)

    resp = await _post(
        app,
        "/v1/admin/policy-distributions/rollback",
        headers=_bearer(),
        json_body=_valid_rollback_body(),
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["rolled_back_to_distribution_id"] == "dist-previous"
    assert body["superseded_distribution_id"] == "dist-current"
    new_distribution_id = body["distribution_id"]

    assert len(inserted_distributions) == 1
    assert inserted_distributions[0]["signed_record"] == previous["signed_record"]
    assert inserted_distributions[0]["content_hash"] == previous["content_hash"]
    assert inserted_distributions[0]["policy_version"] == previous["policy_version"]
    assert inserted_distributions[0]["distribution_id"] == new_distribution_id

    assert len(inserted_targets) == 1
    assert inserted_targets[0]["sentinel_id"] == "sentinel-a"
    assert inserted_targets[0]["distribution_id"] == new_distribution_id

    assert audit_calls == [
        (
            {
                "distribution_id": new_distribution_id,
                "policy_id": "policy-1",
                "tenant_id": "tenant-a",
                "policy_type": "budget_limit",
            },
            "submitted",
        )
    ]
    assert rollback_calls == [
        {
            "tenant_id": "tenant-a",
            "policy_id": "policy-1",
            "source_distribution_id": "dist-previous",
            "superseded_distribution_id": "dist-current",
            "new_distribution_id": new_distribution_id,
        }
    ]
    assert drive_calls == [(new_distribution_id, "tenant-a")]
