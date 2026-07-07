"""Unit tests for the O-007 admin API (ADR-0007). No DB.

Mirrors test_coordination_router_auth.py (operator-token boundary: 401/403/fail-closed) and
test_query_router.py (limit clamp + metadata-only response shape), but for the NEW
cross-tenant `/v1/admin/events/recent` and `/v1/admin/distributions/recent` reads. The
privileged session is replaced with a fake CM (no Postgres) and the repo functions are
monkeypatched so these tests assert router behavior only.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone

import httpx
import pytest

from orchestrator.admin import router as admin_router

_ADMIN_TOKEN = "unit-orch-admin-token"  # noqa: S105 - test-only fake


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def app_no_token(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    monkeypatch.delenv("ORCH_ADMIN_TOKEN", raising=False)
    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = _ADMIN_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get(app, path: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=headers or {})


def _patch_privileged_session(monkeypatch):
    """Replace get_privileged_session in the admin router with a fake CM (no DB)."""

    @contextlib.asynccontextmanager
    async def _fake():
        yield object()

    monkeypatch.setattr(admin_router, "get_privileged_session", _fake)


_ROUTES = [
    ("GET", "/v1/admin/events/recent"),
    ("GET", "/v1/admin/distributions/recent"),
]


# --------------------------------------------------------------------------- #
# Operator-auth boundary (mirrors the registry seam's fail-closed posture).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("method", "path"), _ROUTES)
async def test_missing_auth_is_401(app, method, path):
    resp = await _get(app, path)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(("method", "path"), _ROUTES)
async def test_wrong_token_is_403(app, method, path):
    resp = await _get(app, path, headers=_bearer("not-the-token"))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize(("method", "path"), _ROUTES)
async def test_unconfigured_admin_token_is_401(app_no_token, method, path):
    # Fail-closed: with no admin token configured, even a presented bearer can never match.
    resp = await _get(app_no_token, path, headers=_bearer())
    assert resp.status_code == 401


async def test_non_bearer_header_is_401(app):
    resp = await _get(app, "/v1/admin/events/recent", headers={"Authorization": _ADMIN_TOKEN})
    assert resp.status_code == 401


async def test_empty_bearer_is_401(app):
    resp = await _get(app, "/v1/admin/events/recent", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Recent events.
# --------------------------------------------------------------------------- #


async def test_recent_events_is_cross_tenant_and_metadata_only(app, monkeypatch):
    _patch_privileged_session(monkeypatch)

    async def _list_recent_events_admin(_session, *, limit):
        return [
            {
                "event_id": "e1",
                "event_type": "policy_decision_deny",
                "event_timestamp": "2026-07-01T00:00:00Z",
                "tenant_id": "tenant-a",
                "team_id": "t1",
                "project_id": "p1",
                "agent_id": "gateway-core",
                "request_id": "req-1",
            },
            {
                "event_id": "e2",
                "event_type": "policy_decision_allow",
                "event_timestamp": "2026-07-01T00:00:05Z",
                "tenant_id": "tenant-b",
                "team_id": "t2",
                "project_id": "p2",
                "agent_id": "gateway-core",
                "request_id": "req-2",
            },
        ]

    monkeypatch.setattr(admin_router, "list_recent_events_admin", _list_recent_events_admin)
    resp = await _get(app, "/v1/admin/events/recent", headers=_bearer())
    assert resp.status_code == 200
    body = resp.json()
    tenants = {row["tenant_id"] for row in body["data"]}
    assert tenants == {"tenant-a", "tenant-b"}  # cross-tenant, unlike /v1/events
    assert "payload" not in body["data"][0]


async def test_recent_events_limit_is_clamped_before_repo(app, monkeypatch):
    _patch_privileged_session(monkeypatch)
    seen: dict[str, int] = {}

    async def _list_recent_events_admin(_session, *, limit):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(admin_router, "list_recent_events_admin", _list_recent_events_admin)
    await _get(app, "/v1/admin/events/recent?limit=9999", headers=_bearer())
    assert seen["limit"] == 200
    await _get(app, "/v1/admin/events/recent?limit=0", headers=_bearer())
    assert seen["limit"] == 1
    await _get(app, "/v1/admin/events/recent", headers=_bearer())
    assert seen["limit"] == 50


# --------------------------------------------------------------------------- #
# Recent distributions.
# --------------------------------------------------------------------------- #


async def test_recent_distributions_is_cross_tenant_and_never_leaks_policy_body(app, monkeypatch):
    _patch_privileged_session(monkeypatch)
    created = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    async def _list_recent_distributions_admin(_session, *, limit):
        return [
            {
                "distribution_id": "d1",
                "policy_id": "p1",
                "tenant_id": "tenant-a",
                "policy_type": "budget_limit",
                "state": "distributed",
                "created_at": created,
                # Leak canaries the response projection must drop.
                "signed_record": {"secret": "leak"},
                "content_hash": "deadbeef",
            }
        ]

    monkeypatch.setattr(
        admin_router, "list_recent_distributions_admin", _list_recent_distributions_admin
    )
    resp = await _get(app, "/v1/admin/distributions/recent", headers=_bearer())
    assert resp.status_code == 200
    body = resp.json()
    row = body["data"][0]
    assert row["created_at"] == created.isoformat()
    assert "signed_record" not in row
    assert "content_hash" not in row
    assert "secret" not in resp.text


async def test_recent_distributions_limit_is_clamped_before_repo(app, monkeypatch):
    _patch_privileged_session(monkeypatch)
    seen: dict[str, int] = {}

    async def _list_recent_distributions_admin(_session, *, limit):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(
        admin_router, "list_recent_distributions_admin", _list_recent_distributions_admin
    )
    await _get(app, "/v1/admin/distributions/recent?limit=-5", headers=_bearer())
    assert seen["limit"] == 1


# --------------------------------------------------------------------------- #
# Static UI shell.
# --------------------------------------------------------------------------- #


async def test_admin_ui_is_served_and_carries_no_secret(app):
    resp = await _get(app, "/admin")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert _ADMIN_TOKEN not in resp.text


async def test_admin_ui_is_public_shell_no_auth_required(app_no_token):
    # The static shell itself carries no data; only the two JSON endpoints are token-gated.
    resp = await _get(app_no_token, "/admin")
    assert resp.status_code == 200
