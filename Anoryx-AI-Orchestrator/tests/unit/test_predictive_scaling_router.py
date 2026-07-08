"""Unit tests for the O-015 predictive-scaling traffic forecast (ADR-0015). No DB.

Mirrors test_admin_router.py (operator-token boundary) and
test_command_center_router.py (repository-layer monkeypatching, no Postgres anywhere in
this file). Genuine end-to-end correctness (real seeded ingest_events) lives in
tests/integration/test_predictive_scaling_e2e.py — this file proves the ROUTER's own
projection math and boundary logic.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest

from orchestrator.predictive_scaling import router as ps_router

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


async def test_missing_auth_is_401(app):
    resp = await _get(app, "/v1/admin/traffic-forecast")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_wrong_token_is_403(app):
    resp = await _get(app, "/v1/admin/traffic-forecast", headers=_bearer("wrong-token"))
    assert resp.status_code == 403


def _patch_privileged_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake():
        yield object()

    monkeypatch.setattr(ps_router, "get_privileged_session", _fake)


def _patch_counts(monkeypatch, *, current: int, previous: int):
    _patch_privileged_session(monkeypatch)
    calls = []

    async def _fake_count(_session, *, since, until):
        calls.append((since, until))
        # First call is the current window (most recent), second is the previous.
        return current if len(calls) == 1 else previous

    monkeypatch.setattr(ps_router, "count_ingest_events_in_window", _fake_count)
    return calls


async def test_genuine_spike_is_detected(app, monkeypatch):
    _patch_counts(monkeypatch, current=20, previous=5)
    resp = await _get(app, "/v1/admin/traffic-forecast", headers=_bearer())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["method"] == "current_rate_projection_v1"
    assert body["current_window"]["event_count"] == 20
    assert body["previous_window"]["event_count"] == 5
    assert body["spike_ratio"] == pytest.approx(4.0)
    assert body["spike_detected"] is True
    assert body["insufficient_data"] is False
    # window_hours defaults to 1, horizon_hours defaults to 24.
    assert body["current_window"]["rate_per_hour"] == pytest.approx(20.0)
    assert body["projected_event_count_over_horizon"] == pytest.approx(20.0 * 24)


async def test_flat_rate_is_not_a_spike(app, monkeypatch):
    _patch_counts(monkeypatch, current=10, previous=10)
    resp = await _get(app, "/v1/admin/traffic-forecast", headers=_bearer())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["spike_ratio"] == pytest.approx(1.0)
    assert body["spike_detected"] is False
    assert body["insufficient_data"] is False


async def test_zero_previous_window_is_insufficient_data_not_a_crash(app, monkeypatch):
    _patch_counts(monkeypatch, current=5, previous=0)
    resp = await _get(app, "/v1/admin/traffic-forecast", headers=_bearer())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["insufficient_data"] is True
    assert body["spike_ratio"] is None
    assert body["spike_detected"] is False


async def test_ratio_below_threshold_is_not_a_spike(app, monkeypatch):
    # 1.5x increase, default threshold is 2.0 -> not a spike.
    _patch_counts(monkeypatch, current=15, previous=10)
    resp = await _get(app, "/v1/admin/traffic-forecast", headers=_bearer())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["spike_ratio"] == pytest.approx(1.5)
    assert body["spike_detected"] is False
