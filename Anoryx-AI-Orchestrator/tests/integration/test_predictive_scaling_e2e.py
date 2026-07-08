"""Non-stubbed predictive-scaling e2e (O-015, ADR-0015).

Drives the REAL FastAPI app over httpx.ASGITransport (real auth resolution, real DB
reads) on a fresh Postgres, proving:

  * Real ingest_events seeded into the current and previous windows produce the correct
    per-window counts, rates, and projected_event_count_over_horizon.
  * A genuine rate increase between the two windows sets spike_detected: true.
  * A flat rate between the two windows does NOT set spike_detected.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

pytestmark = pytest.mark.integration

_ADMIN_TOKEN = "o015-operator-token"  # noqa: S105 - test-only fake


def _app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    monkeypatch.setenv("ORCH_PREDICTIVE_SCALING_WINDOW_HOURS", "1")
    monkeypatch.setenv("ORCH_PREDICTIVE_SCALING_HORIZON_HOURS", "24")
    monkeypatch.setenv("ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD", "2.0")
    from orchestrator.app import create_app

    return create_app()


async def _client(app) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://orch")


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


async def _seed_event_at(db_conn, *, tenant_id: str, event_timestamp: datetime) -> str:
    """INSERT one ingest_events row with an explicit event_timestamp (privileged conn)."""
    eid = str(uuid.uuid4())
    short = eid[:8]
    ts_str = event_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    await db_conn.execute(
        "INSERT INTO ingest_events (envelope_id, idempotency_key, source_product, "
        "source_sequence, schema_version, occurred_at, correlation_id, event_id, event_type, "
        "event_timestamp, request_id, tenant_id, team_id, project_id, agent_id, payload, "
        "content_hash) VALUES ($1, $2, 'sentinel', 1024, 1, $3, $4, $5, "
        "'policy_decision_deny', $6, $7, $8, $9, $10, 'gateway-core', $11::jsonb, $12)",
        str(uuid.uuid4()),
        eid,
        ts_str,
        "req-" + short,
        eid,
        ts_str,
        "req-" + short,
        tenant_id,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        '{"note": "not exposed on the forecast endpoint"}',
        "c" * 64,
    )
    return eid


# NOTE ON ORDERING: the forecast is deliberately CROSS-TENANT (mirrors every other O-014
# admin read), and every window is relative to REAL wall-clock `now()` at call time — so
# within this one file (the only place in the suite that seeds `ingest_events` with
# now()-relative timestamps), an EARLIER test's seeded rows can still fall inside a LATER
# test's own current/previous window. The flat-traffic test therefore runs FIRST, while
# no other now()-relative rows exist yet; the spike test runs second and asserts with
# `>=`/inequalities that are safe even if it additionally picks up the flat test's own
# (small, non-spiky) rows.


async def test_flat_traffic_is_not_flagged_as_a_spike(
    predictive_scaling_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Same count (3) in both windows -- a flat rate. Offsets keep a safe margin from
    # both the 60-minute window boundary and "now" itself, so the small delay between
    # capturing `now` here and the server computing its OWN `now` a moment later can
    # never flip which window an event lands in (a boundary-adjacent offset like exactly
    # 60 minutes is flaky for exactly that reason).
    for offset_minutes in (110, 95, 80):
        await _seed_event_at(
            db_conn, tenant_id=tenant_id, event_timestamp=now - timedelta(minutes=offset_minutes)
        )
    for offset_minutes in (50, 35, 20):
        await _seed_event_at(
            db_conn, tenant_id=tenant_id, event_timestamp=now - timedelta(minutes=offset_minutes)
        )

    async with await _client(app) as client:
        resp = await client.get("/v1/admin/traffic-forecast", headers=_admin_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["insufficient_data"] is False
    assert body["spike_ratio"] == pytest.approx(1.0, abs=0.5)
    assert body["spike_detected"] is False


async def test_forecast_reflects_real_windowed_counts_and_detects_a_spike(
    predictive_scaling_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Previous window: [now - 2h, now - 1h) -- 2 events.
    for offset_minutes in (90, 75):
        await _seed_event_at(
            db_conn, tenant_id=tenant_id, event_timestamp=now - timedelta(minutes=offset_minutes)
        )
    # Current window: [now - 1h, now) -- 8 events (a genuine rate increase; the >= 2.0
    # assertion below holds regardless of any residual rows the flat-traffic test above
    # may also contribute to these same real-time windows).
    for offset_minutes in (50, 40, 30, 25, 20, 15, 10, 5):
        await _seed_event_at(
            db_conn, tenant_id=tenant_id, event_timestamp=now - timedelta(minutes=offset_minutes)
        )

    async with await _client(app) as client:
        resp = await client.get("/v1/admin/traffic-forecast", headers=_admin_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["method"] == "current_rate_projection_v1"
    assert body["current_window"]["event_count"] >= 8
    assert body["previous_window"]["event_count"] >= 2
    assert body["insufficient_data"] is False
    assert body["spike_ratio"] >= 2.0
    assert body["spike_detected"] is True
    assert body["projected_event_count_over_horizon"] == pytest.approx(
        body["current_window"]["rate_per_hour"] * 24
    )
