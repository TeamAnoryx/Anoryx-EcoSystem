"""Health endpoint threat model + behavior tests (F-010, ADR-0012 §6/§9).

Covers deployment threat-model vectors:
  1  test_livez_does_not_touch_db                       — liveness performs no DB I/O (R5)
  2  test_readyz_503_when_postgres_down                 — readiness 503 on Postgres down
  3  test_readyz_200_with_degraded_flag_when_redis_down — Redis non-gating (F-009 γ, ADR-0012 §12)
  3b test_readyz_does_not_trigger_redis_probe           — readiness opens no fresh Redis connection
  4  test_health_endpoints_no_sensitive_content         — no secrets/URLs leaked
  R-a test_backcompat_health_endpoints_unchanged        — /health + /ready exact ADR-0006 D2 shapes
  R-b test_healthz_aliases_readyz                        — /healthz == /readyz

Endpoints are unauthenticated by design (operational, out-of-contract). The app is
exercised via httpx.ASGITransport (no real server, lifespan not triggered — so
Redis/HTTP pools are never initialised, matching the gateway test convention).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gateway import __version__
from gateway.main import create_app

# Endpoints under test.
_LIVENESS_NEW = "/livez"
_READINESS_NEW = "/readyz"
_READINESS_ALIAS = "/healthz"
_LIVENESS_OLD = "/health"
_READINESS_OLD = "/ready"


@pytest.fixture()
def app(settings_env):
    """Build the gateway app (env provided by the autouse _ensure_gateway_env)."""
    return create_app()


@asynccontextmanager
async def _client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _pg_session_cm(ok: bool):
    """Return a get_privileged_session replacement.

    ok=True  → yields a session whose SELECT 1 succeeds.
    ok=False → raises on enter (simulating Postgres unreachable).
    """

    @asynccontextmanager
    async def _cm():
        if not ok:
            raise RuntimeError("simulated postgres outage")
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        session.execute = AsyncMock(return_value=MagicMock())
        yield session

    return _cm


# --------------------------------------------------------------------------- #
# Vector 1 — liveness never touches the database (R5).                        #
# --------------------------------------------------------------------------- #
async def test_livez_does_not_touch_db(app):
    """A liveness probe MUST NOT open a DB session even when Postgres is down."""
    sentinel = MagicMock(side_effect=AssertionError("/livez opened a DB session"))
    with patch("gateway.routes.health.get_privileged_session", sentinel):
        async with _client(app) as c:
            resp = await c.get(_LIVENESS_NEW)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "alive"
    assert body["postgres"] == "not_checked"  # liveness never probes the DB
    assert body["version"] == __version__
    sentinel.assert_not_called()


# --------------------------------------------------------------------------- #
# Vector 2 — readiness 503 when Postgres is unreachable (hard dependency).     #
# --------------------------------------------------------------------------- #
async def test_readyz_503_when_postgres_down(app):
    with patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=False)):
        async with _client(app) as c:
            resp = await c.get(_READINESS_NEW)
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["postgres"] == "unhealthy"


# --------------------------------------------------------------------------- #
# Vector 3 — Redis down is NON-gating: 200 + degraded flag (ADR-0012 §12).     #
# --------------------------------------------------------------------------- #
async def test_readyz_200_with_degraded_flag_when_redis_down(app):
    with (
        patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=True)),
        patch("gateway.redis_client.is_degraded", return_value=True),
    ):
        async with _client(app) as c:
            resp = await c.get(_READINESS_NEW)
    assert resp.status_code == 200  # Redis down does NOT remove the pod from service
    body = resp.json()
    assert body["status"] == "ready"
    assert body["postgres"] == "healthy"
    assert body["redis"] == "degraded"


# --------------------------------------------------------------------------- #
# Vector 3b — readiness reads the F-009 flag, never opens a fresh connection.  #
# --------------------------------------------------------------------------- #
async def test_readyz_does_not_trigger_redis_probe(app):
    """Readiness MUST read is_degraded() (the gauge-mirrored flag), not probe Redis."""
    probe = MagicMock(side_effect=AssertionError("/readyz opened a Redis connection"))
    with (
        patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=True)),
        patch("gateway.redis_client.get_client", probe),
    ):
        async with _client(app) as c:
            resp = await c.get(_READINESS_NEW)
    assert resp.status_code == 200
    probe.assert_not_called()


# --------------------------------------------------------------------------- #
# Vector 4 — no secrets / connection strings / build info beyond app version.  #
# --------------------------------------------------------------------------- #
async def test_health_endpoints_no_sensitive_content(app):
    forbidden = (
        "password",
        "secret",
        "postgresql://",
        "postgresql+asyncpg://",
        "redis://",
        "sk-",
        "database_url",
        "bearer",
        "@",  # would appear inside any leaked connection URL
    )
    with (
        patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=True)),
        patch("gateway.redis_client.is_degraded", return_value=False),
    ):
        async with _client(app) as c:
            for path in (_LIVENESS_NEW, _READINESS_NEW, _READINESS_ALIAS):
                resp = await c.get(path)
                raw = resp.text.lower()
                for token in forbidden:
                    assert token not in raw, f"{path} leaked '{token}': {resp.text}"
                # Only the app release version is disclosed (allowed — vector 4).
                assert __version__ in resp.text


# --------------------------------------------------------------------------- #
# Regression R-a — preserved ADR-0006 D2 endpoints keep their EXACT shapes.    #
# --------------------------------------------------------------------------- #
async def test_backcompat_health_endpoints_unchanged(app):
    # /health: exact legacy liveness body, no DB touch.
    sentinel = MagicMock(side_effect=AssertionError("/health opened a DB session"))
    with patch("gateway.routes.health.get_privileged_session", sentinel):
        async with _client(app) as c:
            resp = await c.get(_LIVENESS_OLD)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}  # byte-identical legacy shape
    sentinel.assert_not_called()

    # /ready healthy: exact legacy readiness body.
    with patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=True)):
        async with _client(app) as c:
            resp = await c.get(_READINESS_OLD)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}

    # /ready unhealthy: exact legacy 503 body.
    with patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=False)):
        async with _client(app) as c:
            resp = await c.get(_READINESS_OLD)
    assert resp.status_code == 503
    assert resp.json() == {"status": "unavailable"}


# --------------------------------------------------------------------------- #
# Regression R-b — /healthz is a faithful alias of /readyz.                     #
# --------------------------------------------------------------------------- #
async def test_healthz_aliases_readyz(app):
    with (
        patch("gateway.routes.health.get_privileged_session", _pg_session_cm(ok=True)),
        patch("gateway.redis_client.is_degraded", return_value=False),
    ):
        async with _client(app) as c:
            readyz = await c.get(_READINESS_NEW)
            healthz = await c.get(_READINESS_ALIAS)
    assert readyz.status_code == healthz.status_code == 200
    assert readyz.json() == healthz.json()
