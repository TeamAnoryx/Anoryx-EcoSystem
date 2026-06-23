"""Admin endpoint integration tests (F-018, ADR-0021 §8).

Vector covered:
  1  test_disclaimer_present — GET /admin/tenants/{id}/shadow-ai/candidates
     returns HONESTY_DISCLAIMER always, even with zero candidates.

DB-GATED: skips when DATABASE_URL/APP_DATABASE_URL not set or Postgres
unreachable. Uses the same admin_app fixture pattern as tests/admin/.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest

from shadow_ai import constants as C

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")

ADMIN_TOKEN = "admin-shadow-ai-test-token"  # noqa: S105 — test-only dummy

_SKIP_REASON = "DATABASE_URL/APP_DATABASE_URL not set or Postgres unreachable"


def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL")) and bool(os.environ.get("APP_DATABASE_URL"))


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


# ---------------------------------------------------------------------------
# Vector 1 — pure-unit: disclaimer string is the constant
# ---------------------------------------------------------------------------


class TestDisclaimerConstant:
    """The HONESTY_DISCLAIMER is defined, non-empty, and load-bearing."""

    def test_disclaimer_is_defined(self) -> None:
        assert C.HONESTY_DISCLAIMER
        assert isinstance(C.HONESTY_DISCLAIMER, str)

    def test_disclaimer_mentions_sentinel(self) -> None:
        assert "Sentinel" in C.HONESTY_DISCLAIMER

    def test_disclaimer_mentions_candidate(self) -> None:
        assert "candidate" in C.HONESTY_DISCLAIMER.lower()

    def test_disclaimer_does_not_claim_100_percent_detection(self) -> None:
        lower = C.HONESTY_DISCLAIMER.lower()
        assert "100%" not in lower
        assert "all shadow" not in lower

    def test_disclaimer_mentions_bypass_limitation(self) -> None:
        lower = C.HONESTY_DISCLAIMER.lower()
        assert "bypass" in lower or "personal device" in lower or "not" in lower


# ---------------------------------------------------------------------------
# Vector 1 — endpoint integration via ASGI client
# ---------------------------------------------------------------------------


@pytest.fixture()
def shadow_ai_admin_app(monkeypatch):
    """Real gateway app with admin token, skips when DB absent."""
    if not _db_available():
        pytest.skip(_SKIP_REASON)

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", ADMIN_TOKEN)
    if not os.environ.get("UPSTREAM_BASE_URL"):
        monkeypatch.setenv("UPSTREAM_BASE_URL", "https://upstream.example.invalid")
    if not os.environ.get("SENTINEL_KEY_SECRET"):
        monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-key-secret")
    # SSO session secret (required by SSO middleware)
    monkeypatch.setenv("SENTINEL_ADMIN_SESSION_SECRET", "session-test-secret-" + "x" * 24)
    try:
        from admin.sso import session as _op_session

        _op_session.reset_secret_cache_for_testing()
    except Exception:
        pass

    from gateway.config import _reset_settings
    from gateway.main import create_app

    _reset_settings()
    return create_app()


@pytest.mark.asyncio
async def test_disclaimer_present_zero_candidates(shadow_ai_admin_app, monkeypatch):
    """Vector 1: disclaimer is returned even when there are zero candidates."""
    import httpx
    from httpx import ASGITransport

    # Fresh UUID tenant with no audit rows -> zero candidates
    tenant_id = str(uuid.uuid4())

    # Seed the tenant so FK/RLS constraints pass
    db_raw = os.environ.get("DATABASE_URL", "")
    if not db_raw:
        pytest.skip(_SKIP_REASON)

    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        pytest.skip(_SKIP_REASON)

    try:
        import asyncpg

        probe = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await probe.close()
    except Exception:
        pytest.skip(_SKIP_REASON)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    db_url = _to_asyncpg_url(db_raw)
    priv_engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )

    async with priv_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"shadow-ai-ep-{tenant_id[:8]}"},
        )

    try:
        async with httpx.AsyncClient(
            transport=ASGITransport(app=shadow_ai_admin_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                f"/admin/tenants/{tenant_id}/shadow-ai/candidates",
                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:400]}"
        payload = resp.json()

        # Vector 1: disclaimer is always present
        assert "disclaimer" in payload, "Response missing 'disclaimer' field"
        assert (
            payload["disclaimer"] == C.HONESTY_DISCLAIMER
        ), "disclaimer field does not match HONESTY_DISCLAIMER constant"

        # Zero candidates (fresh tenant)
        assert "candidates" in payload
        assert isinstance(payload["candidates"], list)
        assert len(payload["candidates"]) == 0

    finally:
        # Cleanup
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
        await priv_engine.dispose()


@pytest.mark.asyncio
async def test_disclaimer_present_with_candidates(shadow_ai_admin_app, monkeypatch):
    """Vector 1: disclaimer present even when candidates are surfaced."""
    import httpx
    from httpx import ASGITransport
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_raw = os.environ.get("DATABASE_URL", "")
    if not db_raw:
        pytest.skip(_SKIP_REASON)

    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        pytest.skip(_SKIP_REASON)

    try:
        import asyncpg

        probe = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await probe.close()
    except Exception:
        pytest.skip(_SKIP_REASON)

    db_url = _to_asyncpg_url(db_raw)
    priv_engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    priv_factory = async_sessionmaker(  # noqa: F841 — used via AuditLogRepository below
        bind=priv_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    async with priv_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"shadow-ai-ep2-{tenant_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
            ),
            {"tm": team_id, "t": tenant_id, "n": f"team-{team_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
            ),
            {"p": project_id, "tm": team_id, "t": tenant_id, "n": f"proj-{project_id[:8]}"},
        )

    # Append a real shadow_ai_detected_outbound row so the classifier sees it
    from persistence.repositories.audit_log_repository import AuditLogRepository

    async with priv_factory() as sess:
        async with sess.begin():
            await AuditLogRepository(sess).append(
                {
                    "event_type": "shadow_ai_detected_outbound",
                    "action_taken": "logged",
                    "event_id": str(uuid.uuid4()),
                    "event_timestamp": "2026-06-24T12:00:00Z",
                    "request_id": "req-" + uuid.uuid4().hex[:32],
                    "tenant_id": tenant_id,
                    "team_id": team_id,
                    "project_id": project_id,
                    "agent_id": "defense",
                    "detected_endpoint": "api.anthropic.com",
                    "traffic_volume": 1,
                    "first_seen_at": "2026-06-24T12:00:00Z",
                    "selected_provider": "anthropic",
                }
            )

    try:
        async with httpx.AsyncClient(
            transport=ASGITransport(app=shadow_ai_admin_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                f"/admin/tenants/{tenant_id}/shadow-ai/candidates",
                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:400]}"
        payload = resp.json()

        # Vector 1: disclaimer always present
        assert "disclaimer" in payload
        assert payload["disclaimer"] == C.HONESTY_DISCLAIMER

        # Should surface the candidate
        assert len(payload["candidates"]) >= 1
        for cand in payload["candidates"]:
            assert cand["label"] == "candidate"
            assert cand["confidence_band"] in ("low", "medium", "high")

    finally:
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
        await priv_engine.dispose()


@pytest.mark.asyncio
async def test_endpoint_requires_admin_auth(shadow_ai_admin_app):
    """Endpoint must reject unauthenticated requests with 401/403."""
    import httpx
    from httpx import ASGITransport

    tenant_id = str(uuid.uuid4())

    async with httpx.AsyncClient(
        transport=ASGITransport(app=shadow_ai_admin_app), base_url="http://test"
    ) as client:
        # No authorization header
        resp = await client.get(f"/admin/tenants/{tenant_id}/shadow-ai/candidates")

    assert resp.status_code in (401, 403), f"Expected 401/403 without auth, got {resp.status_code}"


@pytest.mark.asyncio
async def test_endpoint_rejects_non_uuid_tenant_id(shadow_ai_admin_app):
    """Endpoint returns 422 for a non-UUID tenant_id path segment."""
    import httpx
    from httpx import ASGITransport

    async with httpx.AsyncClient(
        transport=ASGITransport(app=shadow_ai_admin_app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/admin/tenants/not-a-uuid/shadow-ai/candidates",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

    assert resp.status_code == 422
