"""Admin auth primitive — threat model vectors 1, 2, 4 (ADR-0014 §11).

These are PURE-UNIT tests (no DB): require_admin never touches the virtual-key
path or Postgres. They exercise the real FastAPI app built by create_app(), so
they also prove the wiring — that AuthMiddleware and TenantContextMiddleware skip
the /admin prefix and require_admin is the sole authority there.

Vectors:
  1  test_tenant_principal_cannot_reach_admin_endpoints — a tenant Bearer key
     (and tenant ID headers) gets 401 on an admin route.
  2  test_admin_cannot_be_forged_from_tenant_creds — no header/token manipulation
     elevates a non-admin caller.
  4  test_no_admin_creds_fails_closed — SENTINEL_ADMIN_TOKEN unset -> 401, never
     tenant data, never fall-back.
Plus the happy path (correct token, NO tenant headers -> 200), which proves the
tenant middlewares skip /admin.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from admin.auth import ADMIN_PRINCIPAL

_ADMIN_TOKEN = "admin-secret-token-for-tests-only"  # noqa: S105 — test-only dummy
_TENANT_KEY = "sk-sentinel-tenant-not-admin"
_WHOAMI = "/admin/whoami"


def _build_app(monkeypatch, *, admin_token: str | None):
    """Build the real gateway app with dummy required settings.

    create_app() reads required settings (upstream_base_url / database_url /
    app_database_url / sentinel_key_secret) but does NOT connect at construction
    (engines are lazy), so dummy values are sufficient for auth-only routes.
    """
    monkeypatch.setenv("UPSTREAM_BASE_URL", "https://upstream.example.invalid")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/sentinel")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://a:p@localhost:5432/sentinel")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-key-secret")
    # list[str] settings are JSON-decoded from env by pydantic-settings; the root
    # .env (loaded into os.environ by conftest) carries non-JSON values, so pin
    # valid JSON here to keep create_app() deterministic in tests.
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    if admin_token is None:
        monkeypatch.delenv("SENTINEL_ADMIN_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", admin_token)

    from gateway.config import _reset_settings
    from gateway.main import create_app

    _reset_settings()
    return create_app()


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _tenant_headers() -> dict[str, str]:
    """Well-formed tenant ID headers (would satisfy the tenant gate on /v1)."""
    return {
        "x-anoryx-tenant-id": str(uuid.uuid4()),
        "x-anoryx-team-id": str(uuid.uuid4()),
        "x-anoryx-project-id": str(uuid.uuid4()),
        "x-anoryx-agent-id": "gateway-core",
    }


@pytest.mark.asyncio
async def test_no_admin_creds_fails_closed(monkeypatch):
    """Vector 4: SENTINEL_ADMIN_TOKEN unset -> every admin route 401, never tenant data."""
    app = _build_app(monkeypatch, admin_token=None)
    async with _client(app) as client:
        # No auth at all.
        r = await client.get(_WHOAMI)
        assert r.status_code == 401
        # Even with a (would-be) bearer, no configured secret = no admin access.
        r2 = await client.get(_WHOAMI, headers={"Authorization": "Bearer anything"})
        assert r2.status_code == 401
        assert "principal" not in r2.text


@pytest.mark.asyncio
async def test_correct_token_authorizes_without_tenant_headers(monkeypatch):
    """Happy path: correct admin token + NO tenant headers -> 200.

    Proves AuthMiddleware + TenantContextMiddleware skip /admin (otherwise the
    missing tenant headers would 400 and the missing virtual key would 401).
    """
    app = _build_app(monkeypatch, admin_token=_ADMIN_TOKEN)
    async with _client(app) as client:
        r = await client.get(_WHOAMI, headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"})
        assert r.status_code == 200
        assert r.json() == {"principal": ADMIN_PRINCIPAL}


@pytest.mark.asyncio
async def test_tenant_principal_cannot_reach_admin_endpoints(monkeypatch):
    """Vector 1: a tenant Bearer key (with tenant headers) is rejected on /admin."""
    app = _build_app(monkeypatch, admin_token=_ADMIN_TOKEN)
    async with _client(app) as client:
        # Tenant-style key + full tenant headers — must NOT elevate to admin.
        r = await client.get(
            _WHOAMI,
            headers={"Authorization": f"Bearer {_TENANT_KEY}", **_tenant_headers()},
        )
        assert r.status_code == 401
        assert "principal" not in r.text
        # Tenant key with no headers — still rejected.
        r2 = await client.get(_WHOAMI, headers={"Authorization": f"Bearer {_TENANT_KEY}"})
        assert r2.status_code == 401


@pytest.mark.asyncio
async def test_admin_cannot_be_forged_from_tenant_creds(monkeypatch):
    """Vector 2: no header/token manipulation elevates a non-admin caller."""
    app = _build_app(monkeypatch, admin_token=_ADMIN_TOKEN)
    async with _client(app) as client:
        forgeries = [
            {},  # no Authorization
            {"Authorization": "Bearer "},  # empty token
            {"Authorization": _ADMIN_TOKEN},  # missing "Bearer " scheme
            {"Authorization": f"Bearer {_ADMIN_TOKEN}x"},  # superset of token
            {"Authorization": f"Bearer {_ADMIN_TOKEN[:-1]}"},  # prefix of token
            {"Authorization": f"Basic {_ADMIN_TOKEN}"},  # wrong scheme
            {"X-Admin-Token": _ADMIN_TOKEN},  # token in a non-standard header
        ]
        for headers in forgeries:
            r = await client.get(_WHOAMI, headers=headers)
            assert r.status_code == 401, f"forgery accepted: {headers}"
            assert "principal" not in r.text
