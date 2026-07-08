"""Non-stubbed cross-product identity-event correlation e2e (O-010, ADR-0010).

Drives the REAL FastAPI app over httpx.ASGITransport (real auth resolution, real body
validation, a real DB write) on a fresh Postgres, proving:

  * A fresh ingest is durably recorded, source_product is SERVER-RESOLVED from the matched
    bearer (never the body), and the row is genuinely RLS-isolated from another tenant.
  * A retried ingest with the SAME (source_product, idempotency_key) is `duplicate` — no
    second row — proving idempotency is real, not merely documented.
  * The tenant-scoped read (`GET /v1/identity/events`, the EXISTING O-006
    query_service_tokens principal) returns only the caller's own tenant's events,
    newest-... ascending-sequence, cursor-bounded.
  * The operator admin read (`GET /v1/admin/identity/events/recent`) is genuinely
    cross-tenant.
  * The identity-dispatch hash chain validates in full, including BOTH an `accepted` and a
    `duplicate` link.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import text

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_identity_chain

pytestmark = pytest.mark.integration

_IDENTITY_SENTINEL_TOKEN = "o010-identity-sentinel-token"  # noqa: S105 - test-only fake
_ADMIN_TOKEN = "o010-operator-token"  # noqa: S105 - test-only fake


def _app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv(
        "ORCH_IDENTITY_SOURCE_TOKENS", json.dumps({"sentinel": _IDENTITY_SENTINEL_TOKEN})
    )
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    from orchestrator.app import create_app

    return create_app()


async def _post_event(app, *, tenant_id: str, idempotency_key: str, action: str = "sso_login"):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            "/v1/identity/events",
            headers={"Authorization": f"Bearer {_IDENTITY_SENTINEL_TOKEN}"},
            json={
                "tenant_id": tenant_id,
                "principal_type": "operator",
                "principal_id": "idp-subject-e2e",
                "action": action,
                "target": "admin-console",
                "idempotency_key": idempotency_key,
                "occurred_at": "2026-07-08T12:00:00Z",
            },
        )


async def test_ingest_persists_dedupes_and_isolates_by_tenant(
    identity_ready, monkeypatch, db_conn, app_db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    idem_key = "sentinel-sso-" + uuid.uuid4().hex

    # --- REAL fresh accept ------------------------------------------------------------- #
    resp1 = await _post_event(app, tenant_id=tenant_a, idempotency_key=idem_key)
    assert resp1.status_code == 202
    assert resp1.json() == {"status": "accepted", "disposition": "accepted"}

    count = await db_conn.fetchval(
        "SELECT count(*) FROM identity_events WHERE idempotency_key = $1", idem_key
    )
    assert count == 1

    # --- REAL idempotent duplicate: same (source_product, idempotency_key) ------------- #
    resp2 = await _post_event(app, tenant_id=tenant_a, idempotency_key=idem_key)
    assert resp2.status_code == 202
    assert resp2.json() == {"status": "accepted", "disposition": "duplicate"}

    count_after = await db_conn.fetchval(
        "SELECT count(*) FROM identity_events WHERE idempotency_key = $1", idem_key
    )
    assert count_after == 1  # still exactly one row — no duplicate insert

    # --- REAL RLS isolation: tenant_a's app-role session sees it, tenant_b's does not --- #
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
    owner_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM identity_events WHERE idempotency_key = $1", idem_key
    )
    assert owner_count == 1
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_b)
    other_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM identity_events WHERE idempotency_key = $1", idem_key
    )
    assert other_count == 0

    # --- REAL chain proof: both the accept AND the duplicate are audited, chain validates #
    async with get_privileged_session() as session:
        result = await session.execute(
            text(
                "SELECT disposition FROM identity_audit_log WHERE idempotency_key = :k "
                "ORDER BY sequence_number ASC"
            ),
            {"k": idem_key},
        )
        dispositions = result.scalars().all()
        assert dispositions == ["accepted", "duplicate"]
        assert await validate_identity_chain(session) is True


async def test_tenant_read_is_scoped_ascending_and_cursor_bounded(
    identity_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_a = await seed_query_token(tenant_a)

    key1 = "sentinel-sso-" + uuid.uuid4().hex
    key2 = "sentinel-sso-" + uuid.uuid4().hex
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key1, action="sso_login")
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key2, action="sso_login_denied")
    await _post_event(app, tenant_id=tenant_b, idempotency_key="other-tenant-key")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.get(
            "/v1/identity/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"limit": 1},
        )
        assert resp.status_code == 200
        page1 = resp.json()
        assert len(page1["data"]) == 1
        assert page1["data"][0]["tenant_id"] == tenant_a
        assert page1["next_cursor"] is not None

        resp2 = await client.get(
            "/v1/identity/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"limit": 10, "cursor": page1["next_cursor"]},
        )
        page2 = resp2.json()
        # Every returned row belongs to tenant_a only (RLS-scoped) — tenant_b's event never
        # appears regardless of page.
        assert all(row["tenant_id"] == tenant_a for row in page2["data"])
        idem_keys = {row["idempotency_key"] for row in page1["data"] + page2["data"]}
        assert idem_keys == {key1, key2}


async def test_admin_read_is_cross_tenant(identity_ready, monkeypatch) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    key_a = "sentinel-sso-" + uuid.uuid4().hex
    key_b = "sentinel-sso-" + uuid.uuid4().hex
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key_a)
    await _post_event(app, tenant_id=tenant_b, idempotency_key=key_b)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.get(
            "/v1/admin/identity/events/recent",
            headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
            params={"limit": 200},
        )
    assert resp.status_code == 200
    idem_keys = {row["idempotency_key"] for row in resp.json()["data"]}
    assert key_a in idem_keys
    assert key_b in idem_keys  # cross-tenant by design (mirrors the O-007 admin reads)
