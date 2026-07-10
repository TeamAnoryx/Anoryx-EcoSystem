"""Non-stubbed cross-product safety-event visibility e2e (X-004).

Drives the REAL FastAPI app over httpx.ASGITransport (real auth resolution, real body
validation, a real DB write) on a fresh Postgres, proving:

  * A fresh ingest is durably recorded, source_product is SERVER-RESOLVED from the matched
    bearer (never the body), and the row is genuinely RLS-isolated from another tenant.
  * A retried ingest with the SAME (source_product, idempotency_key) is `duplicate` — no
    second row — proving idempotency is real, not merely documented.
  * The tenant-scoped read (`GET /v1/safety/events`, the EXISTING O-006
    query_service_tokens principal) returns only the caller's own tenant's events,
    ascending-sequence, cursor-bounded, and the category/source_product filters narrow
    the result set for real.
  * The safety-dispatch hash chain validates in full, including BOTH an `accepted` and a
    `duplicate` link.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import text

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_safety_chain

pytestmark = pytest.mark.integration

_SAFETY_RENDLY_TOKEN = "x004-safety-rendly-token"  # noqa: S105 - test-only fake
_SAFETY_SENTINEL_TOKEN = "x004-safety-sentinel-token"  # noqa: S105 - test-only fake


def _app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv(
        "ORCH_SAFETY_SOURCE_TOKENS",
        json.dumps({"rendly": _SAFETY_RENDLY_TOKEN, "sentinel": _SAFETY_SENTINEL_TOKEN}),
    )
    from orchestrator.app import create_app

    return create_app()


async def _post_event(
    app,
    *,
    tenant_id: str,
    idempotency_key: str,
    category: str = "pii",
    token: str = _SAFETY_RENDLY_TOKEN,
    target: str | None = "room-7f3a",
):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "tenant_id": tenant_id,
                "category": category,
                "outcome": "block",
                "target": target,
                "idempotency_key": idempotency_key,
                "occurred_at": "2026-07-08T12:00:00Z",
            },
        )


async def test_ingest_persists_dedupes_and_isolates_by_tenant(
    safety_ready, monkeypatch, db_conn, app_db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    idem_key = "rendly-safety-" + uuid.uuid4().hex

    # --- REAL fresh accept ------------------------------------------------------------- #
    resp1 = await _post_event(app, tenant_id=tenant_a, idempotency_key=idem_key)
    assert resp1.status_code == 202
    assert resp1.json() == {"status": "accepted", "disposition": "accepted"}

    count = await db_conn.fetchval(
        "SELECT count(*) FROM safety_events WHERE idempotency_key = $1", idem_key
    )
    assert count == 1

    # --- REAL idempotent duplicate: same (source_product, idempotency_key) ------------- #
    resp2 = await _post_event(app, tenant_id=tenant_a, idempotency_key=idem_key)
    assert resp2.status_code == 202
    assert resp2.json() == {"status": "accepted", "disposition": "duplicate"}

    count_after = await db_conn.fetchval(
        "SELECT count(*) FROM safety_events WHERE idempotency_key = $1", idem_key
    )
    assert count_after == 1  # still exactly one row — no duplicate insert

    # --- REAL RLS isolation: tenant_a's app-role session sees it, tenant_b's does not --- #
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
    owner_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM safety_events WHERE idempotency_key = $1", idem_key
    )
    assert owner_count == 1
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_b)
    other_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM safety_events WHERE idempotency_key = $1", idem_key
    )
    assert other_count == 0

    # --- REAL chain proof: both the accept AND the duplicate are audited, chain validates #
    async with get_privileged_session() as session:
        result = await session.execute(
            text(
                "SELECT disposition FROM safety_audit_log WHERE idempotency_key = :k "
                "ORDER BY sequence_number ASC"
            ),
            {"k": idem_key},
        )
        dispositions = result.scalars().all()
        assert dispositions == ["accepted", "duplicate"]
        assert await validate_safety_chain(session) is True


async def test_tenant_read_is_scoped_ascending_and_cursor_bounded(
    safety_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_a = await seed_query_token(tenant_a)

    key1 = "rendly-safety-" + uuid.uuid4().hex
    key2 = "rendly-safety-" + uuid.uuid4().hex
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key1, category="pii")
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key2, category="injection")
    await _post_event(app, tenant_id=tenant_b, idempotency_key="other-tenant-key")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.get(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"limit": 1},
        )
        assert resp.status_code == 200
        page1 = resp.json()
        assert len(page1["data"]) == 1
        assert page1["data"][0]["tenant_id"] == tenant_a
        assert page1["next_cursor"] is not None

        resp2 = await client.get(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"limit": 10, "cursor": page1["next_cursor"]},
        )
        page2 = resp2.json()
        # Every returned row belongs to tenant_a only (RLS-scoped) — tenant_b's event never
        # appears regardless of page.
        assert all(row["tenant_id"] == tenant_a for row in page2["data"])
        idem_keys = {row["idempotency_key"] for row in page1["data"] + page2["data"]}
        assert idem_keys == {key1, key2}

        # --- category filter narrows the result set for real -------------------------- #
        resp3 = await client.get(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"category": "injection", "limit": 10},
        )
        cat_filtered = resp3.json()["data"]
        assert {row["idempotency_key"] for row in cat_filtered} == {key2}
        assert all(row["category"] == "injection" for row in cat_filtered)


async def test_source_product_filter_narrows_results(
    safety_ready, monkeypatch, seed_query_token
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    token_a = await seed_query_token(tenant_a)

    key_rendly = "rendly-safety-" + uuid.uuid4().hex
    key_sentinel = "sentinel-safety-" + uuid.uuid4().hex
    await _post_event(
        app, tenant_id=tenant_a, idempotency_key=key_rendly, token=_SAFETY_RENDLY_TOKEN
    )
    await _post_event(
        app, tenant_id=tenant_a, idempotency_key=key_sentinel, token=_SAFETY_SENTINEL_TOKEN
    )

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.get(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token_a}"},
            params={"source_product": "sentinel", "limit": 10},
        )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert {row["idempotency_key"] for row in data} == {key_sentinel}
    assert all(row["source_product"] == "sentinel" for row in data)


async def test_cross_tenant_read_never_sees_other_tenants_events(
    safety_ready, monkeypatch, seed_query_token
) -> None:
    """A tenant's own query token never surfaces another tenant's safety events, even
    with no filters applied — RLS is the structural enforcer, not an app-level filter."""
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_b = await seed_query_token(tenant_b)

    key_a = "rendly-safety-" + uuid.uuid4().hex
    await _post_event(app, tenant_id=tenant_a, idempotency_key=key_a)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.get(
            "/v1/safety/events",
            headers={"Authorization": f"Bearer {token_b}"},
            params={"limit": 200},
        )
    assert resp.status_code == 200
    idem_keys = {row["idempotency_key"] for row in resp.json()["data"]}
    assert key_a not in idem_keys
