"""X-005 revenue ingest on a REAL Postgres + the REAL app + signed requests.

Nothing on the path under test is stubbed: a signed request goes through the real
``POST /v1/ingest/revenue`` -> HMAC verify (revenue secret) -> validate -> ``post_revenue``
(real ``get_tenant_session``) -> the real ledger. Assertions read the committed ledger back
through a delta_app (RLS) session, so tenant isolation, idempotency, the exact posting model
(DEBIT receivable ASSET / CREDIT revenue REVENUE), and integer-cents are observed at the
database, not asserted from the HTTP response alone.

Skipped as a module when the Delta DB env is absent so the pure-unit modules still run.
Requires DATABASE_URL + APP_DATABASE_URL (+ DELTA_PROVISION_APP_ROLE on an ephemeral DB).
"""

from __future__ import annotations

import json
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.skipif(
    not os.environ.get("APP_DATABASE_URL"),
    reason="Delta DB (APP_DATABASE_URL / DATABASE_URL) not configured",
)


def _asyncpg(url: str) -> str:
    import re

    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _body(event: dict) -> bytes:
    """Serialize the event ONCE; the same bytes are signed and transmitted."""
    return json.dumps(event).encode("utf-8")


async def _post(client, sign_revenue, event: dict, *, secret: bytes | None = None):
    body = _body(event)
    headers = sign_revenue(body) if secret is None else sign_revenue(body, secret=secret)
    return await client.post("/v1/ingest/revenue", content=body, headers=headers)


async def _revenue_entries(tenant_id: str) -> list[dict]:
    """Every ledger entry for ``tenant_id`` joined to its account type (delta_app / RLS)."""
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            rows = (
                (
                    await conn.execute(
                        text(
                            "SELECT le.direction, le.amount_minor_units, a.type AS account_type "
                            "FROM delta.ledger_entries le "
                            "JOIN delta.accounts a ON a.account_id = le.account_id "
                            "ORDER BY le.direction"
                        )
                    )
                )
                .mappings()
                .all()
            )
            return [dict(r) for r in rows]
    finally:
        await engine.dispose()


async def _txn_count(tenant_id: str) -> int:
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            return int(
                (await conn.execute(text("SELECT count(*) FROM delta.transactions"))).scalar_one()
            )
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- auth (vector 6)
async def test_unsigned_revenue_post_is_401_and_writes_nothing(client, revenue_event, tenant_id):
    body = _body(revenue_event(tenant_id))
    resp = await client.post(
        "/v1/ingest/revenue", content=body, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 401
    assert resp.json() == {"status": "unauthorized"}
    assert await _revenue_entries(tenant_id) == []


async def test_usage_secret_does_not_authenticate_revenue(
    client, sign_revenue, hmac_secret, revenue_event, tenant_id
):
    # Signing the revenue request with the USAGE secret must be rejected — the seams are
    # keyed by DISTINCT secrets, so holding the usage key is not being Rendly.
    resp = await _post(client, sign_revenue, revenue_event(tenant_id), secret=hmac_secret)
    assert resp.status_code == 401
    assert await _revenue_entries(tenant_id) == []


# --------------------------------------------------------------------------- happy path
async def test_subscription_granted_posts_debit_asset_credit_revenue(
    client, sign_revenue, revenue_event, tenant_id
):
    resp = await _post(client, sign_revenue, revenue_event(tenant_id, amount=1999))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["applied"] is True
    assert data["idempotent_replay"] is False
    assert isinstance(data["txn_id"], str)

    entries = await _revenue_entries(tenant_id)
    assert len(entries) == 2
    by_dir = {e["direction"]: e for e in entries}
    # EXACTLY: DEBIT the receivable ASSET, CREDIT the revenue REVENUE account.
    assert by_dir["debit"]["account_type"] == "asset"
    assert by_dir["credit"]["account_type"] == "revenue"
    # Integer cents, equal, no float leak.
    assert by_dir["debit"]["amount_minor_units"] == 1999
    assert by_dir["credit"]["amount_minor_units"] == 1999
    assert type(by_dir["debit"]["amount_minor_units"]) is int  # noqa: E721
    assert await _txn_count(tenant_id) == 1


# --------------------------------------------------------------------------- idempotency
async def test_replayed_grant_applies_once(client, sign_revenue, revenue_event, tenant_id):
    event = revenue_event(tenant_id, amount=4242, idem="rev-replay-key")
    first = await _post(client, sign_revenue, event)
    assert first.status_code == 200 and first.json()["applied"] is True

    second = await _post(client, sign_revenue, event)  # SAME idempotency_key
    assert second.status_code == 200
    body = second.json()
    assert body["applied"] is False
    assert body["idempotent_replay"] is True

    assert await _txn_count(tenant_id) == 1  # still exactly one transaction
    assert len(await _revenue_entries(tenant_id)) == 2  # one debit, one credit


# --------------------------------------------------------------------------- revoke (v1 no-op)
async def test_subscription_revoked_accepts_but_posts_nothing(
    client, sign_revenue, revenue_event, tenant_id
):
    resp = await _post(
        client, sign_revenue, revenue_event(tenant_id, event_type="subscription_revoked")
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data == {
        "status": "accepted",
        "applied": False,
        "idempotent_replay": False,
        "txn_id": None,
    }
    # v1 revoke is a durable-accept no-op: NO ledger entries, NO transaction.
    assert await _revenue_entries(tenant_id) == []
    assert await _txn_count(tenant_id) == 0


# --------------------------------------------------------------------------- isolation
async def test_revenue_tenant_isolation(
    client, sign_revenue, revenue_event, tenant_id, other_tenant_id
):
    a = await _post(client, sign_revenue, revenue_event(tenant_id, amount=1000))
    assert a.status_code == 200
    # Tenant B sees NONE of tenant A's revenue entries under RLS.
    assert await _revenue_entries(other_tenant_id) == []
    assert await _txn_count(other_tenant_id) == 0
