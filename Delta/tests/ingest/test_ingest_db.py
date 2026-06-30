"""End-to-end ingest on a REAL Postgres + the REAL app + signed requests (D-004).

Nothing on the path under test is stubbed: a signed request goes through the real
``POST /v1/ingest/usage`` -> HMAC verify -> validate -> ``post_usage`` (real
``get_tenant_session``) -> the real ledger. Assertions read the committed ledger / DLQ
back through a delta_app (RLS) session (and a privileged session for the NULL-tenant DLQ
row), so tenant isolation and idempotency are observed at the database, not asserted from
the HTTP response alone.

Skipped as a module when the Delta DB env is absent so the pure-unit modules still run.
Requires DATABASE_URL + APP_DATABASE_URL (+ DELTA_PROVISION_APP_ROLE on an ephemeral DB).
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("APP_DATABASE_URL"),
    reason="Delta DB (APP_DATABASE_URL / DATABASE_URL) not configured",
)


def _body(event: dict) -> bytes:
    """Serialize the event ONCE; the same bytes are signed and transmitted."""
    return json.dumps(event).encode("utf-8")


async def _post(client, sign, event: dict, *, secret: bytes | None = None):
    body = _body(event)
    headers = sign(body) if secret is None else sign(body, secret=secret)
    return await client.post("/v1/ingest/usage", content=body, headers=headers)


# --------------------------------------------------------------------------- vector 6 (auth)
async def test_unsigned_post_is_401_and_writes_nothing(
    client, usage_event, tenant_id, read_tenant_ledger
):
    body = _body(usage_event(tenant_id))
    resp = await client.post(
        "/v1/ingest/usage", content=body, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 401
    assert resp.json() == {"status": "unauthorized"}
    snap = await read_tenant_ledger(tenant_id)
    assert snap["txns"] == 0 and snap["entries"] == 0


async def test_wrong_secret_is_401_and_writes_nothing(
    client, sign, usage_event, tenant_id, read_tenant_ledger
):
    resp = await _post(client, sign, usage_event(tenant_id), secret=b"not-the-shared-secret")
    assert resp.status_code == 401
    assert resp.json() == {"status": "unauthorized"}
    snap = await read_tenant_ledger(tenant_id)
    assert snap["entries"] == 0


# --------------------------------------------------------------------------- happy path
async def test_valid_usage_posts_one_balanced_debit(
    client, sign, usage_event, tenant_id, read_tenant_ledger
):
    resp = await _post(client, sign, usage_event(tenant_id, cost=1234))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["applied"] is True
    assert data["idempotent_replay"] is False
    assert isinstance(data["txn_id"], str)

    snap = await read_tenant_ledger(tenant_id)
    assert snap["txns"] == 1
    assert snap["entries"] == 2
    assert snap["debit"] == 1234
    assert snap["credit"] == 1234
    assert snap["balanced"] is True


# --------------------------------------------------------------------------- vector 2 (idempotency)
async def test_replayed_event_applies_once(
    client, sign, usage_event, tenant_id, read_tenant_ledger
):
    event = usage_event(tenant_id, cost=4242)
    first = await _post(client, sign, event)
    assert first.status_code == 200
    assert first.json()["applied"] is True

    second = await _post(client, sign, event)  # SAME event_id -> idempotent replay
    assert second.status_code == 200
    body = second.json()
    assert body["applied"] is False
    assert body["idempotent_replay"] is True

    snap = await read_tenant_ledger(tenant_id)
    assert snap["txns"] == 1  # still exactly one transaction
    assert snap["entries"] == 2  # one debit, one credit
    assert snap["debit"] == 4242


# --------------------------------------------------------------------------- vector 1 (isolation)
async def test_tenant_isolation(
    client, sign, usage_event, tenant_id, other_tenant_id, read_tenant_ledger
):
    a_resp = await _post(client, sign, usage_event(tenant_id, cost=1000))
    assert a_resp.status_code == 200

    # Tenant B sees ZERO of tenant A's rows (A's debit is invisible to B under RLS).
    b_view = await read_tenant_ledger(other_tenant_id)
    assert b_view["txns"] == 0 and b_view["entries"] == 0

    # A second event for tenant B posts into B; A still sees only its own.
    b_resp = await _post(client, sign, usage_event(other_tenant_id, cost=2000))
    assert b_resp.status_code == 200

    a_view = await read_tenant_ledger(tenant_id)
    assert a_view["txns"] == 1 and a_view["debit"] == 1000
    b_view2 = await read_tenant_ledger(other_tenant_id)
    assert b_view2["txns"] == 1 and b_view2["debit"] == 2000


# --------------------------------------------------------------------------- vector 5 (cost)
async def test_negative_cost_dead_letters_invalid_cost(
    client, sign, usage_event, tenant_id, read_tenant_ledger
):
    resp = await _post(client, sign, usage_event(tenant_id, cost=-5))
    assert resp.status_code == 422
    assert resp.json() == {"status": "dead_lettered", "reason": "invalid_cost"}
    snap = await read_tenant_ledger(tenant_id)
    assert snap["entries"] == 0  # nothing posted on a permanent failure


async def test_float_cost_quantizes_half_even_and_posts_integer(
    client, sign, usage_event, tenant_id, read_tenant_ledger
):
    # 12.5 quantizes half-even to 12 (banker's rounding to even), an exact BIGINT cents.
    resp = await _post(client, sign, usage_event(tenant_id, cost=12.5))
    assert resp.status_code == 200, resp.text
    snap = await read_tenant_ledger(tenant_id)
    assert snap["txns"] == 1
    assert snap["debit"] == 12
    assert snap["credit"] == 12
    assert type(snap["debit"]) is int  # noqa: E721 - integer cents, no float anywhere


# --------------------------------------------------------------------------- vectors 4 + 8 (DLQ)
async def test_non_usage_event_dead_letters_tenant_visible_and_dedupes(
    client, sign, usage_event, tenant_id, read_dlq_tenant
):
    event_id = str(uuid.uuid4())
    poison = usage_event(tenant_id, event_id=event_id, event_type="audit")

    resp = await _post(client, sign, poison)
    assert resp.status_code == 422
    assert resp.json() == {"status": "dead_lettered", "reason": "malformed_payload"}

    rows = await read_dlq_tenant(tenant_id, source_event_id=event_id)
    assert len(rows) == 1
    assert rows[0]["reason"] == "malformed_payload"
    assert rows[0]["tenant_id"] == tenant_id

    # Re-POST the SAME poison event -> still exactly ONE DLQ row (dedup, vector 8).
    resp2 = await _post(client, sign, poison)
    assert resp2.status_code == 422
    rows2 = await read_dlq_tenant(tenant_id, source_event_id=event_id)
    assert len(rows2) == 1


async def test_missing_tenant_dead_letters_null_tenant_row(
    client, sign, usage_event, tenant_id, read_dlq_privileged, read_dlq_tenant
):
    event_id = str(uuid.uuid4())
    poison = usage_event(tenant_id, event_id=event_id)
    poison.pop("tenant_id")  # unknown tenant -> tenant-NULL DLQ row

    resp = await _post(client, sign, poison)
    assert resp.status_code == 422
    assert resp.json() == {"status": "dead_lettered", "reason": "unknown_tenant"}

    # Written tenant-NULL via the privileged session (RLS-invisible to any delta_app tenant).
    priv = await read_dlq_privileged(source_event_id=event_id)
    assert len(priv) == 1
    assert priv[0]["tenant_id"] is None
    assert priv[0]["reason"] == "unknown_tenant"

    # A tenant session cannot see the NULL-tenant row.
    assert await read_dlq_tenant(tenant_id, source_event_id=event_id) == []
