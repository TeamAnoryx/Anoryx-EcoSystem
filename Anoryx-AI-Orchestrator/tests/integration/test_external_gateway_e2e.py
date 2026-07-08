"""Non-stubbed third-party external-gateway e2e (O-013, ADR-0013).

Drives the REAL FastAPI app over httpx.ASGITransport (real key resolution, real DB
writes) on a fresh Postgres, proving:

  * An operator-issued key reads its own tenant's events and never another tenant's
    (genuine RLS isolation on the gated read, not merely a documented claim).
  * A revoked key is rejected (403) and the rejection itself is chain-audited.
  * A key without the required scope is rejected (403) and chain-audited.
  * A key that exceeds its configured rate limit within one window is rejected (429) and
    chain-audited.
  * `ORCH_EXTERNAL_GATEWAY_ENABLED` unset/false disables the gated read (404) even for a
    genuinely valid key, while key issuance itself is unaffected by the flag.
  * The external-gateway hash chain validates in full.
  * An unknown key never produces a chain-audit row (no tenant to attribute it to).
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_external_gateway_chain

pytestmark = pytest.mark.integration

_ADMIN_TOKEN = "o013-operator-token"  # noqa: S105 - test-only fake


def _app(monkeypatch, *, enabled: bool = True):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "e2e-ingest-secret")
    monkeypatch.setenv("ORCH_ADMIN_TOKEN", _ADMIN_TOKEN)
    monkeypatch.setenv("ORCH_EXTERNAL_GATEWAY_ENABLED", "1" if enabled else "0")

    from orchestrator.app import create_app

    return create_app()


async def _client(app) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://orch")


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


async def _seed_event(db_conn, tenant_id: str) -> str:
    """INSERT one ingest_events row for *tenant_id* on the privileged conn; return its event_id."""
    eid = str(uuid.uuid4())
    short = eid[:8]
    await db_conn.execute(
        "INSERT INTO ingest_events (envelope_id, idempotency_key, source_product, "
        "source_sequence, schema_version, occurred_at, correlation_id, event_id, event_type, "
        "event_timestamp, request_id, tenant_id, team_id, project_id, agent_id, payload, "
        "content_hash) VALUES ($1, $2, 'sentinel', 1024, 1, '2026-07-08T12:00:01Z', $3, $4, "
        "'policy_decision_deny', '2026-07-08T12:00:00Z', $5, $6, $7, $8, 'gateway-core', "
        "$9::jsonb, $10)",
        str(uuid.uuid4()),
        eid,
        "req-" + short,
        eid,
        "req-" + short,
        tenant_id,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        '{"note": "secret payload not exposed on the external gateway"}',
        "b" * 64,
    )
    return eid


async def _issue_key(app, *, tenant_id: str, scopes=("events:read",), rate_limit=None) -> dict:
    body = {"tenant_id": tenant_id, "label": "e2e-key", "scopes": list(scopes)}
    if rate_limit is not None:
        body["rate_limit_per_minute"] = rate_limit
    async with await _client(app) as client:
        resp = await client.post("/v1/admin/external-keys", headers=_admin_headers(), json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _seed_scopeless_key(db_conn, *, tenant_id: str) -> str:
    """INSERT one third_party_api_keys row with NO scopes (direct DB — unreachable via the
    admin API, since the only known scope is required non-empty at issuance)."""
    import hashlib

    plaintext = "eak_" + uuid.uuid4().hex
    key_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    await db_conn.execute(
        "INSERT INTO third_party_api_keys "
        "(key_id, tenant_id, key_hash, label, scopes, status, rate_limit_per_minute) "
        "VALUES ($1, $2, $3, 'scopeless-e2e', $4, 'active', 60)",
        "extkey-" + uuid.uuid4().hex,
        tenant_id,
        key_hash,
        [],
    )
    return plaintext


async def test_key_reads_own_tenant_events_and_not_others(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())

    issued = await _issue_key(app, tenant_id=tenant_a)
    api_key = issued["api_key"]

    event_a = await _seed_event(db_conn, tenant_a)
    event_b = await _seed_event(db_conn, tenant_b)

    async with await _client(app) as client:
        resp = await client.get(
            "/v1/external/events", headers={"X-Api-Key": api_key}, params={"limit": 200}
        )
    assert resp.status_code == 200, resp.text
    seen = {row["event_id"] for row in resp.json()["data"]}
    assert event_a in seen
    assert event_b not in seen
    assert "payload" not in resp.text
    assert "secret payload" not in resp.text


async def test_revoked_key_is_rejected_and_chain_audited(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    issued = await _issue_key(app, tenant_id=tenant)

    async with await _client(app) as client:
        revoke = await client.post(
            f"/v1/admin/external-keys/{issued['key_id']}/revoke", headers=_admin_headers()
        )
        assert revoke.status_code == 200, revoke.text
        assert revoke.json()["status"] == "revoked"

        resp = await client.get("/v1/external/events", headers={"X-Api-Key": issued["api_key"]})
    assert resp.status_code == 403, resp.text

    count = await db_conn.fetchval(
        "SELECT count(*) FROM external_gateway_audit_log WHERE key_id = $1 AND outcome = 'revoked'",
        issued["key_id"],
    )
    assert count == 1

    # Idempotent revoke: revoking again is still 200, not an error.
    async with await _client(app) as client:
        again = await client.post(
            f"/v1/admin/external-keys/{issued['key_id']}/revoke", headers=_admin_headers()
        )
    assert again.status_code == 200, again.text


async def test_scopeless_key_is_rejected_and_chain_audited(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    api_key = await _seed_scopeless_key(db_conn, tenant_id=tenant)

    async with await _client(app) as client:
        resp = await client.get("/v1/external/events", headers={"X-Api-Key": api_key})
    assert resp.status_code == 403, resp.text

    count = await db_conn.fetchval(
        "SELECT count(*) FROM external_gateway_audit_log WHERE outcome = 'scope_denied' "
        "AND tenant_id = $1",
        tenant,
    )
    assert count == 1


async def test_rate_limit_enforced_within_window(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    issued = await _issue_key(app, tenant_id=tenant, rate_limit=2)
    headers = {"X-Api-Key": issued["api_key"]}

    async with await _client(app) as client:
        r1 = await client.get("/v1/external/events", headers=headers)
        r2 = await client.get("/v1/external/events", headers=headers)
        r3 = await client.get("/v1/external/events", headers=headers)
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert r3.status_code == 429, r3.text

    count = await db_conn.fetchval(
        "SELECT count(*) FROM external_gateway_audit_log "
        "WHERE key_id = $1 AND outcome = 'rate_limited'",
        issued["key_id"],
    )
    assert count == 1


async def test_gateway_disabled_returns_404_but_issuance_still_works(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch, enabled=False)
    tenant = str(uuid.uuid4())
    issued = await _issue_key(app, tenant_id=tenant)

    async with await _client(app) as client:
        resp = await client.get("/v1/external/events", headers={"X-Api-Key": issued["api_key"]})
    assert resp.status_code == 404, resp.text


async def test_unknown_key_is_401_and_never_chain_audited(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    before = await db_conn.fetchval("SELECT count(*) FROM external_gateway_audit_log")

    async with await _client(app) as client:
        resp = await client.get("/v1/external/events", headers={"X-Api-Key": "eak_totally-unknown"})
    assert resp.status_code == 401, resp.text

    after = await db_conn.fetchval("SELECT count(*) FROM external_gateway_audit_log")
    assert after == before


async def test_external_gateway_chain_validates(
    external_gateway_ready, monkeypatch, db_conn
) -> None:
    app = _app(monkeypatch)
    tenant = str(uuid.uuid4())
    issued = await _issue_key(app, tenant_id=tenant)
    async with await _client(app) as client:
        await client.get("/v1/external/events", headers={"X-Api-Key": issued["api_key"]})

    async with get_privileged_session() as session:
        assert await validate_external_gateway_chain(session) is True
