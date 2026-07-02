"""Non-stubbed per-tenant authorization + read-seam e2e (O-006, ADR-0006) — the acceptance gate.

Proves, on a REAL Postgres with the REAL app (driven over httpx → the real RLS-scoped read
path), that a per-tenant service token cannot read another tenant's data:

  1. A-token GET /v1/policies/distributions/{A} → 200; B-token same id → 404 (O-004 LOW-1 closed).
  2. A-token GET /v1/bus/dlq → only A's rows; B-token → none of A's (O-002 DLQ prose closed).
  3. A-token GET /v1/events → A only; ?tenant_id=B → 403 (Fork C).
  4. distribution POST, A-token, body tenant_id=B → 403 (O-004 LOW-2 closed).
  5. Direct-DB RLS proof via the raw orchestrator_app (NOBYPASSRLS) conn: GUC→A sees the row,
     GUC→B sees 0 — the DB blocks a direct cross-tenant query (Windows-robust, mirrors
     test_ingest_e2e.py:208).
  6. Linux-only: the same isolation through the EXACT runtime path — get_tenant_session (autobegin,
     no session.begin()) — not just the DB-level equivalent.

Seeding is done on the privileged (BYPASSRLS owner) conn so both tenants' rows exist; the reads
are the non-stubbed thing under test.
"""

from __future__ import annotations

import sys
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def app(monkeypatch):
    """The real Orchestrator app; the query/distribution seams resolve principals from the DB."""
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "authz-e2e-secret")
    monkeypatch.delenv("ORCH_DISTRIBUTION_TARGETS", raising=False)

    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get(app, path: str, token: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=_bearer(token))


async def _post_distribution(app, body: dict, token: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post("/v1/policies/distributions", json=body, headers=_bearer(token))


def _valid_policy(tenant_id: str) -> dict:
    """A schema-valid model_denylist policy (passes the locked policy.schema.json)."""
    return {
        "policy_type": "model_denylist",
        "tenant_id": tenant_id,
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": "2026-01-01T00:00:00Z",
        "signature": "aaaaaa.bbbbbb.cccccc",
        "denied_model_ids": ["gpt-3.5-turbo"],
        "reason": "authz e2e policy",
    }


async def _seed_event(db_conn, tenant_id: str) -> str:
    """INSERT one ingest_events row for *tenant_id* on the privileged conn; return its event_id."""
    eid = str(uuid.uuid4())
    short = eid[:8]
    await db_conn.execute(
        "INSERT INTO ingest_events (envelope_id, idempotency_key, source_product, "
        "source_sequence, schema_version, occurred_at, correlation_id, event_id, event_type, "
        "event_timestamp, request_id, tenant_id, team_id, project_id, agent_id, payload, "
        "content_hash) VALUES ($1, $2, 'sentinel', 1024, 1, '2026-06-26T12:00:01Z', $3, $4, "
        "'policy_decision_deny', '2026-06-26T12:00:00Z', $5, $6, $7, $8, 'gateway-core', "
        "$9::jsonb, $10)",
        str(uuid.uuid4()),
        eid,
        "req-" + short,
        eid,
        "req-" + short,
        tenant_id,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        '{"note": "secret payload not exposed on the read seam"}',
        "a" * 64,
    )
    return eid


async def _seed_dlq(db_conn, tenant_id: str) -> str:
    """INSERT one dead_letter_queue row for *tenant_id* (privileged conn); return its dlq_id."""
    dlq_id = str(uuid.uuid4())
    await db_conn.execute(
        "INSERT INTO dead_letter_queue (dlq_id, original_envelope, reason, attempt_count, "
        "first_failed_at, event_type, source_product, source_sequence, tenant_id) VALUES ($1, "
        "$2::jsonb, 'unknown_schema_version', 1, '2026-06-26T12:00:10Z', 'policy_decision_deny', "
        "'sentinel', 1024, $3)",
        dlq_id,
        '{"envelope": "preserved body — never exposed on the read seam"}',
        tenant_id,
    )
    return dlq_id


# --------------------------------------------------------------------------- #
# 1. GET distribution-status is tenant-scoped (O-004 LOW-1 closed).
# --------------------------------------------------------------------------- #


async def test_distribution_status_is_tenant_scoped(
    authz_ready, app, db_conn, seed_query_token, seed_distribution
):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    tok_a = await seed_query_token(tenant_a)
    tok_b = await seed_query_token(tenant_b)

    distribution_id = uuid.uuid4().hex
    signed = {
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "policy_type": "model_denylist",
        "tenant_id": tenant_a,
    }
    await seed_distribution(
        distribution_id=distribution_id,
        tenant_id=tenant_a,
        signed_record=signed,
        sentinel_ids=["sentinel-a"],
    )

    ok = await _get(app, f"/v1/policies/distributions/{distribution_id}", tok_a)
    assert ok.status_code == 200, ok.text
    assert ok.json()["distribution_id"] == distribution_id

    # B may not read A's distribution — cross-tenant lookup is a 404 (no existence oracle).
    cross = await _get(app, f"/v1/policies/distributions/{distribution_id}", tok_b)
    assert cross.status_code == 404, cross.text
    assert cross.json()["error"]["code"] == "not_found"


# --------------------------------------------------------------------------- #
# 2. GET /v1/bus/dlq is tenant-scoped (O-002 DLQ-read prose deferral closed).
# --------------------------------------------------------------------------- #


async def test_dlq_read_is_tenant_scoped(authz_ready, app, db_conn, seed_query_token):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    tok_a = await seed_query_token(tenant_a)
    tok_b = await seed_query_token(tenant_b)

    a1 = await _seed_dlq(db_conn, tenant_a)
    a2 = await _seed_dlq(db_conn, tenant_a)
    b1 = await _seed_dlq(db_conn, tenant_b)

    resp_a = await _get(app, "/v1/bus/dlq?limit=200", tok_a)
    assert resp_a.status_code == 200, resp_a.text
    seen_a = {row["dlq_id"] for row in resp_a.json()["data"]}
    assert {a1, a2} <= seen_a
    assert b1 not in seen_a
    # Metadata-only: the preserved envelope is never exposed.
    assert "original_envelope" not in resp_a.text
    assert "preserved body" not in resp_a.text

    resp_b = await _get(app, "/v1/bus/dlq?limit=200", tok_b)
    seen_b = {row["dlq_id"] for row in resp_b.json()["data"]}
    assert b1 in seen_b
    assert a1 not in seen_b and a2 not in seen_b


# --------------------------------------------------------------------------- #
# 3. GET /v1/events is tenant-scoped + FilterTenantId=B → 403 (Fork C).
# --------------------------------------------------------------------------- #


async def test_events_read_is_tenant_scoped_and_filter_rejects_cross_tenant(
    authz_ready, app, db_conn, seed_query_token
):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    tok_a = await seed_query_token(tenant_a)
    tok_b = await seed_query_token(tenant_b)

    a1 = await _seed_event(db_conn, tenant_a)
    a2 = await _seed_event(db_conn, tenant_a)
    b1 = await _seed_event(db_conn, tenant_b)

    resp_a = await _get(app, "/v1/events?limit=200", tok_a)
    assert resp_a.status_code == 200, resp_a.text
    rows = resp_a.json()["data"]
    assert all(row["tenant_id"] == tenant_a for row in rows)
    seen_a = {row["event_id"] for row in rows}
    assert {a1, a2} <= seen_a
    assert b1 not in seen_a
    # Metadata-only: no payload leaks.
    assert "payload" not in resp_a.text
    assert "secret payload" not in resp_a.text

    # An A token may not even ASK for B's tenant → 403.
    forbidden = await _get(app, f"/v1/events?tenant_id={tenant_b}", tok_a)
    assert forbidden.status_code == 403, forbidden.text
    assert forbidden.json()["error"]["code"] == "forbidden"

    # B sees only its own event.
    resp_b = await _get(app, "/v1/events?limit=200", tok_b)
    seen_b = {row["event_id"] for row in resp_b.json()["data"]}
    assert b1 in seen_b
    assert a1 not in seen_b and a2 not in seen_b


# --------------------------------------------------------------------------- #
# 4. Distribution POST validates body tenant_id against the principal (O-004 LOW-2 closed).
# --------------------------------------------------------------------------- #


async def test_distribution_post_body_tenant_mismatch_is_403(
    authz_ready, app, db_conn, seed_query_token
):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    tok_a = await seed_query_token(tenant_a)

    # A-token, but the signed body claims tenant_id=B → 403 REJECTED, before any persist.
    resp = await _post_distribution(app, {"policy": _valid_policy(tenant_b)}, tok_a)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "forbidden"

    # A-token with a matching body tenant is accepted (202) — the binding is validated, not a block.
    ok = await _post_distribution(app, {"policy": _valid_policy(tenant_a)}, tok_a)
    assert ok.status_code == 202, ok.text


# --------------------------------------------------------------------------- #
# 5. Direct-DB RLS proof via the raw orchestrator_app (NOBYPASSRLS) conn (Windows-robust).
# --------------------------------------------------------------------------- #


async def test_direct_db_rls_blocks_cross_tenant(authz_ready, app_db_conn, db_conn):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    event_id = await _seed_event(db_conn, tenant_a)

    # GUC → A: the app role sees the row.
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE event_id = $1", event_id
        )
        == 1
    )

    # GUC → B: RLS hides it (NOBYPASSRLS role cannot widen past its tenant).
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_b)
    assert (
        await app_db_conn.fetchval(
            "SELECT count(*) FROM ingest_events WHERE event_id = $1", event_id
        )
        == 0
    )


# --------------------------------------------------------------------------- #
# 6. Linux/CI: the same isolation through the EXACT runtime path — get_tenant_session.
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="SQLAlchemy+asyncpg direct connect from the bare test coroutine is flaky on Windows "
    "(WinError 10054); the runtime path is exercised on Linux CI (and via httpx above). RLS is "
    "also proven Windows-robustly via the orchestrator_app raw conn in the test above.",
)
async def test_rls_isolation_via_get_tenant_session(authz_ready, db_conn):
    from sqlalchemy import text

    from orchestrator.persistence.database import get_tenant_session

    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    event_id = await _seed_event(db_conn, tenant_a)

    async with get_tenant_session(tenant_a) as session:
        seen = await session.execute(
            text("SELECT count(*) FROM ingest_events WHERE event_id = :e"), {"e": event_id}
        )
        assert seen.scalar_one() == 1
    async with get_tenant_session(tenant_b) as session:
        hidden = await session.execute(
            text("SELECT count(*) FROM ingest_events WHERE event_id = :e"), {"e": event_id}
        )
        assert hidden.scalar_one() == 0
